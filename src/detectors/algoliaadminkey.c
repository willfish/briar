/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/algoliaadminkey and pkg/cache/simple. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <math.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *id, *key; } algolia_patterns;
typedef struct invalid_host {
    char id[11];
    int64_t expires_ns;
    struct invalid_host *next;
} invalid_host;
static invalid_host *invalid_hosts;
static atomic_flag hosts_lock = ATOMIC_FLAG_INIT;
static const int64_t host_ttl_ns = 12LL * 60 * 60 * 1000000000;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int key_error(br_result *result, const char *cause)
{
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int wall_clock_ns(int64_t *out)
{
    struct timespec now;
    if (timespec_get(&now, TIME_UTC) != TIME_UTC || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (uint64_t)(INT64_MAX - host_ttl_ns) / 1000000000)
        return -1;
    *out = (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
    return 0;
}

static void lock_hosts(void)
{
    while (atomic_flag_test_and_set_explicit(&hosts_lock, memory_order_acquire)) { }
}
static void unlock_hosts(void) { atomic_flag_clear_explicit(&hosts_lock, memory_order_release); }

static int host_cached(const char *id, bool *found)
{
    int64_t now;
    *found = false;
    if (wall_clock_ns(&now) != 0) return -1;
    lock_hosts();
    invalid_host **link = &invalid_hosts;
    while (*link) {
        invalid_host *entry = *link;
        /* go-cache considers an item expired only after its expiration instant. */
        if (now > entry->expires_ns) {
            *link = entry->next;
            free(entry);
        } else {
            if (!strcmp(entry->id, id)) *found = true;
            link = &entry->next;
        }
    }
    unlock_hosts();
    return 0;
}

static int cache_host(const char *id)
{
    int64_t now;
    if (wall_clock_ns(&now) != 0) return -1;
    lock_hosts();
    for (invalid_host *entry = invalid_hosts; entry; entry = entry->next) {
        if (!strcmp(entry->id, id)) {
            entry->expires_ns = now + host_ttl_ns;
            unlock_hosts();
            return 0;
        }
    }
    invalid_host *entry = malloc(sizeof(*entry));
    if (!entry) { unlock_hosts(); return -1; }
    memcpy(entry->id, id, sizeof(entry->id));
    entry->expires_ns = now + host_ttl_ns;
    entry->next = invalid_hosts;
    invalid_hosts = entry;
    unlock_hosts();
    return 0;
}

static double entropy(const char *text)
{
    size_t counts[128] = {0}, len = strlen(text);
    for (size_t i = 0; i < len; ++i) ++counts[(unsigned char)text[i]];
    double value = 0;
    for (size_t i = 0; i < 128; ++i) {
        if (!counts[i]) continue;
        double probability = (double)counts[i] / (double)len;
        value -= probability * log2(probability);
    }
    return value;
}

/* Positive means a candidate's decode error; negative means an allocation failure. */
static int decode_error(br_result *result, const char *message)
{
    return key_error(result, message) == 0 ? 1 : -1;
}

static int type_error(br_result *result, br_json *value, const char *field, const char *type)
{
    char *cause = NULL;
    if (br_json_type_cause(value, field, type, &cause) != 0) return -1;
    int rc = decode_error(result, cause);
    free(cause);
    return rc;
}

static bool text_equals(br_slice text, const char *literal)
{
    return text.len == strlen(literal) && !memcmp(text.data, literal, text.len);
}

static int acl_order(const void *left, const void *right)
{
    br_slice a = br_json_text(*(br_json *const *)left), b = br_json_text(*(br_json *const *)right);
    size_t len = a.len < b.len ? a.len : b.len;
    int order = len ? memcmp(a.data, b.data, len) : 0;
    return order ? order : a.len < b.len ? -1 : a.len > b.len;
}

static int extra_text(br_json *object, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len((const char *)text.data, (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(object, name, value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int permissions(br_json *acl, br_json *description, br_result *result)
{
    size_t count = acl ? json_object_array_length(acl) : 0;
    bool sensitive = false;
    for (size_t i = 0; i < count; ++i) {
        br_slice text = br_json_text(json_object_array_get_idx(acl, i));
        if (!text_equals(text, "listIndexes") && !text_equals(text, "search") && !text_equals(text, "settings"))
            sensitive = true;
    }
    if (!sensitive) return 0;
    json_object_array_sort(acl, acl_order);
    size_t len = count - 1;
    for (size_t i = 0; i < count; ++i) {
        size_t n = br_json_text(json_object_array_get_idx(acl, i)).len;
        if (n > SIZE_MAX - len) return -1;
        len += n;
    }
    if (len > INT_MAX) return -1;
    unsigned char *joined = malloc(len + 1);
    if (!joined) return -1;
    size_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        br_slice text = br_json_text(json_object_array_get_idx(acl, i));
        if (i) joined[at++] = ',';
        if (text.len) memcpy(joined + at, text.data, text.len);
        at += text.len;
    }
    joined[at] = '\0';
    result->extra_data = json_object_new_object();
    int rc = result->extra_data ? extra_text(result->extra_data, "acl", (br_slice){joined, len}) : -1;
    free(joined);
    br_slice text = br_json_text(description);
    if (!rc && text.len && !text_equals(text, "<redacted>"))
        rc = extra_text(result->extra_data, "description", text);
    if (!rc) result->verified = true;
    return rc;
}

typedef struct {
    br_result *result;
    br_json *acl, *description;
    size_t acl_len;
} response_fields;

static int read_field(void *user, br_slice name, br_json *value, br_slice encoded_value)
{
    (void)encoded_value;
    response_fields *fields = user;
    int rc = 0;
    if (br_json_field_name(name, "acl")) {
        if (value && !json_object_is_type(value, json_type_array))
            return type_error(fields->result, value, "keyResponse.acl", "[]string");
        size_t count = value ? json_object_array_length(value) : 0;
        for (size_t i = 0; i < count; ++i) {
            br_json *item = json_object_array_get_idx(value, i);
            if (item && !json_object_is_type(item, json_type_string))
                return type_error(fields->result, item, "keyResponse.acl", "string");
        }
        if (!count) {
            json_object_put(fields->acl);
            fields->acl = json_object_get(value);
            fields->acl_len = 0;
            return 0;
        }
        if (!fields->acl) fields->acl = json_object_new_array_ext((int)count);
        if (!fields->acl) return -1;
        /* Repeated ACL arrays reuse string slots. JSON null leaves an existing
         * string unchanged, even after a preceding array shrinks. */
        for (size_t i = 0; !rc && i < count; ++i) {
            br_json *item = json_object_array_get_idx(value, i);
            if (item || i >= json_object_array_length(fields->acl)) {
                br_json *owned = json_object_get(item);
                if (json_object_array_put_idx(fields->acl, i, owned) != 0) {
                    json_object_put(owned);
                    rc = -1;
                }
            }
        }
        fields->acl_len = count;
    } else if (br_json_field_name(name, "description") && value) {
        if (!json_object_is_type(value, json_type_string))
            return type_error(fields->result, value, "keyResponse.description", "string");
        json_object_put(fields->description);
        fields->description = json_object_get(value);
    }
    return rc;
}

static int decode_response(br_slice body, const char *body_error, br_result *result)
{
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int rc = br_json_first_document(body, body_error, &root, &end, &cause);
    if (rc > 0) {
        rc = decode_error(result, cause);
        free(cause);
        return rc < 0 ? rc : 0;
    }
    if (rc < 0 || !root) return rc; /* JSON null decodes to the zero struct. */
    if (!json_object_is_type(root, json_type_object)) {
        rc = type_error(result, root, NULL, "algoliaadminkey.keyResponse");
        json_object_put(root);
        return rc < 0 ? rc : 0;
    }
    response_fields fields = {.result = result};
    rc = br_json_each_member((br_slice){body.data, end}, read_field, &fields);
    json_object_put(root);
    if (!rc && fields.acl && fields.acl_len < json_object_array_length(fields.acl))
        rc = json_object_array_del_idx(fields.acl, fields.acl_len,
                                       json_object_array_length(fields.acl) - fields.acl_len);
    if (!rc) rc = permissions(fields.acl, fields.description, result);
    json_object_put(fields.acl);
    json_object_put(fields.description);
    return rc < 0 ? rc : 0;
}

static int verify_algolia(const br_scan_ctx *ctx, const char *key, const char *id,
                           br_result *result, bool *no_host)
{
    char url[128];
    snprintf(url, sizeof(url), "https://%s.algolia.net/1/keys/%s", id, key);
    const br_header headers[] = {{"X-Algolia-Application-Id", id}, {"X-Algolia-API-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 170,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        if (error && strstr(error, "no such host")) *no_host = true;
        else rc = key_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200: rc = decode_response(response.body, response.body_error, result); break;
        case 401:
        case 403: break;
        default: {
            char message[80];
            snprintf(message, sizeof(message), "unexpected HTTP response status %d", response.status);
            rc = key_error(result, message);
            break;
        }
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int make_result(const br_detector *detector, const char *key, const char *id, br_result *result)
{
    if (br_finding_pair(result, detector->type, key, "key", id, "id") != 0) return -1;
    /* This provider's RawV2 is id:key, unlike the shared key+id convention. */
    unsigned char *raw_v2 = realloc(result->raw_v2.data, 43);
    if (!raw_v2) return -1;
    result->raw_v2 = (br_bytes){raw_v2, 43};
    memcpy(raw_v2, id, 10);
    raw_v2[10] = ':';
    memcpy(raw_v2 + 11, key, 32);
    return 0;
}

static int scan_algolia(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AlgoliaAdminKey scan arguments");
    const algolia_patterns *compiled = detector->state;
    if (!compiled->id || !compiled->key) return fail(error, "uninitialized AlgoliaAdminKey patterns");
    br_captures ids = {0}, keys = {0};
    int rc = br_captures_find(compiled->id, input, &ids, true, error);
    if (!rc) rc = br_captures_find(compiled->key, input, &keys, true, error);
    bool *removed = !rc && keys.len && ids.len ? calloc(ids.len, sizeof(*removed)) : NULL;
    if (!rc && keys.len && ids.len && !removed) rc = fail(error, "out of memory tracking Algolia IDs");
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        if (entropy(keys.items[k]) <= 3) continue;
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            if (removed[i] || entropy(ids.items[i]) <= 2) continue;
            bool cached = false;
            if (host_cached(ids.items[i], &cached) != 0) { rc = fail(error, "wall clock unavailable"); break; }
            if (cached) { removed[i] = true; continue; } /* Source deletes this ID from its local map. */
            br_result result = {0};
            bool no_host = false;
            if (make_result(detector, keys.items[k], ids.items[i], &result) != 0 ||
                (verify && verify_algolia(ctx, keys.items[k], ids.items[i], &result, &no_host) != 0)) {
                br_result_clear(&result);
                rc = fail(error, "out of memory creating AlgoliaAdminKey result");
                break;
            }
            if (no_host) {
                br_result_clear(&result);
                if (cache_host(ids.items[i]) != 0) rc = fail(error, "cannot store invalid Algolia host");
                continue;
            }
            bool verified = result.verified;
            if (br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory appending AlgoliaAdminKey result");
            }
            if (verified) break;
        }
    }
    free(removed);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    return rc;
}

static algolia_patterns patterns;
static const char *const keywords[] = {"algolia", "docsearch"};
static const char *const id_prefixes[] = {"algolia", "docsearch", "appId"};
static const char *const key_prefixes[] = {"algolia", "docsearch", "apiKey"};
static const br_detector algolia = {
    .type = 170, .version = 0, .name = "AlgoliaAdminKey", .custom_name = "",
    .description = "Algolia is a search-as-a-service platform. Algolia Admin Keys can be used to manage indices "
                   "and API keys, and perform administrative tasks.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_algolia,
};

int br_algoliaadminkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AlgoliaAdminKey detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile_prefixed(id_prefixes, 3, "\\b([A-Z0-9]{10})\\b", &patterns.id, error) != 0)
        return -1;
    if (!patterns.key && br_regex_compile_prefixed(key_prefixes, 3, "\\b([a-zA-Z0-9]{32})\\b", &patterns.key, error) != 0)
        return -1;
    *out = &algolia;
    return 0;
}
