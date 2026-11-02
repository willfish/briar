/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shopify/shopify.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int add_part(br_result *result, const char *name, const char *text, char **error)
{
    if (!result->secret_parts && !(result->secret_parts = json_object_new_object()))
        return fail(error, "cannot create Shopify result");
    br_json *value = json_object_new_string(text);
    if (!value || json_object_object_add(result->secret_parts, name, value) != 0) {
        json_object_put(value);
        return fail(error, "cannot create Shopify result");
    }
    return 0;
}

static int make_result(br_result *result, br_slice key, br_slice domain, char **error)
{
    if (key.len > SIZE_MAX - domain.len) return fail(error, "cannot create Shopify result");
    result->detector_type = 902;
    result->raw.data = malloc(key.len + domain.len);
    result->primary_secret.data = malloc(key.len);
    result->redacted = malloc(domain.len + 1);
    if (!result->raw.data || !result->primary_secret.data || !result->redacted)
        return fail(error, "cannot create Shopify result");
    memcpy(result->raw.data, key.data, key.len);
    memcpy(result->raw.data + key.len, domain.data, domain.len);
    result->raw.len = key.len + domain.len;
    memcpy(result->primary_secret.data, key.data, key.len);
    result->primary_secret.len = key.len;
    memcpy(result->redacted, domain.data, domain.len);
    result->redacted[domain.len] = '\0';
    char *key_text = malloc(key.len + 1), *domain_text = malloc(domain.len + 1);
    if (!key_text || !domain_text) { free(key_text); free(domain_text); return fail(error, "cannot create Shopify result"); }
    memcpy(key_text, key.data, key.len); key_text[key.len] = '\0';
    memcpy(domain_text, domain.data, domain.len); domain_text[domain.len] = '\0';
    int rc = add_part(result, "key", key_text, error);
    if (!rc) rc = add_part(result, "store_url", domain_text, error);
    free(key_text); free(domain_text);
    return rc;
}

typedef struct {
    char *text;
    size_t len;
} shopify_handle;

/* Backing survives a shorter array. Empty and null replace it. ordinary is sticky. */
typedef struct {
    shopify_handle *items;
    size_t len;
    size_t cap;
    size_t seen;
    bool ordinary;
} shopify_scopes;

static void clear_scopes(shopify_scopes *scopes)
{
    for (size_t i = 0; i < scopes->cap; ++i) free(scopes->items[i].text);
    free(scopes->items);
    scopes->items = NULL;
    scopes->len = 0;
    scopes->cap = 0;
    scopes->seen = 0;
}

static int ensure_slot(shopify_scopes *scopes, size_t index)
{
    size_t need = index + 1;
    if (need <= scopes->cap) return 0;
    if (need > SIZE_MAX / sizeof(*scopes->items)) return -1;
    shopify_handle *grown = realloc(scopes->items, need * sizeof(*scopes->items));
    if (!grown) return -1;
    memset(grown + scopes->cap, 0, (need - scopes->cap) * sizeof(*grown));
    scopes->items = grown;
    scopes->cap = need;
    return 0;
}

static int set_handle(shopify_handle *slot, br_json *value)
{
    br_slice text = br_json_text(value);
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(slot->text);
    slot->text = copy;
    slot->len = text.len;
    return 0;
}

static int scope_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    shopify_scopes *scopes = user;
    if (!br_json_field_name(name, "handle")) return 0;
    /* Null leaves the string unchanged, including a reused backing element. */
    if (!value || json_object_get_type(value) == json_type_null) return 0;
    if (json_object_get_type(value) != json_type_string) {
        scopes->ordinary = true;
        return 0;
    }
    if (scopes->seen == 0) return -1;
    return set_handle(&scopes->items[scopes->seen - 1], value);
}

static int scope_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    shopify_scopes *scopes = user;
    if (ensure_slot(scopes, index) != 0) return -1;
    scopes->seen = index + 1;
    /* A fresh slot is zero. Null and a skipped type error leave backing unchanged. */
    if (!value || json_object_get_type(value) == json_type_null) return 0;
    if (json_object_get_type(value) != json_type_object) {
        scopes->ordinary = true;
        return 0;
    }
    return br_json_each_member(encoded, scope_member, scopes);
}

static int scopes_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    shopify_scopes *scopes = user;
    if (!br_json_field_name(name, "access_scopes")) return 0;
    /* null and [] replace the slice. A type error must not clear a saved error or the slice. */
    if (!value || json_object_get_type(value) == json_type_null) {
        clear_scopes(scopes);
        return 0;
    }
    if (json_object_get_type(value) != json_type_array) {
        scopes->ordinary = true;
        return 0;
    }
    scopes->seen = 0;
    int walked = br_json_each_element(encoded, scope_element, scopes);
    if (walked != 0) return walked;
    if (scopes->seen == 0) {
        clear_scopes(scopes);
        return 0;
    }
    scopes->len = scopes->seen;
    return 0;
}

static int join_scopes(const shopify_scopes *scopes, char **out, size_t *out_len)
{
    size_t total = 0;
    for (size_t i = 0; i < scopes->len; ++i) {
        if (i && total >= SIZE_MAX - 1) return -1;
        if (i) ++total;
        if (total == SIZE_MAX || scopes->items[i].len > SIZE_MAX - total - 1) return -1;
        total += scopes->items[i].len;
    }
    char *text = malloc(total + 1);
    if (!text) return -1;
    size_t at = 0;
    for (size_t i = 0; i < scopes->len; ++i) {
        if (i) text[at++] = ',';
        if (scopes->items[i].len && scopes->items[i].text)
            memcpy(text + at, scopes->items[i].text, scopes->items[i].len);
        at += scopes->items[i].len;
    }
    text[at] = '\0';
    *out = text;
    *out_len = at;
    return 0;
}

static int publish_scopes(br_result *result, const char *joined, size_t len, char **error)
{
    if (len > INT_MAX) return fail(error, "cannot create Shopify metadata");
    result->extra_data = json_object_new_object();
    br_json *text = json_object_new_string_len(joined ? joined : "", (int)len);
    if (!result->extra_data || !text ||
        json_object_object_add(result->extra_data, "access_scopes", text) != 0) {
        json_object_put(text);
        return fail(error, "cannot create Shopify metadata");
    }
    result->verified = true;
    return 0;
}

static int decode_scopes(br_slice body, const char *read_error, br_result *result, char **error)
{
    br_json *value = NULL;
    char *cause = NULL;
    size_t end = 0;
    int decoded = br_json_first_document(body, read_error, &value, &end, &cause);
    free(cause);
    if (decoded < 0 || decoded > 1) { json_object_put(value); return fail(error, "cannot decode Shopify response"); }
    if (decoded == 1) {
        json_object_put(value);
        return 0; /* Malformed JSON stays unverified and is not a scan failure. */
    }
    /* JSON null is a successful zero struct. */
    if (!value || json_object_get_type(value) == json_type_null) {
        json_object_put(value);
        return publish_scopes(result, "", 0, error);
    }
    if (json_object_get_type(value) != json_type_object) {
        json_object_put(value);
        return 0;
    }
    json_object_put(value);
    shopify_scopes scopes = {0};
    int walked = br_json_each_member((br_slice){body.data, end}, scopes_member, &scopes);
    if (walked != 0) {
        clear_scopes(&scopes);
        return fail(error, "cannot decode Shopify response");
    }
    if (scopes.ordinary) {
        clear_scopes(&scopes);
        return 0;
    }
    char *joined = NULL;
    size_t joined_len = 0;
    if (join_scopes(&scopes, &joined, &joined_len) != 0) {
        clear_scopes(&scopes);
        return fail(error, "cannot create Shopify metadata");
    }
    clear_scopes(&scopes);
    int rc = publish_scopes(result, joined, joined_len, error);
    free(joined);
    return rc;
}

static int verify_shopify(const br_scan_ctx *ctx, const char *key, const char *domain,
                          br_result *result, char **error)
{
    size_t domain_len = strlen(domain);
    static const char prefix[] = "https://", suffix[] = "/admin/oauth/access_scopes.json";
    if (domain_len > SIZE_MAX - sizeof(prefix) - sizeof(suffix))
        return fail(error, "cannot create Shopify URL");
    char *url = malloc(sizeof(prefix) - 1 + domain_len + sizeof(suffix));
    if (!url) return fail(error, "cannot create Shopify URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, domain, domain_len);
    memcpy(url + sizeof(prefix) - 1 + domain_len, suffix, sizeof(suffix));
    if (!ctx) { free(url); return 1; }
    const br_header headers[] = {{"X-Shopify-Access-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000, .detector_type = 902,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    free(url);
    int rc = 0;
    /* Non-2xx does not decode. Do errors are ignored. Close is only reached on 2xx. */
    if (sent == 0 && response.status >= 200 && response.status < 300)
        rc = decode_scopes(response.body, response.body_error, result, error);
    br_http_release(ctx, &response);
    return rc;
}

static int scan_shopify(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Shopify scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, domains = {0};
    int rc = br_captures_find(patterns[0], input, &keys, false, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &domains, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        for (size_t j = 0; rc == 0 && j < domains.len; ++j) {
            br_result result = {0};
            int drop = 0;
            if (make_result(&result, br_captures_at(&keys, i), br_captures_at(&domains, j), error) != 0)
                rc = -1;
            else if (verify) drop = verify_shopify(ctx, keys.items[i], domains.items[j], &result, error);
            if (rc == 0 && drop < 0) rc = -1;
            else if (rc == 0 && drop == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append Shopify result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    return rc == 0 ? 0 : -1;
}

static bool shopify_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector; (void)result;
    if (reason) *reason = NULL;
    return false;
}

static const char *const shopify_keywords[] = {"shppa_", "shpat_"};
static br_regex *shopify_patterns[2];
static br_detector shopify_detector = {
    .type = 902, .version = 0, .name = "Shopify", .custom_name = "",
    .description = "An ecommerce platform, API keys can be used to access customer data",
    .keywords = shopify_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = shopify_patterns, .scan = scan_shopify, .false_positive = shopify_false_positive,
};

int br_shopify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Shopify detector output");
    *out = NULL;
    if (!shopify_patterns[0] &&
        br_regex_compile("\\b((?:shppa_|shpat_)[0-9A-Fa-f]{32})\\b", &shopify_patterns[0], error) != 0)
        return -1;
    if (!shopify_patterns[1] &&
        br_regex_compile("([a-zA-Z0-9-]+\\.myshopify\\.com)", &shopify_patterns[1], error) != 0)
        return -1;
    *out = &shopify_detector;
    return 0;
}
