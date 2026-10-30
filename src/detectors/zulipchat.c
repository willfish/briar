/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zulipchat/zulipchat.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id, *domain; } zulip_patterns;
typedef enum { ZU_ABORT = -1, ZU_KEEP = 0 } zu_outcome;
typedef struct { bool failed; char *cause; } zulip_decode;

static int zu_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int zu_add(br_json *object, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value);
    if (!part || json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static void zu_keep(zulip_decode *fields, char *cause)
{
    if (!fields->failed) {
        fields->failed = true;
        fields->cause = cause;
    } else free(cause);
}

/* 0 is a completed diagnostic, even when cause is NULL. Every other code is fatal. */
__attribute__((weak)) int br_zulipchat_type_cause(br_json *value, const char *field,
                                                  const char *expected, char **cause)
{
    return br_json_type_cause(value, field, expected, cause);
}

__attribute__((weak)) int br_zulipchat_each_element(br_slice array, br_json_element_fn callback,
                                                    void *user)
{
    return br_json_each_element(array, callback, user);
}

static int zu_note(zulip_decode *fields, br_json *value, const char *field, const char *expected)
{
    char *cause = NULL;
    int typed = br_zulipchat_type_cause(value, field, expected, &cause);
    if (typed != 0) {
        free(cause);
        return typed;
    }
    zu_keep(fields, cause);
    return 0;
}

static int zu_member_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    zulip_decode *fields = user;
    if (!br_json_field_name(name, "full_name") && !br_json_field_name(name, "email")) return 0;
    /* Null into a string is ignored and does not stop later fields. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        const char *field = br_json_field_name(name, "email") ? "usersResponse.members.email"
                                                               : "usersResponse.members.full_name";
        return zu_note(fields, value, field, "string");
    }
    return 0;
}

static int zu_member(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index;
    zulip_decode *fields = user;
    /* Null into a struct value is ignored, leaving the zero member. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return zu_note(fields, value, NULL, "zulipchat.member");
    return br_json_each_member(encoded, zu_member_field, fields);
}

static int zu_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    zulip_decode *fields = user;
    if (br_json_field_name(name, "result")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string))
            return zu_note(fields, value, "usersResponse.result", "string");
    } else if (br_json_field_name(name, "members")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_array))
            return zu_note(fields, value, "usersResponse.members", "[]zulipchat.member");
        return br_zulipchat_each_element(encoded, zu_member, fields);
    }
    return 0;
}

__attribute__((weak)) int br_zulipchat_json_document(br_slice body, const char *read_error,
                                                    br_json **out, size_t *end, char **cause)
{
    return br_json_first_document(body, read_error, out, end, cause);
}

__attribute__((weak)) int br_zulipchat_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    return br_json_each_member(object, callback, user);
}

/* 0 when encoding/json would accept usersResponse. 1 is a swallowed decode error. */
static int zu_users(br_slice body, const char *read_error)
{
    if (read_error) return 1;
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int rc = br_zulipchat_json_document(body, NULL, &root, &end, &cause);
    free(cause);
    if (rc == 1) { json_object_put(root); return 1; }
    if (rc != 0) { json_object_put(root); return -1; }
    if (!root || json_object_is_type(root, json_type_null)) {
        json_object_put(root);
        return 0; /* Null into the struct is ignored. */
    }
    if (!json_object_is_type(root, json_type_object)) {
        json_object_put(root);
        return 1; /* Typed rejection stays ordinary; it is not a visitor status. */
    }
    zulip_decode fields = {0};
    rc = br_zulipchat_each_member((br_slice){body.data, end}, zu_field, &fields);
    json_object_put(root);
    if (rc != 0) { free(fields.cause); return -1; }
    if (fields.failed) { free(fields.cause); return 1; }
    return 0;
}

static char *zu_basic(const char *id, const char *key, char **error)
{
    size_t id_len = strlen(id), key_len = strlen(key);
    if (id_len > INT_MAX - 1 || key_len > INT_MAX - id_len - 1) return NULL;
    int plain_len = (int)(id_len + 1 + key_len);
    unsigned char *plain = malloc((size_t)plain_len);
    size_t encoded_len = 4 * (((size_t)plain_len + 2) / 3);
    unsigned char *encoded = malloc(encoded_len + 1);
    char *header = malloc(6 + encoded_len + 1);
    if (!plain || !encoded || !header) {
        free(plain); free(encoded); free(header);
        zu_fail(error, "cannot allocate ZulipChat basic auth");
        return NULL;
    }
    memcpy(plain, id, id_len);
    plain[id_len] = ':';
    memcpy(plain + id_len + 1, key, key_len);
    int n = EVP_EncodeBlock(encoded, plain, plain_len);
    free(plain);
    if (n < 0 || (size_t)n != encoded_len) {
        free(encoded); free(header);
        zu_fail(error, "ZulipChat Base64 encoding failed");
        return NULL;
    }
    memcpy(header, "Basic ", 6);
    memcpy(header + 6, encoded, encoded_len + 1);
    free(encoded);
    return header;
}

static zu_outcome zu_verify(const br_scan_ctx *ctx, const char *domain, const char *id,
                            const char *key, br_result *result, char **error)
{
    size_t domain_len = strlen(domain);
    size_t url_len = strlen("https://") + domain_len + strlen("/api/v1/users");
    char *url = malloc(url_len + 1);
    if (!url) return zu_fail(error, "cannot allocate ZulipChat URL"), ZU_ABORT;
    snprintf(url, url_len + 1, "https://%s/api/v1/users", domain);
    const char *cause = NULL;
    char status_error[64];
    char *send_error = NULL;
    char *authorization = NULL;
    br_http_response response = {0};
    bool sent = false;
    if (!ctx) cause = "net/http: nil Context";
    else if (!(authorization = zu_basic(id, key, error))) {
        free(url);
        return ZU_ABORT;
    } else {
        const br_header headers[] = {
            {"Accept", "application/json"},
            {"Content-Type", "application/json"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 3,
            .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000,
            .detector_type = result->detector_type,
        };
        sent = true;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            cause = send_error;
        } else if (response.status == 200) {
            int decoded = zu_users(response.body, response.body_error);
            if (decoded < 0) {
                free(url); free(authorization); free(send_error);
                br_http_release(ctx, &response);
                return zu_fail(error, "cannot decode ZulipChat users"), ZU_ABORT;
            }
            result->verified = decoded == 0;
        } else if (response.status != 401) {
            int n = snprintf(status_error, sizeof(status_error),
                             "unexpected HTTP response status %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error)) {
                free(url); free(authorization); free(send_error);
                br_http_release(ctx, &response);
                return zu_fail(error, "cannot format ZulipChat status"), ZU_ABORT;
            }
            cause = status_error;
        }
    }
    /* SetVerificationError receives no secrets, so the cause is not redacted. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    if (sent) br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    free(url);
    return rc == 0 ? ZU_KEEP : ZU_ABORT;
}

static int zu_copy_unique(const br_regex *pattern, br_slice input, char ***out, size_t *count, char **error)
{
    *out = NULL;
    *count = 0;
    br_captures found = {0};
    if (br_captures_find(pattern, input, &found, true, error) != 0) return -1;
    if (!found.len) { br_captures_clear(&found); return 0; }
    char **items = calloc(found.len, sizeof(*items));
    if (!items) { br_captures_clear(&found); return zu_fail(error, "out of memory collecting ZulipChat captures"); }
    size_t n = found.len;
    int rc = 0;
    for (size_t i = 0; i < n; ++i) {
        items[i] = strdup(found.items[i]);
        if (!items[i]) rc = zu_fail(error, "out of memory copying ZulipChat capture");
    }
    br_captures_clear(&found);
    if (rc != 0) {
        for (size_t i = 0; i < n; ++i) free(items[i]);
        free(items);
        return -1;
    }
    *out = items;
    *count = n;
    return 0;
}

static int zu_finding(br_result *result, const char *key, const char *id, const char *domain, char **error)
{
    br_slice colon = {(const unsigned char *)":", 1};
    if (br_finding_pair_bytes(result, 811,
                              (br_slice){(const unsigned char *)key, strlen(key)}, "key",
                              (br_slice){(const unsigned char *)id, strlen(id)}, "id", colon) != 0)
        return zu_fail(error, "cannot create ZulipChat result");
    size_t key_len = strlen(key), id_len = strlen(id), domain_len = strlen(domain);
    size_t n = key_len + 1 + id_len + 1 + domain_len;
    unsigned char *raw = malloc(n ? n : 1);
    result->extra_data = json_object_new_object();
    if (!raw || !result->extra_data || zu_add(result->secret_parts, "domain", domain) != 0 ||
        zu_add(result->extra_data, "Domain", domain) != 0 ||
        zu_add(result->extra_data, "Id", id) != 0) {
        free(raw);
        return zu_fail(error, "cannot create ZulipChat metadata");
    }
    memcpy(raw, key, key_len);
    raw[key_len] = ':';
    memcpy(raw + key_len + 1, id, id_len);
    raw[key_len + 1 + id_len] = ':';
    memcpy(raw + key_len + 1 + id_len + 1, domain, domain_len);
    free(result->raw_v2.data);
    result->raw_v2.data = raw;
    result->raw_v2.len = n;
    return 0;
}

static int zu_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return zu_fail(error, "invalid or uninitialized ZulipChat scan");
    const zulip_patterns *patterns = detector->state;
    size_t original_len = out->len;
    char **keys = NULL, **ids = NULL, **domains = NULL;
    size_t nkeys = 0, nids = 0, ndomains = 0;
    char *owned_error = NULL;
    int rc = zu_copy_unique(patterns->key, input, &keys, &nkeys, &owned_error);
    if (rc == 0) rc = zu_copy_unique(patterns->id, input, &ids, &nids, &owned_error);
    if (rc == 0) rc = zu_copy_unique(patterns->domain, input, &domains, &ndomains, &owned_error);
    for (size_t k = 0; rc == 0 && k < nkeys; ++k) {
        for (size_t i = 0; rc == 0 && i < nids; ++i) {
            for (size_t d = 0; rc == 0 && d < ndomains; ++d) {
                br_result result = {0};
                zu_outcome outcome = ZU_KEEP;
                if (zu_finding(&result, keys[k], ids[i], domains[d], &owned_error) != 0)
                    rc = -1;
                else if (verify)
                    outcome = zu_verify(ctx, domains[d], ids[i], keys[k], &result, &owned_error);
                if (rc == 0 && outcome == ZU_ABORT) rc = -1;
                if (rc == 0 && outcome == ZU_KEEP && br_results_push(out, &result) != 0)
                    rc = zu_fail(&owned_error, "cannot append ZulipChat result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    for (size_t i = 0; i < nkeys; ++i) free(keys[i]);
    for (size_t i = 0; i < nids; ++i) free(ids[i]);
    for (size_t i = 0; i < ndomains; ++i) free(domains[i]);
    free(keys); free(ids); free(domains);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const zu_keywords[] = {"zulip"};
static zulip_patterns zu_state;
static br_detector zu_detector = {
    .type = 811, .version = 0, .name = "ZulipChat", .custom_name = "",
    .description = "ZulipChat is a group chat application used for team communication. ZulipChat API keys can be used to access and manage various functionalities of the chat service.",
    .keywords = zu_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = zu_scan, .state = &zu_state,
};

int br_zulipchat_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return zu_fail(error, "invalid ZulipChat detector output");
    *out = NULL;
    /* None of these patterns uses PrefixRegex. zulip is only the engine keyword. */
    if (!zu_state.key && br_regex_compile("\\b([0-9a-zA-Z]{32})\\b", &zu_state.key, error) != 0)
        return -1;
    if (!zu_state.id &&
        br_regex_compile("\\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})\\b",
                         &zu_state.id, error) != 0)
        return -1;
    if (!zu_state.domain &&
        br_regex_compile("(?i)\\b([a-z0-9-]+\\.zulip(?:chat)?\\.com|chat\\.zulip\\.org)\\b",
                         &zu_state.domain, error) != 0)
        return -1;
    *out = &zu_detector;
    return 0;
}
