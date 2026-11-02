/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/openrouter/openrouter.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

typedef struct {
    char *label;
    size_t label_len;
    char limit[128], usage[128], free[8], remaining[128];
    char *cause;
    bool ordinary, fatal;
} or_key;

static int or_type(or_key *key, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) { free(next); return rc; }
    if (!key->ordinary) {
        key->ordinary = true;
        key->cause = next;
    } else free(next);
    return 0;
}

/* Exact helper +1 is ordinary. Any other nonzero, including +2, is fatal. */
static int or_number(or_key *key, br_slice encoded, const char *field)
{
    char *raw = NULL;
    int checked = br_json_check_float64_numbers(encoded, &raw);
    if (checked < 0) { free(raw); return checked; }
    if (checked == 0) { free(raw); return 0; }
    if (checked != 1) { free(raw); return checked; }
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go value of type float64";
    size_t raw_len = raw ? strlen(raw) : 0;
    size_t prefix_len = sizeof(prefix) - 1, suffix_len = sizeof(suffix) - 1;
    if (!raw || raw_len < prefix_len + suffix_len || memcmp(raw, prefix, prefix_len) != 0 ||
        memcmp(raw + raw_len - suffix_len, suffix, suffix_len) != 0) {
        if (key->ordinary) { free(raw); return 1; }
        key->ordinary = true;
        key->cause = raw;
        return 1;
    }
    size_t token_len = raw_len - prefix_len - suffix_len;
    static const char mid[] = " into Go struct field ";
    static const char tail[] = " of type float64";
    size_t field_len = strlen(field), fixed = prefix_len + sizeof(mid) + sizeof(tail) - 1;
    if (token_len > SIZE_MAX - fixed || field_len > SIZE_MAX - fixed - token_len) { free(raw); return -1; }
    size_t n = fixed - 1 + token_len + field_len;
    char *message = malloc(n + 1);
    if (!message) { free(raw); return -1; }
    char *at = message;
    memcpy(at, prefix, prefix_len); at += prefix_len;
    memcpy(at, raw + prefix_len, token_len); at += token_len;
    memcpy(at, mid, sizeof(mid) - 1); at += sizeof(mid) - 1;
    memcpy(at, field, strlen(field)); at += strlen(field);
    memcpy(at, tail, sizeof(tail));
    free(raw);
    if (key->ordinary) { free(message); return 1; }
    key->ordinary = true;
    key->cause = message;
    return 1;
}

static int format_go_f(double value, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%.6f", value);
    return n < 0 || (size_t)n >= cap ? -1 : 0;
}

static int or_float(or_key *key, br_json *value, char *out, bool pointer, const char *field,
                    br_slice encoded)
{
    if (!value || json_object_is_type(value, json_type_null)) {
        if (pointer) snprintf(out, 128, "<nil>");
        return 0;
    }
    if (!json_object_is_type(value, json_type_double) && !json_object_is_type(value, json_type_int))
        return or_type(key, value, field, "float64");
    int checked = or_number(key, encoded, field);
    if (checked == 1) return 0;
    if (checked != 0) return checked;
    return format_go_f(json_object_get_double(value), out, 128);
}

static int or_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    or_key *key = user;
    if (br_json_field_name(name, "label")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string)) return or_type(key, value, "key.data.label", "string");
        br_slice text = br_json_text(value);
        if (text.len == SIZE_MAX) return -1;
        char *copy = malloc(text.len + 1);
        if (!copy) return -1;
        if (text.len) memcpy(copy, text.data, text.len);
        copy[text.len] = '\0';
        free(key->label);
        key->label = copy;
        key->label_len = text.len;
        return 0;
    }
    if (br_json_field_name(name, "limit"))
        return or_float(key, value, key->limit, true, "key.data.limit", encoded);
    if (br_json_field_name(name, "limit_remaining"))
        return or_float(key, value, key->remaining, true, "key.data.limit_remaining", encoded);
    if (br_json_field_name(name, "usage"))
        return or_float(key, value, key->usage, false, "key.data.usage", encoded);
    if (br_json_field_name(name, "is_free_tier")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_boolean))
            return or_type(key, value, "key.data.is_free_tier", "bool");
        snprintf(key->free, sizeof(key->free), "%s", json_object_get_boolean(value) ? "true" : "false");
        return 0;
    }
    return 0;
}

static int or_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    or_key *key = user;
    if (!br_json_field_name(name, "data")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return or_type(key, value, "keyResponse.data", "openrouter.key");
    return br_json_each_member(encoded, or_field, key);
}

static int or_decode(br_slice body, const char *read_error, or_key *key, char **error)
{
    *key = (or_key){0};
    snprintf(key->limit, sizeof(key->limit), "<nil>");
    snprintf(key->remaining, sizeof(key->remaining), "<nil>");
    snprintf(key->usage, sizeof(key->usage), "0.000000");
    snprintf(key->free, sizeof(key->free), "false");
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &key->cause);
    if (rc < 0 || rc > 1) { json_object_put(root); return fail(error, "cannot decode OpenRouter response"); }
    if (rc == 1) { json_object_put(root); return 1; }
    br_slice document = {body.data, end};
    if (!br_utf8_valid(document)) {
        json_object_put(root);
        return fail(error, "unsupported: OpenRouter invalid UTF-8 in consumed JSON document");
    }
    if (root && !json_object_is_type(root, json_type_null) && !json_object_is_type(root, json_type_object)) {
        rc = or_type(key, root, NULL, "openrouter.keyResponse");
    } else if (root && json_object_is_type(root, json_type_object)) {
        rc = br_json_each_member(document, or_member, key);
    }
    json_object_put(root);
    if (rc != 0 || key->fatal) return fail(error, "cannot project OpenRouter response");
    return key->ordinary ? 1 : 0;
}

static int add_extra_len(br_json *extra, const char *name, const char *value, size_t len)
{
    if (len > INT_MAX) return -1;
    br_json *owned = json_object_new_string_len(value ? value : "", (int)len);
    if (!owned || json_object_object_add(extra, name, owned) != 0) {
        json_object_put(owned);
        return -1;
    }
    return 0;
}

static int add_extra(br_json *extra, const char *name, const char *value)
{
    return add_extra_len(extra, name, value, value ? strlen(value) : 0);
}

static int verify_openrouter(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) == 0
            ? 0 : fail(error, "cannot set OpenRouter verification error");
    if (secret.len > SIZE_MAX - 8) return fail(error, "OpenRouter authorization is too large");
    char *auth = malloc(7 + secret.len + 1);
    if (!auth) return fail(error, "cannot format OpenRouter authorization");
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, secret.data, secret.len);
    auth[7 + secret.len] = '\0';
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://openrouter.ai/api/v1/key",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 1057,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    or_key key = {0};
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error;
    } else if (response.status == 200) {
        int decoded = or_decode(response.body, response.body_error, &key, error);
        if (decoded < 0) rc = -1;
        else if (decoded > 0) cause = key.cause;
        else {
            verified = true;
            result->extra_data = json_object_new_object();
            if (!result->extra_data ||
                add_extra_len(result->extra_data, "label", key.label, key.label_len) != 0 ||
                add_extra(result->extra_data, "limit", key.limit) != 0 ||
                add_extra(result->extra_data, "usage", key.usage) != 0 ||
                add_extra(result->extra_data, "is_free_tier", key.free) != 0 ||
                add_extra(result->extra_data, "limit_remaining", key.remaining) != 0)
                rc = fail(error, "cannot store OpenRouter extra data");
        }
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = fail(error, "cannot format OpenRouter status");
        else cause = status_error;
    }
    br_http_release(ctx, &response);
    if (!rc) {
        result->verified = verified;
        if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
            rc = fail(error, "cannot set OpenRouter verification error");
    }
    free(key.cause);
    free(key.label);
    free(send_error);
    free(auth);
    return rc;
}

static int scan_openrouter(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized OpenRouter scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (secret.len != 73) rc = fail(&owned, "invalid OpenRouter capture");
        else if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0)
            rc = fail(&owned, "cannot create OpenRouter finding");
        if (!rc) {
            char *redacted = malloc(19);
            if (!redacted) rc = fail(&owned, "cannot redact OpenRouter token");
            else {
                memcpy(redacted, secret.data, 12);
                memcpy(redacted + 12, "...", 3);
                memcpy(redacted + 15, secret.data + 70, 3);
                redacted[18] = '\0';
                result.redacted = redacted;
            }
        }
        if (!rc && verify) rc = verify_openrouter(ctx, secret, &result, &owned);
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append OpenRouter finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"sk-or-v1-"};
static br_detector openrouter = {
    .type = 1057, .version = 0, .name = "OpenRouter", .custom_name = "",
    .description = "OpenRouter provides a unified API that gives you access to hundreds of AI models through a single endpoint, while automatically handling fallbacks and selecting the most cost-effective options.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_openrouter,
};

int br_openrouter_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid OpenRouter detector output");
    *out = NULL;
    if (openrouter.state) { *out = &openrouter; return 0; }
    br_regex *regex = NULL;
    if (br_regex_compile("\\b(sk-or-v1-[0-9a-f]{64})\\b", &regex, error) != 0) return -1;
    openrouter.state = regex;
    *out = &openrouter;
    return 0;
}
