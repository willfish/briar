/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sendbird/sendbird.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *app; } sb_patterns;
typedef enum { SB_ABORT = -1, SB_KEEP = 0, SB_DROP = 1 } sb_outcome;

static const char sb_guide[] = "https://howtorotate.com/docs/tutorials/sendbird/";

static int sb_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static char *sb_join(const char *prefix, const char *detail)
{
    size_t n = strlen(prefix), m = strlen(detail);
    char *out = malloc(n + m + 1);
    if (!out) return NULL;
    memcpy(out, prefix, n);
    memcpy(out + n, detail, m + 1);
    return out;
}

static int sb_extra(br_result *result, char **error)
{
    result->extra_data = json_object_new_object();
    br_json *guide = json_object_new_string(sb_guide);
    if (!result->extra_data || !guide) {
        json_object_put(guide);
        return sb_fail(error, "cannot create Sendbird metadata");
    }
    if (json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return sb_fail(error, "cannot create Sendbird metadata");
    }
    return 0;
}

static bool sb_parse_int(br_slice number, intptr_t *out)
{
    size_t at = 0;
    bool negative = false;
    if (at < number.len && number.data[at] == '-') { negative = true; ++at; }
    if (at == number.len) return false;
    uintptr_t limit = (uintptr_t)INTPTR_MAX + (negative ? 1u : 0u), magnitude = 0;
    for (; at < number.len; ++at) {
        unsigned char c = number.data[at];
        if (c < '0' || c > '9') return false;
        uintptr_t digit = (uintptr_t)(c - '0');
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    if (!negative) *out = (intptr_t)magnitude;
    else if (magnitude == (uintptr_t)INTPTR_MAX + 1u) *out = INTPTR_MIN;
    else *out = -(intptr_t)magnitude;
    return true;
}

static int sb_number_cause(br_slice number, char **cause)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field userResp.code of type int";
    size_t fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (number.len > SIZE_MAX - fixed) return -1;
    *cause = malloc(fixed + number.len);
    if (!*cause) return -1;
    memcpy(*cause, prefix, sizeof(prefix) - 1);
    memcpy(*cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(*cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    return 0;
}

typedef struct { intptr_t code; bool seen, failed; char *cause; } sb_body;

static void sb_keep(sb_body *body, char *cause)
{
    if (!body->failed) {
        body->failed = true;
        body->cause = cause;
    } else free(cause);
}

/* 0 is a completed diagnostic, even when cause is NULL. Every other code is fatal. */
__attribute__((weak)) int br_sendbird_type_cause(br_json *value, const char *field,
                                                 const char *expected, char **cause)
{
    return br_json_type_cause(value, field, expected, cause);
}

static int sb_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    sb_body *body = user;
    if (!br_json_field_name(name, "code")) return 0;
    /* JSON null into an int is ignored, including after an earlier assignment. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
        intptr_t code = 0;
        if (sb_parse_int(encoded, &code)) { body->code = code; body->seen = true; return 0; }
        char *cause = NULL;
        if (sb_number_cause(encoded, &cause) != 0) return -1;
        sb_keep(body, cause);
        return 0;
    }
    char *cause = NULL;
    int typed = br_sendbird_type_cause(value, "userResp.code", "int", &cause);
    if (typed != 0) {
        free(cause);
        return typed;
    }
    sb_keep(body, cause);
    return 0;
}

__attribute__((weak)) int br_sendbird_json_document(br_slice body, const char *read_error,
                                                   br_json **out, size_t *end, char **cause)
{
    return br_json_first_document(body, read_error, out, end, cause);
}

__attribute__((weak)) int br_sendbird_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    return br_json_each_member(object, callback, user);
}

static int sb_decode_code(br_slice body, const char *read_error, intptr_t *code, char **cause)
{
    *cause = NULL;
    if (read_error) {
        *cause = sb_join("error decoding json response body: ", read_error);
        return *cause ? 1 : -1;
    }
    br_json *root = NULL;
    size_t end = 0;
    char *decode = NULL;
    int rc = br_sendbird_json_document(body, NULL, &root, &end, &decode);
    if (rc == 1) {
        *cause = decode ? sb_join("error decoding json response body: ", decode) : NULL;
        free(decode);
        return decode && !*cause ? -1 : 1;
    }
    if (rc != 0) {
        free(decode);
        json_object_put(root);
        return -1;
    }
    sb_body fields = {0};
    if (!root || json_object_is_type(root, json_type_null)) {
        /* Null into the struct is ignored, leaving the zero code. */
    } else if (!json_object_is_type(root, json_type_object)) {
        char *typed_cause = NULL;
        int typed = br_sendbird_type_cause(root, NULL, "sendbird.userResp", &typed_cause);
        if (typed != 0) {
            free(typed_cause);
            rc = typed;
        } else sb_keep(&fields, typed_cause);
    } else rc = br_sendbird_each_member((br_slice){body.data, end}, sb_member, &fields);
    json_object_put(root);
    if (rc != 0) { free(fields.cause); return -1; }
    if (fields.failed) {
        int joined = 0;
        if (fields.cause) {
            *cause = sb_join("error decoding json response body: ", fields.cause);
            joined = *cause ? 1 : -1;
        }
        free(fields.cause);
        return joined < 0 ? -1 : 1;
    }
    *code = fields.code;
    return 0;
}

static sb_outcome sb_verify(const br_scan_ctx *ctx, const char *app, const char *key,
                            br_result *result, char **error)
{
    char url[80];
    int n = snprintf(url, sizeof(url), "https://api-%s.sendbird.com/v3/users", app);
    if (n < 0 || (size_t)n >= sizeof(url))
        return sb_fail(error, "cannot format Sendbird verification URL"), SB_ABORT;
    if (!ctx) return SB_DROP;
    const br_header headers[] = {{"Api-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    char *cause = NULL;
    bool owned = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        cause = send_error;
    } else if (response.status >= 200 && response.status < 300) {
        result->verified = true;
    } else if (response.status == 400) {
        intptr_t code = 0;
        char *decode = NULL;
        int decoded = sb_decode_code(response.body, response.body_error, &code, &decode);
        if (decoded < 0) rc = sb_fail(error, "cannot decode Sendbird response");
        else if (decoded > 0) { cause = decode; owned = true; }
        else if (code != 400401) {
            int written = snprintf(status_error, sizeof(status_error),
                                   "unexpected response code: %ld", (long)code);
            if (written < 0 || (size_t)written >= sizeof(status_error))
                rc = sb_fail(error, "cannot format Sendbird response code");
            else cause = status_error;
        }
    } else {
        int written = snprintf(status_error, sizeof(status_error),
                               "unexpected HTTP response status %d", response.status);
        if (written < 0 || (size_t)written >= sizeof(status_error))
            rc = sb_fail(error, "cannot format Sendbird verification status");
        else cause = status_error;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    if (rc == 0 && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = sb_fail(error, "cannot set Sendbird verification error");
    br_http_release(ctx, &response);
    free(send_error);
    if (owned) free(cause);
    return rc == 0 ? SB_KEEP : SB_ABORT;
}

static int sb_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return sb_fail(error, "invalid or uninitialized Sendbird scan");
    const sb_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, apps = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->app, input, &apps, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    for (size_t a = 0; rc == 0 && a < apps.len; ++a) {
        for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
            br_result result = {0};
            sb_outcome outcome = SB_KEEP;
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0 ||
                sb_extra(&result, &owned_error) != 0)
                rc = owned_error ? -1 : sb_fail(&owned_error, "cannot create Sendbird result");
            else if (verify)
                outcome = sb_verify(ctx, apps.items[a], keys.items[k], &result, &owned_error);
            if (rc == 0 && outcome == SB_ABORT) rc = -1;
            if (rc == 0 && outcome == SB_KEEP && br_results_push(out, &result) != 0)
                rc = sb_fail(&owned_error, "cannot append Sendbird result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&apps);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const sb_keywords[] = {"sendbird"};
static sb_patterns sb_state;
static br_detector sb_detector = {
    .type = 750, .version = 0, .name = "Sendbird", .custom_name = "",
    .description = "Sendbird is a communication platform providing chat, voice, and video services. Sendbird API tokens can be used to access and manage communication services.",
    .keywords = sb_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = sb_scan, .state = &sb_state,
};

int br_sendbird_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return sb_fail(error, "invalid Sendbird detector output");
    *out = NULL;
    if (!sb_state.key &&
        br_regex_compile_prefixed(sb_keywords, 1, "\\b([0-9a-f]{40})\\b", &sb_state.key, error) != 0)
        return -1;
    if (!sb_state.app &&
        br_regex_compile_prefixed(sb_keywords, 1,
            "\\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\\b",
            &sb_state.app, error) != 0)
        return -1;
    *out = &sb_detector;
    return 0;
}
