/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fetchrss/fetchrss.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { bool success; intptr_t code; br_json *message; char *cause; } fetchrss_response;

static int fetchrss_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static br_slice fetchrss_number_text(br_slice number)
{
    while (number.len) {
        unsigned char c = number.data[number.len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --number.len;
    }
    return number;
}

static bool fetchrss_parse_code(br_slice number, intptr_t *out)
{
    /* Reuse Api2Cart/Copper's checked ORIGINAL-number-span mechanic: fractions,
     * exponents and overflow are type errors, never json-c saturation/coercion. */
    size_t at = 0;
    bool negative = number.len && number.data[0] == '-';
    if (negative) ++at;
    if (at == number.len) return false;
    uintptr_t limit = (uintptr_t)INTPTR_MAX + (negative ? 1u : 0u), magnitude = 0;
    for (; at < number.len; ++at) {
        unsigned char c = number.data[at];
        if (c < '0' || c > '9') return false;
        uintptr_t digit = c - '0';
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    if (!negative) *out = (intptr_t)magnitude;
    else if (magnitude == (uintptr_t)INTPTR_MAX + 1u) *out = INTPTR_MIN;
    else *out = -(intptr_t)magnitude;
    return true;
}

static int fetchrss_number_cause(br_slice number, char **cause)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field .error.code of type int";
    size_t fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (number.len > SIZE_MAX - fixed) return -1;
    *cause = malloc(fixed + number.len);
    if (!*cause) return -1;
    memcpy(*cause, prefix, sizeof(prefix) - 1);
    memcpy(*cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(*cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    return 0;
}

static int fetchrss_error_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    fetchrss_response *fields = user;
    if (!value) return 0; /* Primitive null never resets an earlier assignment. */
    if (br_json_field_name(name, "message")) {
        if (json_object_is_type(value, json_type_string)) {
            json_object_put(fields->message); fields->message = json_object_get(value);
        } else if (!fields->cause && br_json_type_cause(value, ".error.message", "string", &fields->cause) != 0) return -1;
    } else if (br_json_field_name(name, "code")) {
        if (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double)) {
            br_slice number = fetchrss_number_text(encoded);
            intptr_t code;
            if (fetchrss_parse_code(number, &code)) fields->code = code;
            else if (!fields->cause && fetchrss_number_cause(number, &fields->cause) != 0) return -1;
        } else if (!fields->cause && br_json_type_cause(value, ".error.code", "int", &fields->cause) != 0) return -1;
    }
    return 0;
}

static int fetchrss_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    fetchrss_response *fields = user;
    if (!value) return 0; /* Null value-struct also leaves its existing fields intact. */
    if (br_json_field_name(name, "success")) {
        if (json_object_is_type(value, json_type_boolean)) fields->success = json_object_get_boolean(value);
        else if (!fields->cause && br_json_type_cause(value, "response.success", "bool", &fields->cause) != 0) return -1;
    } else if (br_json_field_name(name, "error")) {
        if (json_object_is_type(value, json_type_object)) return br_json_each_member(encoded, fetchrss_error_member, fields);
        if (!fields->cause && br_json_type_cause(value, "response.error", "struct { Message string \"json:\\\"message\\\"\"; Code int \"json:\\\"code\\\"\" }", &fields->cause) != 0) return -1;
    }
    /* Continue even after the first type error: later resource failures are
     * fatal. Nested duplicate objects merge; unknown huge numbers are ignored. */
    return 0;
}

static int fetchrss_decode(br_slice body, const char *read_error, fetchrss_response *fields)
{
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(body, read_error, &root, &end, &fields->cause);
    if (rc == 0 && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){body.data, end}, fetchrss_member, fields);
        else rc = br_json_type_cause(root, NULL, "fetchrss.response", &fields->cause) == 0 ? 1 : -1;
    }
    json_object_put(root);
    if (rc == 0 && fields->cause) rc = 1;
    /* Typed FIRST document only, with original spans and sticky first error.
     * Validate every known field BEFORE testing Success or code 401. No generic
     * float64-map conversion, whole-body Unmarshal or null-root panic. */
    return rc == 0 ? 0 : rc == 1 && fields->cause ? 1 : -1;
}

static int fetchrss_unexpected_cause(const fetchrss_response *fields, char **cause, char **error)
{
    br_slice message = br_json_text(fields->message);
    /* ONLY this diagnostic needs an ABI1 C string. Success/401 can ignore NUL. */
    if (memchr(message.data, '\0', message.len))
        return fetchrss_fail(error, "unsupported: Fetchrss diagnostic Message contains NUL; ABI1 error strings cannot represent it");
    char number[21]; int n = snprintf(number, sizeof(number), "%" PRIdPTR, fields->code);
    if (n < 0 || (size_t)n >= sizeof(number)) return fetchrss_fail(error, "cannot format Fetchrss diagnostic code");
    static const char prefix[] = "unexpected error: [code=", middle[] = ", message=", suffix[] = "]";
    size_t fixed = sizeof(prefix) - 1 + (size_t)n + sizeof(middle) - 1 + sizeof(suffix);
    if (message.len > SIZE_MAX - fixed) return fetchrss_fail(error, "Fetchrss diagnostic size overflow");
    *cause = malloc(fixed + message.len);
    if (!*cause) return fetchrss_fail(error, "cannot allocate Fetchrss diagnostic cause");
    size_t at = sizeof(prefix) - 1; memcpy(*cause, prefix, at);
    memcpy(*cause + at, number, (size_t)n); at += (size_t)n;
    memcpy(*cause + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(*cause + at, message.data, message.len); at += message.len;
    memcpy(*cause + at, suffix, sizeof(suffix)); /* Complete plain %s bytes, no quoting/redaction/cap. */
    return 0;
}

static int fetchrss_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    static const char base[] = "https://fetchrss.com/api/v1/feed/list?auth=";
    char url[sizeof(base) + 40];
    _Static_assert(sizeof(url) == 84, "Fetchrss URL is 83 bytes plus NUL");
    memcpy(url, base, sizeof(base) - 1); memcpy(url + sizeof(base) - 1, token.data, 40); url[83] = '\0';
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0)
            return fetchrss_fail(error, "cannot set Fetchrss verification error");
        return 0; /* Retain constructor error, not skip/background context. */
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL, *unexpected = NULL;
    fetchrss_response fields = {0}; const char *cause = NULL; char status_error[80]; int rc = 0;
    /* Retain the WHOLE mixed setup/allocation/Do domain without classifying text. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else if (response.status == 200) {
        int decoded = fetchrss_decode(response.body, response.body_error, &fields);
        if (decoded < 0) rc = fetchrss_fail(error, "cannot decode Fetchrss verification response");
        else if (decoded == 1) cause = fields.cause;
        else if (fields.success) result->verified = true;
        else if (fields.code != 401) {
            rc = fetchrss_unexpected_cause(&fields, &unexpected, error); cause = unexpected;
        }
    } else {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = fetchrss_fail(error, "cannot format Fetchrss verification status");
        else cause = status_error;
    }
    /* Source passes ZERO secrets. Preserve credential echoes; copy all borrowed
     * causes before release. NULL no-op, setter +1 and own resources are fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = fetchrss_fail(error, "cannot set Fetchrss verification error");
    /* URL and retained original Message stay live through send/release. Source
     * defers drain+close; eager buffering/release, full Reader/raw-UTF8/unquoting,
     * private client/native/regexp and global source/engine/output parity are partial. */
    br_http_release(ctx, &response);
    free(send_error); free(unexpected); free(fields.cause); json_object_put(fields.message);
    return rc == 0 ? 0 : -1;
}

static int fetchrss_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fetchrss_fail(error, "invalid or uninitialized Fetchrss scan");
    size_t original_len = out->len; br_captures tokens = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0}; br_slice token = br_captures_at(&tokens, i);
        /* Original-byte uniqueness only: no TrimSpace, normalization, filter,
         * validation or cache. Finding resources precede constructor handling. */
        if (br_finding_key_bytes(&result, detector->type, token, "key") != 0)
            rc = fetchrss_fail(&owned_error, "cannot create Fetchrss result");
        if (rc == 0 && verify && fetchrss_verify(ctx, token, &result, &owned_error) != 0) rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0) rc = fetchrss_fail(&owned_error, "cannot append Fetchrss result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fetchrss_keywords[] = {"fetchrss"};
static br_detector fetchrss_detector = {
    .type = 592, .version = 0, .name = "Fetchrss", .custom_name = "",
    .description = "FetchRSS is a service used to convert web content into RSS feeds. FetchRSS API keys can be used to manage and access these feeds.",
    .keywords = fetchrss_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = fetchrss_scan,
};

int br_fetchrss_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fetchrss_fail(error, "invalid Fetchrss detector output");
    *out = NULL;
    if (br_key_pattern_init(&fetchrss_detector, "\\b([a-zA-Z0-9.]{40})\\b", error) != 0) return -1;
    *out = &fetchrss_detector;
    return 0;
}
