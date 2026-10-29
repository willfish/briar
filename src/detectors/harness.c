/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/harness/harness.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int64_t last_login; char *cause; } harness_response;

static int harness_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void harness_remember(harness_response *response, char *cause)
{
    if (!response->cause) response->cause = cause;
    else free(cause);
}

static int harness_type(harness_response *response, br_json *value,
                        const char *field, const char *expected)
{
    char *cause = NULL;
    int rc = br_json_type_cause(value, field, expected, &cause);
    if (rc != 0) { free(cause); return -1; }
    harness_remember(response, cause);
    return 0;
}

static br_slice harness_number_text(br_slice encoded)
{
    while (encoded.len) {
        unsigned char c = encoded.data[encoded.len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        --encoded.len;
    }
    return encoded;
}

/* Select the 64-bit Go int contract, independently of C int/json-c widths.
 * The document is syntax-validated; exponent/fraction tokens are not Go ints. */
static bool harness_integer(br_slice text, int64_t *out)
{
    size_t at = 0;
    bool negative = text.len && text.data[0] == '-';
    if (negative) ++at;
    if (at == text.len) return false;
    uint64_t magnitude = 0, limit = (uint64_t)INT64_MAX + (negative ? 1u : 0u);
    for (; at < text.len; ++at) {
        unsigned char c = text.data[at];
        if (c < '0' || c > '9') return false;
        unsigned digit = c - '0';
        if (magnitude > (limit - digit) / 10) return false;
        magnitude = magnitude * 10 + digit;
    }
    *out = negative ? (magnitude == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)magnitude) : (int64_t)magnitude;
    return true;
}

static int harness_number_cause(harness_response *response, br_slice number)
{
    static const char prefix[] = "json: cannot unmarshal number ";
    static const char suffix[] = " into Go struct field .data.lastLogin of type int";
    size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
    if (number.len > SIZE_MAX - overhead) return -1;
    char *cause = malloc(overhead + number.len);
    if (!cause) return -1;
    memcpy(cause, prefix, sizeof(prefix) - 1);
    memcpy(cause + sizeof(prefix) - 1, number.data, number.len);
    memcpy(cause + sizeof(prefix) - 1 + number.len, suffix, sizeof(suffix));
    harness_remember(response, cause);
    return 0;
}

static int harness_data_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    harness_response *response = user;
    if (!br_json_field_name(name, "lastlogin") || !value) return 0;
    if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double))
        return harness_type(response, value, ".data.lastLogin", "int");
    int64_t number;
    br_slice text = harness_number_text(encoded);
    if (!harness_integer(text, &number)) return harness_number_cause(response, text);
    response->last_login = number;
    return 0;
}

static int harness_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    harness_response *response = user;
    if (!br_json_field_name(name, "data") || !value) return 0;
    if (!json_object_is_type(value, json_type_object))
        return harness_type(response, value, "response.data", "struct { LastLogin int \"json:\\\"lastLogin\\\"\" }");
    /* Nested structs merge in source order; null never resets a previous int.
     * Ordinary type errors stick, but cannot stop later owned work/failures. */
    return br_json_each_member(encoded, harness_data_member, response);
}

/* 0: first typed document decoded (including null); +1: ordinary decode/read
 * failure; -1: owned/resource failure, never the verified-without-metadata path. */
static int harness_decode(const br_http_response *http, harness_response *response)
{
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(http->body, http->body_error, &root, &end, &response->cause);
    if (rc != 0) { json_object_put(root); return rc == 1 ? 1 : -1; }
    if (root && !json_object_is_type(root, json_type_object))
        rc = harness_type(response, root, NULL, "harness.response");
    else if (root)
        rc = br_json_each_member((br_slice){http->body.data, end}, harness_member, response);
    json_object_put(root);
    if (rc != 0) return -1;
    return response->cause ? 1 : 0;
}

static int harness_metadata(br_json *extra, int64_t last_login, char **error)
{
    char decimal[32];
    int len = snprintf(decimal, sizeof(decimal), "%" PRId64, last_login);
    if (len < 0 || (size_t)len >= sizeof(decimal))
        return harness_fail(error, "cannot format Harness last login");
    br_json *value = json_object_new_string_len(decimal, len);
    if (!value) return harness_fail(error, "cannot allocate Harness last login");
    if (json_object_object_add(extra, "last_login", value) != 0) {
        json_object_put(value);
        return harness_fail(error, "cannot insert Harness last login");
    }
    return 0;
}

static int harness_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    bool verified = false;
    br_json *extra = NULL;
    const char *cause = NULL;
    char *send_error = NULL, status_error[64];
    int rc = 0;
    if (!ctx) cause = "net/http: nil Context";
    else {
        /* Captures are complete, NUL-terminated ASCII tokens. Only the original
         * provider values survive send; shared preparation ends at its return. */
        const br_header header = {"X-Api-Key", (const char *)key.data};
        const br_http_request request = {
            .method = "GET", .url = "https://app.harness.io/ng/api/user/currentUser",
            .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
            .detector_type = 1020,
        };
        br_http_response response = {0};
        if (br_http_send(ctx, &request, &response, &send_error) != 0)
            cause = send_error ? send_error : "HTTP transport failed";
        else if (response.status == 200) {
            /* Source allocates the initial map BEFORE decoding, including on
             * ordinary malformed/type/read failures which later discard it. */
            extra = json_object_new_object();
            if (!extra) rc = harness_fail(error, "cannot allocate Harness metadata");
            else {
                harness_response decoded = {0};
                int decoded_rc = harness_decode(&response, &decoded);
                if (decoded_rc < 0) rc = harness_fail(error, "cannot decode Harness response");
                else {
                    verified = true; /* Every successfully sent exact 200. */
                    if (decoded_rc == 0) rc = harness_metadata(extra, decoded.last_login, error);
                    else { json_object_put(extra); extra = NULL; }
                }
                free(decoded.cause);
            }
        } else if (response.status != 401) {
            int len = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            if (len < 0 || (size_t)len >= sizeof(status_error))
                rc = harness_fail(error, "cannot format Harness response status");
            else cause = status_error;
        }
        /* The helper's deferred drain/Close precedes caller publication and
         * sanitization, even on failed shared setup/Do attempts. */
        br_http_release(ctx, &response);
    }
    if (rc == 0) {
        result->verified = verified;
        json_object_put(result->extra_data);
        result->extra_data = extra; extra = NULL;
        /* NULL cause is deliberately still checked: it is a no-op, not clear. */
        if (br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = harness_fail(error, "cannot store Harness verification error");
    }
    json_object_put(extra);
    free(send_error);
    return rc;
}

static int harness_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return harness_fail(error, "invalid or uninitialized Harness scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    if (rc != 0 && !owned_error) harness_fail(&owned_error, "cannot collect Harness captures");
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = harness_fail(&owned_error, "cannot create Harness finding");
        if (rc == 0 && verify) rc = harness_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = harness_fail(&owned_error, "cannot append Harness finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const harness_keywords[] = {"harness"};
static br_detector harness_detector = {
    .type = 1020, .version = 0, .name = "Harness", .custom_name = "",
    .description = "Harness.io is an AI-driven CI/CD platform that automates software delivery, streamlining code building, testing, and deployment with intelligent optimization and multi-cloud support.",
    .keywords = harness_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = harness_scan,
};

int br_harness_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return harness_fail(error, "invalid Harness detector output");
    *out = NULL;
    if (!harness_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(harness_keywords, 1,
            "\\b(pat\\.[A-Za-z0-9_]{22}\\.[0-9a-f]{24}\\.[A-Za-z0-9]{20})\\b", &regex, error) != 0)
            return -1;
        harness_detector.state = regex;
    }
    *out = &harness_detector;
    return 0;
}
