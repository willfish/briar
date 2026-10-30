/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lob/lob.go. */
#include "captures.h"
#include "findings.h"
#include "gcp_json.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int lob_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int lob_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : lob_fail(error, "cannot allocate Lob verification cause");
}

typedef struct {
    br_json *code_ref;
    br_slice code;
    br_bytes repair;
    bool type_error;
    char **fatal;
} lob_projection;

static int lob_code_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    lob_projection *projection = user;
    if (!br_json_field_name(name, "code") || !value) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        projection->type_error = true;
        return 0;
    }
    br_slice text = {0};
    br_bytes repair = {0};
    if (br_gcp_json_text(value, &text, &repair, projection->fatal) != 0) {
        free(repair.data);
        return -1;
    }
    /* Ordered visitor values are borrowed, including overwritten duplicates. */
    json_object_get(value);
    json_object_put(projection->code_ref);
    free(projection->repair.data);
    projection->code_ref = value;
    projection->code = text;
    projection->repair = repair;
    return 0;
}

static int lob_error_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    lob_projection *projection = user;
    if (!br_json_field_name(name, "error") || !value) return 0;
    if (!json_object_is_type(value, json_type_object)) {
        projection->type_error = true;
        return 0;
    }
    /* Value structs merge; null is a no-op. Continue after ordinary type errors
     * so a subsequent owned projection failure cannot be hidden. */
    return br_json_each_member(encoded, lob_code_member, projection);
}

static bool lob_code_is(br_slice code, const char *expected)
{
    size_t len = strlen(expected);
    return code.len == len && !memcmp(code.data, expected, len);
}

static int lob_forbidden(const br_http_response *response, bool *verified,
                          char **cause, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    char *decode_cause = NULL;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &decode_cause);
    free(decode_cause);
    if (rc != 0) {
        json_object_put(root);
        /* Only this helper's documented +1 domain is ordinary decode failure. */
        return rc == 1 ? lob_cause(cause, "invalid API response", error) :
                         lob_fail(error, "cannot decode Lob response");
    }
    lob_projection projection = {.fatal = error};
    if (root && !json_object_is_type(root, json_type_object)) projection.type_error = true;
    else if (root && br_json_each_member((br_slice){response->body.data, end}, lob_error_member, &projection) != 0)
        rc = lob_fail(error && *error ? NULL : error, "cannot project Lob response");
    json_object_put(root);
    if (rc == 0) {
        if (projection.type_error) rc = lob_cause(cause, "invalid API response", error);
        else if (lob_code_is(projection.code, "billing_address_required") ||
                 lob_code_is(projection.code, "feature_limit_reached")) *verified = true;
        else if (!lob_code_is(projection.code, "invalid_api_key")) {
            static const char prefix[] = "unexpected error code: <";
            static const char suffix[] = "> in the API response body";
            size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
            /* Finish typed projection and exact known-code comparisons first.
             * ABI1 cannot carry an embedded NUL in a diagnostic C string. */
            if (projection.code.len && memchr(projection.code.data, 0, projection.code.len))
                rc = lob_fail(error, "unsupported: Lob error code contains NUL in verification diagnostic");
            else if (projection.code.len > SIZE_MAX - overhead)
                rc = lob_fail(error, "Lob verification cause too large");
            else {
                *cause = malloc(overhead + projection.code.len);
                if (!*cause) rc = lob_fail(error, "cannot allocate Lob verification cause");
                else {
                    memcpy(*cause, prefix, sizeof(prefix) - 1);
                    if (projection.code.len)
                        memcpy(*cause + sizeof(prefix) - 1, projection.code.data, projection.code.len);
                    memcpy(*cause + sizeof(prefix) - 1 + projection.code.len, suffix, sizeof(suffix));
                }
            }
        }
    }
    json_object_put(projection.code_ref);
    free(projection.repair.data);
    return rc;
}

static int lob_verify(const br_scan_ctx *ctx, br_slice key, bool *verified,
                       char **cause, char **error)
{
    *verified = false;
    *cause = NULL;
    if (!ctx) return lob_cause(cause, "net/http: nil Context", error);
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0) {
        free(authorization);
        return -1;
    }
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "POST", .url = "https://api.lob.com/v1/us_verifications",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = 490,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* Keep the whole mixed preparation/Do cause, never classify its text. */
        if (send_error) { *cause = send_error; send_error = NULL; }
        else rc = lob_cause(cause, "HTTP transport failed", error);
    } else {
        switch (response.status) {
        case 422: *verified = true; break;
        case 401: break;
        case 403: rc = lob_forbidden(&response, verified, cause, error); break;
        default: {
            char message[64];
            int n = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(message)) rc = lob_fail(error, "cannot format Lob status cause");
            else rc = lob_cause(cause, message, error);
            break;
        }
        }
    }
    /* Helper-local Close precedes caller Verified/setter/publication. Preserve
     * original auth/key values through one release, not synthesized headers/UA. */
    br_http_release(ctx, &response);
    free(authorization);
    free(send_error);
    return rc;
}

static int lob_finding(br_result *result, int32_t type, br_slice key, char **error)
{
    if (br_finding_key_bytes(result, type, key, "key") != 0)
        return lob_fail(error, "cannot create Lob result");
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return lob_fail(error, "cannot create Lob environment map");
    br_json *environment = json_object_new_string_len((const char *)key.data, 4);
    if (!environment) return lob_fail(error, "cannot create Lob environment string");
    if (json_object_object_add(result->extra_data, "environment", environment) != 0) {
        json_object_put(environment);
        return lob_fail(error, "cannot insert Lob environment");
    }
    return 0;
}

static int lob_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return lob_fail(error, "invalid or uninitialized Lob scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Source builds a unique map before any findings; map iteration is not a
     * promised ordering contract. TrimSpace is a no-op for this grammar. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 40) rc = lob_fail(&owned_error, "invalid Lob capture");
        else rc = lob_finding(&result, detector->type, key, &owned_error);
        if (rc == 0 && verify) {
            bool verified = false;
            char *cause = NULL;
            rc = lob_verify(ctx, key, &verified, &cause, &owned_error);
            if (rc == 0) {
                result.verified = verified;
                /* Source calls this even for NULL, and supplies NO secrets. */
                if (br_result_set_verification_error(&result, cause, NULL, 0) != 0)
                    rc = lob_fail(&owned_error, "cannot store Lob verification error");
            }
            free(cause);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = lob_fail(&owned_error, "cannot append Lob result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const lob_keywords[] = {"live_", "test_"};
static br_detector lob_detector = {
    .type = 490, .version = 0, .name = "Lob", .custom_name = "",
    .description = "Lob is a service for automating the creation and sending of letters, checks, and postcards. Lob API keys can be used to access and manage these services.",
    .keywords = lob_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = lob_scan,
};

int br_lob_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return lob_fail(error, "invalid Lob detector output");
    *out = NULL;
    if (!lob_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b((live|test)_[a-f0-9]{35})\\b", &regex, error) != 0) return -1;
        lob_detector.state = regex;
    }
    *out = &lob_detector;
    return 0;
}
