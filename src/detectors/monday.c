/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/monday/monday.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int monday_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int monday_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : monday_fail(error, "cannot create Monday verification cause");
}

static int monday_verify(const br_scan_ctx *ctx, const char *key, bool *verified,
                         char **cause, char **error)
{
    /* The literal reader/body is constructed before the nil constructor guard.
     * Immutable provider bytes and this view need no heap copy or JWT parsing. */
    static const unsigned char payload[] = "{\"query\":\"{boards(limit:1){id name}}\"}";
    br_slice body = {payload, sizeof(payload) - 1};
    *verified = false;
    *cause = NULL;
    if (!ctx) return monday_cause(cause, "net/http: nil Context", error);
    /* Constructor succeeds before source Content-Type then raw Authorization.
     * All original body/header/token values survive send AND local release. */
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", key}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.monday.com/v2",
        .headers = headers, .nheaders = 2, .body = body,
        .profile = BR_HTTP_SANE, .detector_type = 246,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = 0;
    bool good = false;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        /* Propagate the WHOLE mixed shared prep/Do domain, including NULL.
         * Preserve borrowed cause bytes before release; never classify text. */
        if (transport_error) rc = monday_cause(cause, transport_error, error);
    } else if (response.status == 200) good = true;
    else if (response.status != 401) {
        char message[64];
        int len = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        if (len < 0 || (size_t)len >= sizeof(message))
            rc = monday_fail(error, "cannot format Monday status cause");
        else rc = monday_cause(cause, message, error);
    }
    /* Source helper drains/closes BEFORE returning to its mandatory setter.
     * Ignore body/read/drain failures; ABI1 releases every attempted send once,
     * also on preparation/guard/resource failures. Never retain prepared UA or
     * request/header-array storage after ordinary send returns. */
    br_http_release(ctx, &response);
    free(transport_error);
    if (rc == 0) *verified = good;
    return rc == 0 ? 0 : -1;
}

static int monday_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return monday_fail(error, "invalid or uninitialized Monday scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op for the literal ASCII JWT-shaped grammar. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = monday_fail(error, "cannot create Monday result");
        if (rc == 0 && verify) {
            bool verified = false;
            char *cause = NULL;
            rc = monday_verify(ctx, keys.items[i], &verified, &cause, error);
            if (rc == 0) {
                result.verified = verified;
                /* Mandatory even for NULL cause; source supplies ZERO explicit
                 * secrets. Never add Raw/token/parts or automatic redaction. */
                if (br_result_set_verification_error(&result, cause, NULL, 0) != 0)
                    rc = monday_fail(error, "cannot set Monday verification error");
            }
            free(cause);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = monday_fail(error, "cannot append Monday result");
        br_result_clear(&result);
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const monday_keywords[] = {"monday"};
static br_detector monday_detector = {
    .type = 246, .version = 0, .name = "Monday", .custom_name = "",
    .description = "Monday.com is a work operating system that powers teams to run projects and workflows with confidence. "
                   "Monday API keys can be used to access and modify data and workflows on the platform.",
    .keywords = monday_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = monday_scan,
};

int br_monday_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return monday_fail(error, "invalid Monday detector output");
    *out = NULL;
    if (br_key_pattern_init(&monday_detector,
        "\\b(eyJ[A-Za-z0-9-_]{15,100}\\.eyJ[A-Za-z0-9-_]{100,300}\\.[A-Za-z0-9-_]{25,100})\\b", error) != 0) return -1;
    *out = &monday_detector;
    return 0;
}
