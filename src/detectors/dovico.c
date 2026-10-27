/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dovico/dovico.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int dovico_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int dovico_verify(const br_scan_ctx *ctx, br_slice key, br_slice user,
                          br_result *result, char **error)
{
    const br_slice secrets[] = {key, user}; /* Source redacts KEY THEN USER, sequentially. */
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", secrets, 2) != 0)
            return dovico_fail(error, "cannot set Dovico verification error");
        return 0; /* Constructor failure RETAINS this false finding. */
    }
    static const char prefix[] = "WRAP access_token=\"client=", middle[] = "&user_token=", suffix[] = "\"";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(middle) - 1 + sizeof(suffix);
    if (key.len > SIZE_MAX - fixed || user.len > SIZE_MAX - fixed - key.len)
        return dovico_fail(error, "Dovico Authorization header size overflow");
    /* Both tails are unbounded. One necessary complete owned header, created
     * AFTER request construction, with no cap, temporary copy or URL encoding. */
    char *authorization = malloc(fixed + key.len + user.len);
    if (!authorization) return dovico_fail(error, "cannot allocate Dovico Authorization header");
    size_t at = 0;
    memcpy(authorization, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(authorization + at, key.data, key.len); at += key.len;
    memcpy(authorization + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(authorization + at, user.data, user.len); at += user.len;
    memcpy(authorization + at, suffix, sizeof(suffix));
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.dovico.com/employees/?version=7",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    /* Shared setup/allocation and Do causes share one ABI1 domain. Retain the
     * cause without diagnostic-stage classification; own failures remain fatal. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = dovico_fail(error, "cannot format Dovico verification status");
        else cause = status_error;
    }
    /* Copy/redact BEFORE release, including substring overlap from key-first
     * replacement. NULL cause is a no-op; positive setter failure is fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, secrets, 2) != 0)
        rc = dovico_fail(error, "cannot set Dovico verification error");
    /* Complete auth remains live through synchronous send AND release. Logical
     * empty body does not establish Go http.NoBody object identity. Source
     * defers drain+close and ignores read errors; eager buffering/release, full
     * private-client, map order and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(send_error);
    free(authorization);
    return rc == 0 ? 0 : -1;
}

static int dovico_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dovico_fail(error, "invalid or uninitialized Dovico scan");
    size_t original_len = out->len;
    br_captures credentials = {0};
    char *owned_error = NULL;
    /* IDENTICAL original grammars and set memberships need only one compiled
     * pattern and byte-unique capture collection, without policy machinery. */
    int rc = br_captures_find(detector->state, input, &credentials, true, &owned_error);
    for (size_t k = 0; rc == 0 && k < credentials.len; ++k) {
        br_slice key = br_captures_at(&credentials, k);
        for (size_t u = 0; rc == 0 && u < credentials.len; ++u) {
            br_slice user = br_captures_at(&credentials, u);
            if (key.len == user.len && !memcmp(key.data, user.data, key.len)) continue;
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, key, "key", user, "user_key", (br_slice){(const unsigned char *)":", 1}) != 0)
                rc = dovico_fail(&owned_error, "cannot create Dovico result");
            if (rc == 0 && verify && dovico_verify(ctx, key, user, &result, &owned_error) != 0) rc = -1;
            bool verified = result.verified;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = dovico_fail(&owned_error, "cannot append Dovico result");
            br_result_clear(&result);
            /* Push moves/zeros the result: save Verified, and only break AFTER
             * successful append. Never let this normal break swallow failures. */
            if (rc == 0 && verified) break;
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&credentials);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dovico_keywords[] = {"dovico"};
static br_detector dovico_detector = {
    .type = 386, .version = 0, .name = "Dovico", .custom_name = "",
    .description = "Dovico is a time tracking and project management service. Dovico keys can be used to access and manage time tracking and project data.",
    .keywords = dovico_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = dovico_scan,
};

int br_dovico_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dovico_fail(error, "invalid Dovico detector output");
    *out = NULL;
    if (br_key_pattern_init(&dovico_detector, "\\b([0-9a-z]{32}\\.[0-9a-z]{1,}\\b)", error) != 0) return -1;
    *out = &dovico_detector;
    return 0;
}
