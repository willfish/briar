/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/duffeltoken/duffeltoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int duffeltoken_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int duffeltoken_verify(const br_scan_ctx *ctx, br_slice token,
                               br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &token, 1) != 0)
            return duffeltoken_fail(error, "cannot set DuffelToken verification error");
        return 0; /* Retain constructor failure as a false finding, not a skip. */
    }
    /* Exact ASCII capture is 55 bytes. Prepare auth/key AFTER construction;
     * complete bounded stack storage remains borrowed through send AND release. */
    char authorization[63];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, token.data, 55);
    authorization[62] = '\0';
    unsigned char dedup_key[60];
    memcpy(dedup_key, "1059:", 5);
    memcpy(dedup_key + 5, token.data, 55);
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Duffel-Version", "v2"},
        {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.duffel.com/identity/customer/users?limit=1",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key)}, /* Mandatory complete 1059:TOKEN, no NUL. */
    };
    br_http_response response = {0};
    char *send_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    /* ABI1 rejects nonempty coalescing keys BEFORE any transport callback.
     * Do not drop the key to manufacture verification success. Retain the whole
     * mixed shared setup/allocation/Do domain without classifying diagnostics. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else if (response.body_error != NULL)
        cause = response.body_error; /* Singleflight ReadAll must precede Do success. */
    else if (response.status == 200 || response.status == 403) result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = duffeltoken_fail(error, "cannot format DuffelToken verification status");
        else cause = status_error;
    }
    if (rc == 0 && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = duffeltoken_fail(error, "cannot set DuffelToken verification error");
    /* Setter copies/redacts before release. No status/body-success branch is
     * proven behind the unchanged guard. Logical empty body is not Go NoBody
     * identity; full singleflight buffering/replay/cancellation, deferred drain,
     * native-client, regexp and global source/engine/output parity remain gaps. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc == 0 ? 0 : -1;
}

static int duffeltoken_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return duffeltoken_fail(error, "invalid or uninitialized DuffelToken scan");
    size_t original_len = out->len;
    br_captures tokens = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, token, "token") != 0)
            rc = duffeltoken_fail(&owned_error, "cannot create DuffelToken result");
        if (rc == 0) {
            result.redacted = malloc(19);
            if (!result.redacted) rc = duffeltoken_fail(&owned_error, "cannot redact DuffelToken result");
            else { memcpy(result.redacted, token.data, 15); memcpy(result.redacted + 15, "...", 4); }
        }
        if (rc == 0 && verify && duffeltoken_verify(ctx, token, &result, &owned_error) != 0) rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = duffeltoken_fail(&owned_error, "cannot append DuffelToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const duffeltoken_keywords[] = {"duffel_test_", "duffel_live_"};
static br_detector duffeltoken_detector = {
    .type = 1059, .version = 0, .name = "DuffelToken", .custom_name = "",
    .description = "Duffel is a flight search and booking API service. Duffel API tokens can be used to access and interact with flight search and booking APIs in test environments.",
    .keywords = duffeltoken_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = duffeltoken_scan,
};

int br_duffeltoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return duffeltoken_fail(error, "invalid DuffelToken detector output");
    *out = NULL;
    if (!duffeltoken_detector.state) {
        br_regex *regex = NULL;
        /* Delimiter is CONSUMED by each whole match, not a lookahead/end \b.
         * Keep the source's inner test/live capture and original-byte uniqueness. */
        if (br_regex_compile("\\b(duffel_(test|live)_[A-Za-z0-9_-]{43})(?:$|[^A-Za-z0-9_-])", &regex, error) != 0) return -1;
        duffeltoken_detector.state = regex;
    }
    *out = &duffeltoken_detector;
    return 0;
}
