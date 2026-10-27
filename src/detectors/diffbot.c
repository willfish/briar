/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/diffbot/diffbot.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int diffbot_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int diffbot_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, char **error)
{
    /* Source assigns its PACKAGE client's Timeout before constructing requests.
     * Model the selected request as SANE + 10s, not PUBLIC or a global engine
     * timeout mutation. Persistent shared-client mutation/races remain a gap. */
    const uint32_t timeout_ms = 10000;
    char url[sizeof("https://api.diffbot.com/v4/account?token=") + 32];
    int n = snprintf(url, sizeof(url), "https://api.diffbot.com/v4/account?token=%.32s", (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url))
        return diffbot_fail(error, "cannot format Diffbot request URL");
    /* The complete 73-byte URL + NUL precedes the known constructor skip. */
    if (!ctx) {
        *keep = false;
        return 0;
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .timeout_ms = timeout_ms, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    static const unsigned char token_marker[] = "\"token\":";
    static const unsigned char credits_marker[] = "\"planCredits\":";
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain. ReadAll
     * failure, including a non-NULL empty cause, RETAINS this false finding.
     * No setter or diagnostic-stage classifier, and no body-error drop policy. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && !response.body_error) {
        bool valid = br_slice_find(response.body, (br_slice){token_marker, sizeof(token_marker) - 1}, 0) != SIZE_MAX &&
                     br_slice_find(response.body, (br_slice){credits_marker, sizeof(credits_marker) - 1}, 0) != SIZE_MAX;
        result->verified = response.status >= 200 && response.status < 300 && valid;
    }
    /* Literal binary substrings, anywhere/past NUL/in either order: never JSON
     * parsing, whitespace normalization or equality with the candidate key.
     * Source defers Close ONLY AFTER successful ReadAll. Always release the ABI
     * response, even on errors, rather than reproducing leaked body lifetimes.
     * Keep the stack URL alive through release; eager buffering/lifetime, full
     * client and global engine/output behavior remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int diffbot_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return diffbot_fail(error, "invalid or uninitialized Diffbot scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* TrimSpace is a no-op for this grammar. Preserve occurrences/duplicates;
     * br_scan_key has no private constructor-skip outcome, so do not append
     * artificial findings and clear them later to represent source continue. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = diffbot_fail(&owned_error, "cannot create Diffbot result");
        if (rc == 0 && verify && diffbot_verify(ctx, key, &result, &keep, &owned_error) != 0)
            rc = -1;
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = diffbot_fail(&owned_error, "cannot append Diffbot result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const diffbot_keywords[] = {"diffbot"};
static br_detector diffbot_detector = {
    .type = 726, .version = 0, .name = "Diffbot", .custom_name = "",
    .description = "Diffbot is a service that provides APIs for extracting data from web pages. Diffbot API tokens can be used to access these services and extract data from web content.",
    .keywords = diffbot_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = diffbot_scan,
};

int br_diffbot_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return diffbot_fail(error, "invalid Diffbot detector output");
    *out = NULL;
    if (br_key_pattern_init(&diffbot_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &diffbot_detector;
    return 0;
}
