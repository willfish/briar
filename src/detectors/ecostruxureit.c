/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ecostruxureit/ecostruxureit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int ecostruxureit_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes constructor skip, NOT a rejected/indeterminate credential.
 * All shared setup/allocation/Do failures instead retain an unverified finding. */
static bool ecostruxureit_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false;
    /* Headers follow successful construction. Exact ASCII captures are 53..58
     * bytes: complete max 65-byte Bearer auth plus NUL, without a heap/formatter
     * seam or truncation. Stack storage remains borrowed through release. */
    char authorization[66];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.ecostruxureit.com/rest/v1/organizations",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Ignore all response bodies/read errors, including empty non-NULL errors.
     * Suppress the whole mixed shared setup/allocation/Do domain without any
     * setter or diagnostic classification; do not confuse Do error with skip. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close, without reading. ABI1 buffers eagerly and owns
     * response release even on failure. Full deferred-close/client/regexp and
     * global source/engine/output parity remain partial. Auth lives through
     * synchronous send AND release, including failed sends. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int ecostruxureit_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ecostruxureit_fail(error, "invalid or uninitialized EcoStruxureIT scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace cannot change this ASCII grammar. Retain every original
         * occurrence without validation, filtering, uniqueness or caching.
         * Finding failures precede even nil-context constructor skips. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ecostruxureit_fail(&owned_error, "cannot create EcoStruxureIT result");
        if (rc == 0 && verify) keep = ecostruxureit_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = ecostruxureit_fail(&owned_error, "cannot append EcoStruxureIT result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ecostruxureit_keywords[] = {"ecostruxureit"};
static br_detector ecostruxureit_detector = {
    .type = 801, .version = 0, .name = "EcoStruxureIT", .custom_name = "",
    .description = "EcoStruxure IT is a cloud-based platform that provides IT infrastructure management. EcoStruxure IT API keys can be used to access and manage IT infrastructure data and operations.",
    .keywords = ecostruxureit_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ecostruxureit_scan,
};

int br_ecostruxureit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ecostruxureit_fail(error, "invalid EcoStruxureIT detector output");
    *out = NULL;
    /* Only the keyword is CI. Slash is both captured alphabet and nonword:
     * preserve greedy quantifier/backtracking and \b, never a token-end policy. */
    if (br_key_pattern_init(&ecostruxureit_detector, "\\b(AK1[0-9a-zA-Z\\/]{50,55})\\b", error) != 0) return -1;
    *out = &ecostruxureit_detector;
    return 0;
}
