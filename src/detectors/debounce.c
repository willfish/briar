/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/debounce/debounce.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    DEBOUNCE_ABORT = -1, DEBOUNCE_KEEP = 0, DEBOUNCE_SKIP = 1
} debounce_outcome;

static int debounce_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static debounce_outcome debounce_verify(const br_scan_ctx *ctx, br_slice key,
                                        br_result *result, char **error)
{
    /* Email validation can consume credits or produce account activity.
     * Acceptance uses synthetic credentials and injected offline HTTP only. */
    char url[67];
    int n = snprintf(url, sizeof(url), "https://api.debounce.io/v1/?api=%.*s&email=some@gmail.com",
                     (int)key.len, (const char *)key.data);
    if (n != 66) {
        debounce_fail(error, "cannot format Debounce URL");
        return DEBOUNCE_ABORT;
    }
    /* The fixed source email, query order and trailing slash are intentional.
     * Prepare the complete URL before the known nil-context constructor skip. */
    if (!ctx) return DEBOUNCE_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the ENTIRE shared setup/allocation/Do error domain. No error
     * setter or diagnostic classifier. This is plain SANE.Do, without dedup. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Borrow the stack URL through send AND release. Source scan-defers Close
     * only and ignores bodies/read errors. Eager buffering/release, full native
     * SANE client behavior and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DEBOUNCE_KEEP;
}

static int debounce_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return debounce_fail(error, "invalid or uninitialized Debounce scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key's verifier cannot signal candidate skips or return a format
     * error cause. Reuse capture/finding helpers, preserving those outcomes and
     * finding -> URL preparation -> constructor skip -> append ordering here. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        debounce_outcome outcome = DEBOUNCE_KEEP;
        /* TrimSpace is a no-op. Preserve occurrences, without uniqueness,
         * entropy, local false-positive filtering or a persistent cache. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            debounce_fail(&owned_error, "cannot create Debounce result");
            outcome = DEBOUNCE_ABORT;
        }
        if (outcome == DEBOUNCE_KEEP && verify)
            outcome = debounce_verify(ctx, key, &result, &owned_error);
        if (outcome == DEBOUNCE_KEEP && br_results_push(out, &result) != 0) {
            debounce_fail(&owned_error, "cannot append Debounce result");
            outcome = DEBOUNCE_ABORT;
        }
        br_result_clear(&result);
        if (outcome == DEBOUNCE_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const debounce_keywords[] = {"debounce"};
/* The pinned default constructor is commented out. Direct factory availability
 * does not authorize default registration or resurrection through selectors. */
static br_detector debounce_detector = {
    .type = 257, .version = 0, .name = "Debounce", .custom_name = "",
    .description = "Debounce is an email validation service that helps in reducing bounce rates by verifying email addresses. Debounce API keys can be used to access and validate email addresses.",
    .keywords = debounce_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = debounce_scan,
};

int br_debounce_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return debounce_fail(error, "invalid Debounce detector output");
    *out = NULL;
    if (br_key_pattern_init(&debounce_detector, "\\b([a-zA-Z0-9]{13})\\b", error) != 0)
        return -1;
    *out = &debounce_detector;
    return 0;
}
