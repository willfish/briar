/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dfuse/dfuse.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { DFUSE_ABORT = -1, DFUSE_KEEP = 0, DFUSE_SKIP = 1 } dfuse_outcome;

static int dfuse_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static dfuse_outcome dfuse_verify(const br_scan_ctx *ctx, br_slice key,
                                  br_result *result, char **error)
{
    /* The fixed ASCII capture needs no JSON escaping. Keep the complete compact
     * body on the stack, borrowed through synchronous send AND release. */
    char body[51];
    _Static_assert(sizeof("{\"api_key\":\"\"}") + 36 == sizeof(body),
                   "Dfuse body must be 50 bytes plus NUL");
    int n = snprintf(body, sizeof(body), "{\"api_key\":\"%.*s\"}",
                     (int)key.len, (const char *)key.data);
    if (n != (int)sizeof(body) - 1) {
        dfuse_fail(error, "cannot format Dfuse request body");
        return DFUSE_ABORT;
    }
    /* Body preparation precedes NewRequestWithContext's known nil-context skip.
     * Headers are added only after successful construction. */
    if (!ctx) return DFUSE_SKIP;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://auth.dfuse.io/v1/auth/issue",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* This endpoint issues sessions. No retries/coalescing are added here.
     * Suppress the WHOLE shared setup/allocation/Do domain, without a setter
     * or diagnostic classifier. Every 2xx verifies; bodies/read errors do not. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Eager buffering
     * and release, native POST redirects (still fail-closed), full client and
     * global engine/output behavior remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DFUSE_KEEP;
}

static int dfuse_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return dfuse_fail(error, "invalid or uninitialized Dfuse scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Original occurrences, not a set. TrimSpace is a no-op for this grammar.
     * br_scan_key's verifier cannot express constructor SKIP after body prep. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        dfuse_outcome outcome = DFUSE_KEEP;
        /* Finding resources must fail before body preparation or any skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            dfuse_fail(&owned_error, "cannot create Dfuse result");
            outcome = DFUSE_ABORT;
        }
        if (outcome == DFUSE_KEEP && verify)
            outcome = dfuse_verify(ctx, key, &result, &owned_error);
        if (outcome == DFUSE_KEEP && br_results_push(out, &result) != 0) {
            dfuse_fail(&owned_error, "cannot append Dfuse result");
            outcome = DFUSE_ABORT;
        }
        br_result_clear(&result);
        if (outcome == DFUSE_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const dfuse_keywords[] = {"dfuse"};
static br_detector dfuse_detector = {
    .type = 567, .version = 0, .name = "Dfuse", .custom_name = "",
    .description = "Dfuse is a blockchain API company providing access to blockchain data and infrastructure. Dfuse API keys can be used to access and interact with blockchain data.",
    .keywords = dfuse_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = dfuse_scan,
};

int br_dfuse_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return dfuse_fail(error, "invalid Dfuse detector output");
    *out = NULL;
    if (!dfuse_detector.state) {
        br_regex *pattern = NULL;
        /* Dispatch uses dfuse, but direct extraction requires no keyword. */
        if (br_regex_compile("\\b(web\\_[0-9a-z]{32})\\b", &pattern, error) != 0)
            return -1;
        dfuse_detector.state = pattern;
    }
    *out = &dfuse_detector;
    return 0;
}
