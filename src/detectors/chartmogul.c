/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/chartmogul/chartmogul.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { CHART_ABORT = -1, CHART_KEEP = 0, CHART_SKIP = 1 } chartmogul_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static chartmogul_outcome verify_chartmogul(const br_scan_ctx *ctx, br_slice key,
                                            br_result *result, char **error)
{
    char *authorization = NULL;
    /* Source prepares Base64(KEY+":") BEFORE NewRequestWithContext. Do not
     * skip nil context first, or suppress the Basic helper's positive failure. */
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error)) {
        free(authorization);
        return CHART_ABORT;
    }
    if (!ctx) { free(authorization); return CHART_SKIP; }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.chartmogul.com/v1/ping",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Every Client.Do error retains an unverified finding, without an error.
     * ABI1 also mixes adapter setup/allocation failures into this domain;
     * preserve that explicit gap rather than classifying error text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read errors. Source scan-defers Close ONLY; ABI1 may buffer
     * eagerly and releases per request, not at the original deferred timing. */
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return CHART_KEEP;
}

static int scan_chartmogul(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Chartmogul scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; chartmogul_outcome outcome = CHART_KEEP;
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the captured lowercase ASCII alphabet. */
        if (br_finding_key_bytes(&result, detector->type, key, "key")) {
            fail(&owned_error, "cannot create Chartmogul result"); outcome = CHART_ABORT;
        }
        if (outcome == CHART_KEEP && verify) outcome = verify_chartmogul(ctx, key, &result, &owned_error);
        if (outcome == CHART_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Chartmogul result"); outcome = CHART_ABORT;
        }
        br_result_clear(&result); /* SKIP discards this candidate only. */
        if (outcome == CHART_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"chartmogul"};
static br_detector chartmogul = {
    .type = 815, .version = 0, .name = "Chartmogul", .custom_name = "",
    .description = "ChartMogul is a subscription analytics platform that helps businesses measure, understand, and grow their subscription revenue. ChartMogul API keys can be used to access and manage subscription data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_chartmogul,
};

int br_chartmogul_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Chartmogul detector output");
    *out = NULL;
    if (br_key_pattern_init(&chartmogul, "\\b([a-z0-9]{32})\\b", error)) return -1;
    *out = &chartmogul;
    return 0;
}
