/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/technicalanalysisapi/technicalanalysisapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { TA_ABORT = -1, TA_KEEP = 0, TA_DROP = 1 } ta_outcome;

static int ta_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static ta_outcome ta_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[128];
    int n = snprintf(url, sizeof(url),
                     "https://technical-analysis-api.com/api/v1/analysis/BTC?apiKey=%s", key);
    if (n < 0 || (size_t)n >= sizeof(url))
        return ta_fail(error, "cannot format TechnicalAnalysisApi URL"), TA_ABORT;
    if (!ctx) return TA_DROP;
    /* SaneHttpClient with its timeout replaced by 10 seconds. No detector headers. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return TA_KEEP;
}

static int ta_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ta_fail(error, "invalid or uninitialized TechnicalAnalysisApi scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        ta_outcome outcome = TA_KEEP;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = ta_fail(&owned_error, "cannot create TechnicalAnalysisApi result");
        else if (verify)
            outcome = ta_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && outcome == TA_ABORT) rc = -1;
        if (rc == 0 && outcome == TA_KEEP && br_results_push(out, &result) != 0)
            rc = ta_fail(&owned_error, "cannot append TechnicalAnalysisApi result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ta_keywords[] = {"technicalanalysisapi"};
static br_detector ta_detector = {
    .type = 582, .version = 0, .name = "TechnicalAnalysisApi", .custom_name = "",
    .description = "TechnicalAnalysisApi is a service used for technical analysis of financial markets. The API key can be used to access and retrieve market analysis data.",
    .keywords = ta_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ta_scan,
};

int br_technicalanalysisapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ta_fail(error, "invalid TechnicalAnalysisApi detector output");
    *out = NULL;
    if (br_key_pattern_init(&ta_detector, "\\b([A-Z0-9]{48})\\b", error) != 0) return -1;
    *out = &ta_detector;
    return 0;
}
