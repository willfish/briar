/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/visualcrossing/visualcrossing.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_visualcrossing(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    const br_header headers[] = {
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = 419,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* TrimSpace is a no-op for this capture alphabet. Transport errors are suppressed. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_visualcrossing(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid VisualCrossing scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool skip = false;
        if (key.len != 25) rc = fail(&owned, "invalid VisualCrossing capture");
        else if (br_finding_key_bytes(&result, 419, key, "key") != 0)
            rc = fail(&owned, "cannot create VisualCrossing result");
        else if (verify) {
            char url[124];
            int n = snprintf(url, sizeof(url),
                             "https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/LA?key=%s",
                             keys.items[i]);
            if (n != 116) rc = fail(&owned, "cannot format VisualCrossing URL");
            else if (!ctx) skip = true; /* URL is complete before the constructor skip. */
            else verify_visualcrossing(ctx, url, &result);
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append VisualCrossing result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"visualcrossing"};
static br_detector visualcrossing = {
    .type = 419, .version = 0, .name = "VisualCrossing", .custom_name = "",
    .description = "Visual Crossing provides weather data services. Visual Crossing API keys can be used to access weather data and services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_visualcrossing,
};

int br_visualcrossing_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid VisualCrossing detector output");
    *out = NULL;
    if (br_key_pattern_init(&visualcrossing, "\\b([0-9A-Z]{25})\\b", error) != 0) return -1;
    *out = &visualcrossing;
    return 0;
}
