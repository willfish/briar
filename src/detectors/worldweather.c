/* SPDX-License-Identifier: AGPL-3.0-only */
/* WorldWeather, from pinned TruffleHog pkg/detectors/worldweather/worldweather.go. */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[128];
    int n = snprintf(url, sizeof(url),
                     "https://api.worldweatheronline.com/premium/v1/search.ashx?query=LA&key=%s", key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format WorldWeather URL");
    if (!ctx) return 1;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .timeout_ms = 5000, .detector_type = 483, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    if (!rc && response.status >= 200 && response.status < 300) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid WorldWeather scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key(&result, detector->type, found.items[i], "key") != 0)
            rc = fail(&owned, "cannot create WorldWeather finding");
        else if (verify_requested && (outcome = verify(ctx, found.items[i], &result, &owned)) < 0)
            rc = -1;
        else if (!outcome && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append WorldWeather finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "WorldWeather", .type = 483, .description =
        "Worldweather provides weather data services through its API. The keys can be used to access various weather data endpoints.",
    .keywords = (const char *[]){"worldweather", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .custom_name = "",
};

int br_worldweather_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid WorldWeather detector output");
    *out = NULL;
    if (!detector.state && br_key_pattern_init(&detector, "\\b([a-z0-9]{31})\\b", error) != 0)
        return -1;
    *out = &detector;
    return 0;
}
