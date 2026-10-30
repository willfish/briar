/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/weatherbit/weatherbit.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char weatherbit_prefix[] =
    "https://api.weatherbit.io/v2.0/history/airquality?lat=38.0&lon=-78.0&key=";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void verify_weatherbit(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[sizeof(weatherbit_prefix) + 32];
    memcpy(url, weatherbit_prefix, sizeof(weatherbit_prefix) - 1);
    memcpy(url + sizeof(weatherbit_prefix) - 1, key, 33);
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 597,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
}

static int scan_weatherbit(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized WeatherBit scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32) { rc = fail(error, "invalid WeatherBit capture"); break; }
        br_result result = {0};
        /* The query is assembled before NewRequest, so a nil context drops only
         * after that URL exists. The 32-byte class needs no escaping. */
        char url[sizeof(weatherbit_prefix) + 32];
        memcpy(url, weatherbit_prefix, sizeof(weatherbit_prefix) - 1);
        memcpy(url + sizeof(weatherbit_prefix) - 1, key.data, 32);
        url[sizeof(weatherbit_prefix) - 1 + 32] = '\0';
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            rc = fail(error, "out of memory creating WeatherBit result");
        } else if (verify && !ctx) {
            br_result_clear(&result);
            continue;
        } else if (verify) verify_weatherbit(ctx, keys.items[i], &result);
        (void)url;
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append WeatherBit result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const weatherbit_keywords[] = {"weatherbit"};
static br_detector weatherbit_detector = {
    .type = 597, .version = 0, .name = "WeatherBit", .custom_name = "",
    .description = "Weatherbit is a weather data service provider. Weatherbit API keys can be used to access weather data and related services.",
    .keywords = weatherbit_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_weatherbit,
};

int br_weatherbit_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid WeatherBit detector output");
    *out = NULL;
    if (br_key_pattern_init(&weatherbit_detector, "\\b([0-9a-z]{32})\\b", error) != 0) return -1;
    *out = &weatherbit_detector;
    return 0;
}
