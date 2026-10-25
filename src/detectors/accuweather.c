/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/accuweather/{v1,v2}/accuweather.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool sufficient_key_entropy(const char *key)
{
    /* Both capture alphabets are ASCII, so rune and byte counts coincide. */
    size_t len = strlen(key);
    double counts[128] = {0};
    for (size_t i = 0; i < len; ++i) ++counts[(unsigned char)key[i]];
    double inverse_total = 1.0 / (double)len, entropy = 0;
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        if (!counts[i]) continue;
        double probability = counts[i] * inverse_total;
        entropy += probability * log2(probability);
    }
    return -entropy >= 4.0;
}

static int verify_accuweather(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[192];
    /* Upstream concatenates the key into RawQuery without escaping percent signs. */
    snprintf(url, sizeof(url),
             "https://dataservice.accuweather.com/locations/v1/cities/autocomplete?apikey=%s&q=----&language=en-us",
             key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 303,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* The response body and body-read errors are ignored upstream. */
        switch (response.status) {
        case 200:
        case 403: result->verified = true; break; /* Lack of permission still validates the key. */
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_accuweather(const br_detector *detector, const br_scan_ctx *ctx,
                            bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Accuweather scan arguments");

    br_captures matches = {0}, keys = {0};
    int rc = br_captures_find(detector->state, input, &matches, false, error);
    /* Both versions use v1 ProcessMatches: entropy, uniqueness, then verification. */
    for (size_t i = 0; rc == 0 && i < matches.len; ++i) {
        const char *key = matches.items[i];
        if (!sufficient_key_entropy(key)) continue;
        rc = br_captures_push(&keys, (br_slice){(const unsigned char *)key, strlen(key)},
                              true, error);
    }
    br_captures_clear(&matches);

    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0 ||
            (verify && verify_accuweather(ctx, keys.items[i], &result) != 0) ||
            br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory creating Accuweather result");
        br_result_clear(&result);
    }
    br_captures_clear(&keys);
    return rc;
}

static const char *const keywords[] = {"accuweather"};
static const char description[] =
    "AccuWeather is a weather forecasting service. "
    "AccuWeather API keys can be used to access weather data and forecasts.";

static br_detector accuweather_v1 = {
    .type = 303, .version = 1, .name = "Accuweather", .custom_name = "",
    .description = description, .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_accuweather,
};
static br_detector accuweather_v2 = {
    .type = 303, .version = 2, .name = "Accuweather", .custom_name = "",
    .description = description, .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_accuweather,
};

static int init_accuweather(br_detector *detector, const char *capture,
                            const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Accuweather detector output");
    *out = NULL;
    if (!detector->state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(detector->keywords, detector->nkeywords,
                                      capture, &regex, error) != 0)
            return -1;
        detector->state = regex;
    }
    *out = detector;
    return 0;
}

int br_accuweather_v1_init(const br_detector **out, char **error)
{
    return init_accuweather(&accuweather_v1, "([a-z0-9A-Z\\%]{35})\\b", out, error);
}

int br_accuweather_v2_init(const br_detector **out, char **error)
{
    return init_accuweather(&accuweather_v2, "\\b([a-zA-Z0-9]{32})\\b", out, error);
}
