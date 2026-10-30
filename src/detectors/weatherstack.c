/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/weatherstack/weatherstack.go. */
#include "detectors.h"
#include "captures.h"
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

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

static bool contains(br_slice body, const char *needle)
{
    return br_slice_find(body, (br_slice){(const unsigned char *)needle, strlen(needle)}, 0) != SIZE_MAX;
}

/* URL is complete before the nil-context drop. A body-read error drops only
 * this candidate. Do errors are ignored. Verification needs 2xx and either
 * marker; other statuses and bodies stay false without a setter. */
static int verify_weatherstack(const br_scan_ctx *ctx, br_slice secret, br_result *result, char **error)
{
    char url[128];
    int n = snprintf(url, sizeof(url), "https://api.weatherstack.com/current?access_key=%s&query=LA",
                     (const char *)secret.data);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format WeatherStack URL");
    if (!ctx) return 1;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 452,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error) rc = 1;
        else if (response.status >= 200 && response.status < 300 &&
                 (contains(response.body, "location") ||
                  contains(response.body, "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"")))
            result->verified = true;
    }
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int scan_weatherstack(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized WeatherStack scan");
    size_t before = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice secret = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0) {
            rc = fail(&owned, "cannot create WeatherStack finding");
        } else if (verify) {
            int status = verify_weatherstack(ctx, secret, &result, &owned);
            if (status > 0) {
                br_result_clear(&result);
                continue;
            }
            if (status < 0) rc = -1;
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append WeatherStack finding");
        br_result_clear(&result);
    }
    if (rc) rollback(out, before);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"weatherstack"};
static br_detector weatherstack = {
    .type = 452, .version = 0, .name = "WeatherStack", .custom_name = "",
    .description = "Weatherstack is a weather service that provides real-time weather information. Weatherstack API keys can be used to access weather data from their API.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_weatherstack,
};

int br_weatherstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid WeatherStack detector output");
    *out = NULL;
    if (br_key_pattern_init(&weatherstack, "\\b([0-9a-z]{32})\\b", error) != 0) return -1;
    *out = &weatherstack;
    return 0;
}
