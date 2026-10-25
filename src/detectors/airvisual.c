/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/airvisual/airvisual.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_airvisual(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[128], auth[44];
    snprintf(url, sizeof(url), "https://api.airvisual.com/v2/countries?key=%s", key);
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {
        {"Accept", "application/vnd.airvisual+json; version=3"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 498,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores errors while draining and closing the response body. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies no secrets to SetVerificationError. Never log the cause. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_airvisual(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_airvisual, error);
}

static const char *const keywords[] = {"airvisual"};
static br_detector airvisual = {
    .type = 498, .version = 0, .name = "AirVisual", .custom_name = "",
    .description = "AirVisual provides air quality information and monitoring. "
                   "The API key allows access to various air quality data and services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_airvisual,
};

int br_airvisual_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AirVisual detector output");
        return -1;
    }
    *out = NULL;
    if (!airvisual.state && br_key_pattern_init(&airvisual, "\\b([a-z0-9-]{36})\\b", error) != 0)
        return -1;
    *out = &airvisual;
    return 0;
}
