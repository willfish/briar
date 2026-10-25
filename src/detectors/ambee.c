/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ambee/ambee.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_ambee(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"x-api-key", key},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.ambeedata.com/latest/by-lat-lng?lat=12&lng=77",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 457,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream drains and closes the body but ignores both errors. */
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
    /* Upstream passes no secrets to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_ambee(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_ambee, error);
}

static const char *const keywords[] = {"ambee"};
static br_detector ambee = {
    .type = 457, .version = 0, .name = "Ambee", .custom_name = "",
    .description = "Ambee provides environmental and climate data APIs. Ambee API keys can "
                   "be used to access this data for various applications such as weather "
                   "forecasting, air quality monitoring, and more.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_ambee,
};

int br_ambee_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Ambee detector output");
        return -1;
    }
    *out = NULL;
    if (!ambee.state && br_key_pattern_init(&ambee, "\\b([0-9a-f]{64})\\b", error) != 0)
        return -1;
    *out = &ambee;
    return 0;
}
