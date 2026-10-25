/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aletheiaapi/aletheiaapi.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_aletheiaapi(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"Key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.aletheiaapi.com/StockData?symbol=msft&summary=true",
        .headers = headers, .nheaders = 1,
        /* Upstream changes its client timeout; keep this request-local instead. */
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = 522,
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

static int scan_aletheiaapi(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_aletheiaapi, error);
}

static const char *const keywords[] = {"aletheiaapi"};
static br_detector aletheiaapi = {
    .type = 522, .version = 0, .name = "AletheiaApi", .custom_name = "",
    .description = "AletheiaApi is a service providing financial data. "
                   "AletheiaApi keys can be used to access this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_aletheiaapi,
};

int br_aletheiaapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AletheiaApi detector output");
        return -1;
    }
    *out = NULL;
    if (!aletheiaapi.state && br_key_pattern_init(&aletheiaapi, "\\b([A-Z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &aletheiaapi;
    return 0;
}
