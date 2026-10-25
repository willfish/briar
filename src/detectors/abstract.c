/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/abstract/abstract.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_abstract(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[sizeof("https://exchange-rates.abstractapi.com/v1/live/?api_key=&base=USD") + 32];
    snprintf(url, sizeof(url),
             "https://exchange-rates.abstractapi.com/v1/live/?api_key=%s&base=USD", key);
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 384,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream ignores the body, including body-read errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
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

static int scan_abstract(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_abstract, error);
}

static const char *const keywords[] = {"abstract"};
static br_detector abstract_detector = {
    .type = 384, .version = 0, .name = "Abstract", .custom_name = "",
    .description = "Abstract API provides various services including exchange rates. "
                   "The API keys can be used to access these services and retrieve data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abstract,
};

int br_abstract_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Abstract detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&abstract_detector, "\\b([0-9a-z]{32})\\b", error) != 0)
        return -1;
    *out = &abstract_detector;
    return 0;
}
