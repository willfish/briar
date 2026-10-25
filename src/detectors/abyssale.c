/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/abyssale/abyssale.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_abyssale(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"x-api-key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.abyssale.com/ready",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 239,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream inspects only status, ignoring body contents and read errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 403: break;
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
    free(error);
    return rc;
}

static int scan_abyssale(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_abyssale, error);
}

static const char *const abyssale_keywords[] = {"abyssale"};

static br_detector abyssale_detector = {
    .type = 239, .version = 0, .name = "Abyssale", .custom_name = "",
    .description = "Abyssale is a service offering various API functionalities for marketing "
                   "automation and services such as images and ad campaigns. Abyssale API "
                   "keys can be used to access and interact with this data.",
    .keywords = abyssale_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abyssale,
};

int br_abyssale_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Abyssale detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&abyssale_detector, "\\b([a-z0-9A-Z]{40})\\b", error) != 0)
        return -1;
    *out = &abyssale_detector;
    return 0;
}
