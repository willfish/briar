/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/axonaut/axonaut.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_axonaut(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"userApiKey", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://axonaut.com/api/v2/companies?type=all&sort=id",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 320,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores errors while draining and closing the body. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
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

static int scan_axonaut(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_axonaut, error);
}

static const char *const keywords[] = {"axonaut"};
static br_detector axonaut = {
    .type = 320, .version = 0, .name = "Axonaut", .custom_name = "",
    .description = "Axonaut is a service that provides business management solutions including "
                   "CRM, invoicing, and accounting. Axonaut API keys can be used to access and "
                   "manage business data through their API.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_axonaut,
};

int br_axonaut_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Axonaut detector output");
        return -1;
    }
    *out = NULL;
    if (!axonaut.state && br_key_pattern_init(&axonaut, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &axonaut;
    return 0;
}
