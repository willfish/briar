/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apollo/apollo.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_apollo(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"x-api-key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.apollo.io/api/v1/mixed_people/search",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 293,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores deferred body-drain and close errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies no secrets to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_apollo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_apollo, error);
}

static const char *const keywords[] = {"apollo"};
/* Disabled in the pinned defaults; keep this unversioned scanner directly callable. */
static br_detector apollo = {
    .type = 293, .version = 0, .name = "Apollo", .custom_name = "",
    .description = "Apollo is a sales intelligence platform. "
                   "Apollo API keys can be used to access and modify data within the Apollo platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_apollo,
};

int br_apollo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Apollo detector output");
        return -1;
    }
    *out = NULL;
    if (!apollo.state && br_key_pattern_init(&apollo, "\\b([a-zA-Z0-9]{22})\\b", error) != 0)
        return -1;
    *out = &apollo;
    return 0;
}
