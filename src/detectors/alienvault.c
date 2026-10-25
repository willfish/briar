/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/alienvault/alienvault.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_alienvault(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"X-OTX-API-KEY", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://otx.alienvault.com/api/v1/users/me",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 399,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores errors from its deferred body drain and close. */
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
    /* Upstream supplies no secrets to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_alienvault(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_alienvault, error);
}

static const char *const keywords[] = {"alienvault"};
static br_detector alienvault = {
    .type = 399, .version = 0, .name = "AlienVault", .custom_name = "",
    .description = "AlienVault is a threat intelligence platform providing real-time data on emerging threats. AlienVault API keys can be used to access threat data and other services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_alienvault,
};

int br_alienvault_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AlienVault detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&alienvault, "\\b([a-z0-9]{64})\\b", error) != 0) return -1;
    *out = &alienvault;
    return 0;
}
