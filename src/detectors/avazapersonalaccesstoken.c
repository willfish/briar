/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/avazapersonalaccesstoken. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_avaza(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    size_t len = strlen(key);
    if (len > SIZE_MAX - sizeof("Bearer ")) return -1;
    char *authorization = malloc(len + sizeof("Bearer "));
    if (!authorization) return -1;
    memcpy(authorization, "Bearer ", sizeof("Bearer ") - 1);
    memcpy(authorization + sizeof("Bearer ") - 1, key, len + 1);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.avaza.com/api/Account",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 733,
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
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    free(authorization);
    return rc;
}

static int scan_avaza(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_avaza, error);
}

static const char *const keywords[] = {"avaza"};
static br_detector avaza = {
    .type = 733, .version = 0, .name = "AvazaPersonalAccessToken", .custom_name = "",
    .description = "Avaza is a business management tool that offers project management, time tracking, and financial management. "
                   "Avaza Personal Access Tokens can be used to access and interact with Avaza's API.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_avaza,
};

int br_avazapersonalaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AvazaPersonalAccessToken detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&avaza, "\\b([0-9]+-[0-9a-f]{40})\\b", error) != 0) return -1;
    *out = &avaza;
    return 0;
}
