/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/appfollow/appfollow.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_appfollow(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"X-AppFollow-API-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.appfollow.io/api/v2/account/users",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 588,
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
        case 200:
        case 402:
        case 422: result->verified = true; break;
        case 401: break;
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

static int scan_appfollow(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    /* TrimSpace is a no-op for this capture alphabet. Keep occurrence order and
     * duplicates: upstream does not use a unique-key map or validate JWT data. */
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_appfollow, error);
}

static const char *const keywords[] = {"appfollow"};
static br_detector appfollow = {
    .type = 588, .version = 0, .name = "Appfollow", .custom_name = "",
    .description = "Appfollow is a service used for app monitoring and analytics. Appfollow API tokens can be used to access and manage app data and analytics.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_appfollow,
};

int br_appfollow_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Appfollow detector output");
        return -1;
    }
    *out = NULL;
    /* Preserve the pinned signature class, including literal '-' and '_'. */
    if (br_key_pattern_init(&appfollow,
            "\\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9\\.[0-9A-Za-z]{74}\\.[0-9A-Z-a-z\\-_]{43})\\b",
            error) != 0)
        return -1;
    *out = &appfollow;
    return 0;
}
