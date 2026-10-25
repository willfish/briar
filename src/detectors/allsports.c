/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/allsports/allsports.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_allsports(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[160];
    snprintf(url, sizeof(url),
             "https://apiv2.allsportsapi.com/football/?met=Countries&APIkey=%s", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 473,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            if (response.body_error) {
                cause = response.body_error;
            } else {
                static const unsigned char wrong_login[] = "Wrong login credentials";
                const br_slice needle = {wrong_login, sizeof(wrong_login) - 1};
                bool rejected = br_slice_find(response.body, needle, 0) != SIZE_MAX;
                result->verified = !rejected;
            }
            break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Only 200 reads the body; errors from the deferred drain are ignored.
     * Upstream supplies no secrets to SetVerificationError. Never log the cause. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_allsports(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_allsports, error);
}

static const char *const keywords[] = {"allsports"};
static br_detector allsports = {
    .type = 473, .version = 0, .name = "Allsports", .custom_name = "",
    .description = "Allsports API keys can be used to access and interact with the Allsports API, "
                   "allowing retrieval of sports data and other related operations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_allsports,
};

int br_allsports_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Allsports detector output");
        return -1;
    }
    *out = NULL;
    if (!allsports.state && br_key_pattern_init(&allsports, "\\b([0-9a-z]{64})\\b", error) != 0)
        return -1;
    *out = &allsports;
    return 0;
}
