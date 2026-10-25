/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apify/apify.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_apify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[160];
    snprintf(url, sizeof(url),
             "https://api.apify.com/v2/acts?token=%s&my=true&offset=10&limit=99&desc=true", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 391,
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

static int scan_apify(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_apify, error);
}

static const char *const keywords[] = {"apify"};
static br_detector apify = {
    .type = 391, .version = 0, .name = "Apify", .custom_name = "",
    .description = "Apify is a platform for web scraping and automation. Apify API keys can be "
                   "used to access and control Apify actors and tasks.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_apify,
};

int br_apify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Apify detector output");
        return -1;
    }
    *out = NULL;
    if (!apify.state) {
        br_regex *regex = NULL;
        /* Source [a-zA-Z-0-9] includes a literal hyphen; keep it explicit here.
         * "apify" is a dispatch keyword, not a PrefixRegex extraction prefix. */
        if (br_regex_compile("\\b(apify_api_[a-zA-Z0-9-]{36})\\b", &regex, error) != 0)
            return -1;
        apify.state = regex;
    }
    *out = &apify;
    return 0;
}
