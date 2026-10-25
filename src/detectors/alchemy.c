/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/alchemy/alchemy.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_alchemy(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[144];
    snprintf(url, sizeof(url),
             "https://eth-mainnet.g.alchemy.com/v2/%s/getNFTs/?owner=vitalik.eth", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 907,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream checks only status and ignores body-drain errors. */
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
    free(error);
    return rc;
}

static int scan_alchemy(const br_detector *detector, const br_scan_ctx *ctx,
                         bool verify, br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_alchemy, error);
}

static const char *const keywords[] = {"alchemy", "alcht_"};
/* The second dispatch keyword is deliberately NOT an extraction prefix. */
static const char *const extraction_prefixes[] = {"alchemy"};
static br_detector alchemy = {
    .type = 907, .version = 0, .name = "Alchemy", .custom_name = "",
    .description = "Alchemy is a blockchain development platform that provides a suite of tools "
                   "and services for building and scaling decentralized applications. "
                   "Alchemy API keys can be used to access these services.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_alchemy,
};

int br_alchemy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Alchemy detector output");
    *out = NULL;
    if (!alchemy.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(extraction_prefixes, 1,
                                      "\\b([0-9a-zA-Z_]{32}|alcht_[0-9a-zA-Z]{30})\\b",
                                      &regex, error) != 0)
            return -1;
        alchemy.state = regex;
    }
    *out = &alchemy;
    return 0;
}
