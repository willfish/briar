/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bitlyaccesstoken. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_bitly(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    /* Fixed method/URL and ASCII capture: nil context is the reachable request
     * constructor error, and the source retains it as a candidate error. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0);
    char authorization[sizeof("Bearer ") + 40];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", token);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api-ssl.bitly.com/v4/user",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 43,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Source supplies NO secrets to SetVerificationError: token-bearing causes
     * intentionally remain unredacted. Never log them. The shared scanner
     * treats every nonzero setter return, including +1, as a resource failure. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_bitly(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_bitly, error);
}

static const char *const keywords[] = {"bitly"};
static br_detector bitly = {
    .type = 43, .version = 0, .name = "BitLyAccessToken", .custom_name = "",
    .description = "Bitly is a URL shortening service. Bitly access tokens can be used to interact "
                   "with the Bitly API, allowing users to create, manage, and track shortened URLs.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_bitly,
};

int br_bitlyaccesstoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BitLyAccessToken detector output");
        return -1;
    }
    *out = NULL;
    /* Source [a-zA-Z-0-9] includes a literal hyphen. Move it to the end of
     * the equivalent class, without changing either ASCII word boundary. */
    if (!bitly.state && br_key_pattern_init(&bitly, "\\b([a-zA-Z0-9-]{40})\\b", error) != 0)
        return -1;
    *out = &bitly;
    return 0;
}
