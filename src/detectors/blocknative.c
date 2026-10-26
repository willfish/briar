/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/blocknative. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int set_cause(br_result *result, const char *cause)
{
    /* Source supplies NO secret arguments: token-bearing causes deliberately
     * remain unredacted. Never log them. Every nonzero core return is fatal. */
    return br_result_set_verification_error(result, cause, NULL, 0) ? -1 : 0;
}

static int verify_blocknative(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    const br_header headers[] = {{"Authorization", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.blocknative.com/gasprices/blockprices",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 908,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Source is disabled because the API also returns 200 for invalid
         * keys. Preserve that status-only rule; do not inspect/fix the body. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: case 429: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = set_cause(result, cause);
    /* Source ignores every body/drain/close error. ABI1 releases eagerly after
     * each send; native Go streaming/drain timing parity remains unestablished. */
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_blocknative(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_blocknative, error);
}

static const char *const keywords[] = {"blocknative"};
static br_detector blocknative = {
    .type = 908, .version = 0, .name = "BlockNative", .custom_name = "",
    .description = "Blocknative is a platform that provides real-time blockchain transaction "
                   "monitoring and notification services. Blocknative API keys can be used to "
                   "access and interact with these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_blocknative,
};

int br_blocknative_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BlockNative detector output");
        return -1;
    }
    *out = NULL;
    /* Uppercase A is accepted ONLY in the first block; this is not a generic
     * case-insensitive UUID. PrefixRegex alone supplies keyword case folding. */
    if (!blocknative.state && br_key_pattern_init(&blocknative,
        "\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", error) != 0)
        return -1;
    *out = &blocknative;
    return 0;
}
