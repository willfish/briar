/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apimatic/apimatic.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_apimatic(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[sizeof("X-Auth-Key ") + 64];
    snprintf(authorization, sizeof(authorization), "X-Auth-Key %s", key);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.apimatic.io/code-generations",
        .headers = headers, .nheaders = 1,
        /* Upstream mutates its shared client; keep the 10-second timeout request-local. */
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = 637,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream drains and closes the body but ignores both errors. */
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
    free(transport_error);
    return rc;
}

static int scan_apimatic(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_apimatic, error);
}

static const char *const keywords[] = {"apimatic"};
/* apikey is an extraction prefix, but not an engine dispatch keyword. */
static const char *const extraction_prefixes[] = {"apimatic", "apikey"};
static br_detector apimatic = {
    .type = 637, .version = 0, .name = "APIMatic", .custom_name = "",
    .description = "APIMatic provides tools for generating SDKs, API documentation, and code "
                   "snippets. APIMatic credentials can be used to access and manage these "
                   "tools and services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_apimatic,
};

int br_apimatic_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid APIMatic detector output");
        return -1;
    }
    *out = NULL;
    if (!apimatic.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(extraction_prefixes, 2, "\\b([a-zA-Z0-9_-]{64})\\b", &regex, error) != 0)
            return -1;
        apimatic.state = regex;
    }
    *out = &apimatic;
    return 0;
}
