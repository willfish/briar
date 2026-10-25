/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apimetrics/apimetrics.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_apimetrics(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Captures are exactly 32 ASCII alphanumeric bytes, with case preserved. */
    char auth[sizeof("Bearer ") + 32];
    snprintf(auth, sizeof(auth), "Bearer %s", key);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://client.apimetrics.io/api/2/calls/",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 1004,
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

static int scan_apimetrics(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_apimetrics, error);
}

static const char *const keywords[] = {"apimetrics"};
static br_detector apimetrics = {
    .type = 1004, .version = 0, .name = "ApiMetrics", .custom_name = "",
    .description = "ApiMetrics is a tool for monitoring the performance of APIs. ApiMetrics keys can be used to access and manage API monitors.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_apimetrics,
};

int br_apimetrics_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid ApiMetrics detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&apimetrics, "\\b([a-zA-Z0-9]{32})\\b", error) != 0) return -1;
    *out = &apimetrics;
    return 0;
}
