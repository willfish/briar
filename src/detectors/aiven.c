/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aiven/aiven.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_aiven(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[sizeof("aivenv1 ") + 372];
    snprintf(auth, sizeof(auth), "aivenv1 %s", key);
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.aiven.io/v1/project",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 917,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
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
    /* Upstream supplies no secrets to SetVerificationError. Never log the cause. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_aiven(const br_detector *detector, const br_scan_ctx *ctx,
                       bool verify, br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_aiven, error);
}

static const char *const keywords[] = {"aiven"};
static br_detector aiven = {
    .type = 917, .version = 0, .name = "Aiven", .custom_name = "",
    .description = "Aiven is a managed cloud service that provides various open-source data infrastructure services. "
                   "Aiven API keys can be used to access and manage these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_aiven,
};

int br_aiven_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Aiven detector output");
        return -1;
    }
    *out = NULL;
    if (!aiven.state && br_key_pattern_init(&aiven, "([a-zA-Z0-9/+=]{372})", error) != 0)
        return -1;
    *out = &aiven;
    return 0;
}
