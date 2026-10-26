/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/aviationstack/aviationstack.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_aviationstack(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[128];
    snprintf(url, sizeof(url), "https://api.aviationstack.com/v1/flights?access_key=%s", key);
    const br_http_request request = {
        .method = "GET", .url = url,
        /* Upstream mutates its shared client; keep the timeout request-local. */
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = 564,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores all errors from draining and closing the body. */
        switch (response.status) {
        case 200: result->verified = true; break;
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

static int scan_aviationstack(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_aviationstack, error);
}

static const char *const keywords[] = {"aviationstack"};
static br_detector aviationstack = {
    .type = 564, .version = 0, .name = "AviationStack", .custom_name = "",
    .description = "AviationStack is a service providing real-time flight status and aviation data. "
                   "The API key can be used to access this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_aviationstack,
};

int br_aviationstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AviationStack detector output");
        return -1;
    }
    *out = NULL;
    if (!aviationstack.state &&
        br_key_pattern_init(&aviationstack, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &aviationstack;
    return 0;
}
