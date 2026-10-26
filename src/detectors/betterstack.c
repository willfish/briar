/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/betterstack/betterstack.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int betterstack_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0 ? 0 : -1;

    /* The capture is exactly 24 ASCII alphanumeric bytes. */
    char authorization[sizeof("Bearer ") + 24];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://uptime.betterstack.com/api/v2/monitors",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 947,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Source ignores its deferred body drain/close errors and content. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int betterstack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    /* TrimSpace cannot change this capture's ASCII alphanumeric alphabet. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", betterstack_verify, error);
    return rc == 0 ? 0 : -1;
}

static const char *const betterstack_keywords[] = {"betterstack"};
static br_detector betterstack_detector = {
    .type = 947, .version = 0, .name = "BetterStack", .custom_name = "",
    .description = "Betterstack is a monitoring service for uptime and performance of websites and APIs. "
                   "Betterstack API keys can be used to access and manage these monitoring services.",
    .keywords = betterstack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = betterstack_scan,
};

int br_betterstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid BetterStack detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&betterstack_detector, "\\b([0-9a-zA-Z]{24})\\b", error) != 0) return -1;
    *out = &betterstack_detector;
    return 0;
}
