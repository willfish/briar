/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bitbar/bitbar.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bitbar_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0 ? 0 : -1;

    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)key, strlen(key)},
                           (br_slice){0}, &authorization, NULL) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://cloud.bitbar.com/api/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 387,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Source ignores content and deferred body drain/close errors. */
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
    free(authorization);
    return rc == 0 ? 0 : -1;
}

static int bitbar_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    /* The captured ASCII alphanumeric alphabet makes TrimSpace a no-op. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", bitbar_verify, error);
    return rc == 0 ? 0 : -1;
}

static const char *const bitbar_keywords[] = {"bitbar"};
static br_detector bitbar_detector = {
    .type = 387, .version = 0, .name = "Bitbar", .custom_name = "",
    .description = "Bitbar provides a cloud-based mobile app testing platform. "
                   "Bitbar API keys can be used to access and manage testing resources and data.",
    .keywords = bitbar_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = bitbar_scan,
};

int br_bitbar_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Bitbar detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&bitbar_detector, "\\b([0-9a-zA-Z]{32})\\b", error) != 0) return -1;
    *out = &bitbar_detector;
    return 0;
}
