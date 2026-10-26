/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/beamer/beamer.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int beamer_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx) {
        /* NewRequestWithContext rejects nil before any HTTP operation. Source
         * retains this candidate and its creation error, rather than skipping. */
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0 ? 0 : -1;
    }
    const br_header headers[] = {{"Beamer-Api-Key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.getbeamer.com/v0/url",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 166,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Body contents and errors from source's deferred drain/close are
         * ignored. Only 200 verifies, not the entire 2xx range. */
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

static int beamer_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    /* The capture alphabet excludes whitespace, so TrimSpace is a no-op. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", beamer_verify, error);
    return rc == 0 ? 0 : -1;
}

static const char *const beamer_keywords[] = {"beamer"};
static br_detector beamer_detector = {
    .type = 166, .version = 0, .name = "Beamer", .custom_name = "",
    .description = "Beamer is a user engagement platform that helps you communicate product updates and other important "
                   "information to your users. Beamer API keys can be used to access and manage this information.",
    .keywords = beamer_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = beamer_scan,
};

int br_beamer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Beamer detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&beamer_detector, "\\b([a-zA-Z0-9_+/]{45}=)", error) != 0) return -1;
    *out = &beamer_detector;
    return 0;
}
