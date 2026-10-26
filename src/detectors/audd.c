/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/audd/audd.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_audd(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Captures are exactly 32 URL-safe bytes. This endpoint changes callback
     * configuration; tests must use the injected transport, never the service. */
    char url[192];
    snprintf(url, sizeof(url),
             "https://api.audd.io/setCallbackUrl/?api_token=%s&url=https://yourwebsite.com/callbacks_handler/", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 376,
    };
    br_http_response response = {0};
    char *error = NULL;
    if (br_http_send(ctx, &request, &response, &error) == 0 && !response.body_error) {
        /* ReadAll and the literal substring check precede status classification.
         * Neither JSON syntax nor whitespace normalization is involved. */
        static const unsigned char success[] = "\"status\":\"success\"";
        bool valid = br_slice_find(response.body, (br_slice){success, sizeof(success) - 1}, 0) != SIZE_MAX;
        if (response.status >= 200 && response.status < 300) result->verified = valid;
    }
    /* Upstream suppresses every verification error and never calls its error
     * setter. Release even on failed sends/reads instead of reproducing leaks. */
    br_http_release(ctx, &response);
    free(error);
    return 0;
}

static int scan_audd(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_audd, error);
}

static const char *const keywords[] = {"audd"};
static br_detector audd = {
    .type = 376, .version = 0, .name = "Audd", .custom_name = "",
    .description = "Audd is a music recognition service. Audd API tokens can be used to access the Audd API services for recognizing music and obtaining metadata.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_audd,
};

int br_audd_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Audd detector output");
        return -1;
    }
    *out = NULL;
    if (!audd.state && br_key_pattern_init(&audd, "\\b([a-z0-9-]{32})\\b", error) != 0) return -1;
    *out = &audd;
    return 0;
}
