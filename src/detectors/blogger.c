/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/blogger/blogger.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int blogger_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) == 0 ? 0 : -1;

    static const char prefix[] = "https://www.googleapis.com/blogger/v3/blogs/2399953?key=";
    /* Captures are exactly 39 unreserved ASCII bytes, appended literally. */
    char url[sizeof(prefix) + 39];
    snprintf(url, sizeof(url), "%s%s", prefix, key);
    const br_http_request request = {
        .method = "GET", .url = url,
        .profile = BR_HTTP_SANE, .detector_type = 302,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Body contents and deferred drain/close errors do not affect status. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 400: case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Source supplies zero secret arguments: errors containing the key remain
     * unredacted, including the query key in a transport cause. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int blogger_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    /* TrimSpace cannot change this capture's ASCII alphabet. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", blogger_verify, error);
    return rc == 0 ? 0 : -1;
}

static const char *const blogger_keywords[] = {"blogger"};
static br_detector blogger_detector = {
    .type = 302, .version = 0, .name = "Blogger", .custom_name = "",
    .description = "Blogger API keys can be used to access and manage blogs on the Blogger platform.",
    .keywords = blogger_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = blogger_scan,
};

int br_blogger_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Blogger detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&blogger_detector, "\\b(AIzaSy[0-9A-Za-z_-]{33})", error) != 0) return -1;
    *out = &blogger_detector;
    return 0;
}
