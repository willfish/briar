/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sanity/sanity.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int sanity_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const char *cause = NULL;
    char status_error[64];
    char *send_error = NULL;
    br_http_response response = {0};
    bool sent = false;
    /* NewRequestWithContext(nil) returns this error; the finding is retained. */
    if (!ctx) cause = "net/http: nil Context";
    else if (strlen(key) != 81) return -1;
    else {
        char authorization[7 + 81 + 1];
        memcpy(authorization, "Bearer ", 7);
        memcpy(authorization + 7, key, 82);
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = "https://api.sanity.io/vX/access/permissions/me",
            .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        sent = true;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            cause = send_error;
        } else if (response.status == 200) {
            result->verified = true;
        } else if (response.status != 401 && response.status != 403) {
            int n = snprintf(status_error, sizeof(status_error),
                             "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error)) return -1;
            cause = status_error;
        }
    }
    /* SetVerificationError is called with no secret arguments, so nothing is redacted. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    if (sent) br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int sanity_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", sanity_verify, error);
}

static const char *const sanity_keywords[] = {"sanity"};
static br_detector sanity_detector = {
    .type = 1012, .version = 0, .name = "Sanity", .custom_name = "",
    .description = "Sanity is the modern CMS that transforms content into a competitive advantage. Customize, collaborate, and scale your digital experiences seamlessly.",
    .keywords = sanity_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sanity_scan,
};

int br_sanity_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Sanity detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&sanity_detector, "\\b(sk[A-Za-z0-9]{79})\\b", error) != 0) return -1;
    *out = &sanity_detector;
    return 0;
}
