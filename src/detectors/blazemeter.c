/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/blazemeter/blazemeter.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int blazemeter_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) == 0 ? 0 : -1;

    /* Every capture is exactly 36 ASCII bytes. */
    char authorization[sizeof("Bearer ") + 36];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.runscope.com/account",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 603,
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
        case 401: case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies NO secrets to SetVerificationError. Preserve its
     * unredacted causes, including any captured key appearing in them. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int blazemeter_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    /* TrimSpace cannot change the lowercase ASCII alphanumeric/hyphen capture. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", blazemeter_verify, error);
    return rc == 0 ? 0 : -1;
}

static const char *const blazemeter_keywords[] = {"blazemeter", "runscope"};
static br_detector blazemeter_detector = {
    .type = 603, .version = 0, .name = "Blazemeter", .custom_name = "",
    .description = "Blazemeter is a continuous testing platform for DevOps. "
                   "The keys can be used to access and manage performance tests and other resources.",
    .keywords = blazemeter_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = blazemeter_scan,
};

int br_blazemeter_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Blazemeter detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&blazemeter_detector,
            "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", error) != 0)
        return -1;
    *out = &blazemeter_detector;
    return 0;
}
