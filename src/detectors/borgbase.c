/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/borgbase/borgbase.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int borgbase_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) == 0 ? 0 : -1;

    char authorization[sizeof("Bearer ") + 152];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", authorization},
    };
    static const unsigned char payload[] = "{\"query\":\"{ sshList {id, name}}\"}";
    const br_http_request request = {
        .method = "POST", .url = "https://api.borgbase.com/graphql",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = 723,
    };
    /* Source mutates its shared client's Timeout. The request-local override
     * preserves 10 seconds, not that shared mutation or its concurrency effects. */
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200:
            if (response.body_error) cause = response.body_error;
            else {
                static const unsigned char marker[] = "\"sshList\":[]";
                result->verified = br_slice_find(response.body,
                    (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            }
            break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream passes zero secret arguments, so transport/read errors remain
     * unredacted even when they include the captured key. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int borgbase_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    /* The capture alphabet excludes whitespace: TrimSpace changes nothing. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", borgbase_verify, error);
    return rc == 0 ? 0 : -1;
}

static const char *const borgbase_keywords[] = {"borgbase"};
static br_detector borgbase_detector = {
    .type = 723, .version = 0, .name = "Borgbase", .custom_name = "",
    .description = "Borgbase is a service for hosting Borg repositories. "
                   "Borgbase API keys can be used to manage and access these repositories.",
    .keywords = borgbase_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = borgbase_scan,
};

int br_borgbase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Borgbase detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&borgbase_detector, "\\b([a-zA-Z0-9/_.-]{148,152})\\b", error) != 0) return -1;
    *out = &borgbase_detector;
    return 0;
}
