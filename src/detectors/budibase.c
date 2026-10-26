/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/budibase/budibase.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int budibase_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) == 0 ? 0 : -1;

    static const unsigned char payload[] = "{\"name\":\"qwerty\"}";
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"x-budibase-api-key", key},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://budibase.app/api/public/v1/applications/search",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 953,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Source ignores content and every deferred body drain/close error. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Source supplies zero secrets: preserve errors containing keys verbatim. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int budibase_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    /* The capture excludes whitespace, making source TrimSpace a no-op. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", budibase_verify, error);
    if (rc != 0 && out)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const budibase_keywords[] = {"budibase"};
static br_detector budibase_detector = {
    .type = 953, .version = 0, .name = "Budibase", .custom_name = "",
    .description = "Budibase is a low-code platform for creating internal tools. "
                   "Budibase API keys can be used to access and modify applications and data within the platform.",
    .keywords = budibase_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = budibase_scan,
};

int br_budibase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Budibase detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&budibase_detector, "\\b([a-f0-9]{32}-[a-f0-9]{78,80})\\b", error) != 0) return -1;
    *out = &budibase_detector;
    return 0;
}
