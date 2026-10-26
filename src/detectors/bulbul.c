/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bulbul/bulbul.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bulbul_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) == 0 ? 0 : -1;

    static const char prefix[] = "https://prod-api.bulbul.io/view_all_users?api_key=";
    char url[sizeof(prefix) + 32]; /* Exactly 32 captured, unreserved ASCII bytes. */
    snprintf(url, sizeof(url), "%s%s", prefix, key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 317,
    };
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
                /* The comma is part of the source's case-sensitive substring.
                 * Search bytes, not JSON or a NUL-terminated body string. */
                static const unsigned char marker[] = "\"message\":\"Successful\",";
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
    /* No secret arguments upstream: query-key echoes remain unredacted. Only
     * 200 consumes read errors; deferred body drain/close errors are ignored. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int bulbul_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    /* ASCII alphanumeric captures make source TrimSpace a no-op. */
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", bulbul_verify, error);
    if (rc != 0 && out)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const bulbul_keywords[] = {"bulbul"};
static br_detector bulbul_detector = {
    .type = 317, .version = 0, .name = "Bulbul", .custom_name = "",
    .description = "Bulbul is an API service. Bulbul API keys can be used to access and modify data within the service.",
    .keywords = bulbul_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = bulbul_scan,
};

int br_bulbul_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Bulbul detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&bulbul_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &bulbul_detector;
    return 0;
}
