/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zenkitapi/zenkitapi.go. */
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int zenkit_set(br_result *result, const char *cause, const char *key)
{
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int zenkit_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx) return zenkit_set(result, "net/http: nil Context", key);
    char api_key[48];
    int n = snprintf(api_key, sizeof(api_key), "%s", key);
    if (n < 0 || (size_t)n >= sizeof(api_key)) return -1;
    const br_header header = {"Zenkit-Api-Key", api_key};
    const br_http_request request = {
        .method = "GET", .url = "https://base.zenkit.com/api/v1/users/me",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[64];
    bool verified = false;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200) verified = true;
    else if (response.status != 401) {
        int wrote = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (wrote < 0 || (size_t)wrote >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            free(transport_error);
            return -1;
        }
        cause = status_error;
    }
    int set = zenkit_set(result, cause, key);
    br_http_release(ctx, &response);
    free(transport_error);
    if (set != 0) return -1;
    result->verified = verified;
    return 0;
}

static int zenkit_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", zenkit_verify, error);
}

static const char *const zenkit_keywords[] = {"zenkit"};
static br_detector zenkit_detector = {
    .type = 720, .version = 0, .name = "ZenkitAPI", .custom_name = "",
    .description = "Zenkit is a collaborative SaaS platform for project management, database building, and more. Zenkit API keys can be used to access and interact with Zenkit's services programmatically.",
    .keywords = zenkit_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = zenkit_scan,
};

int br_zenkitapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid ZenkitAPI detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&zenkit_detector, "\\b([0-9a-z]{8}-[0-9A-Za-z]{32})\\b", error) != 0)
        return -1;
    *out = &zenkit_detector;
    return 0;
}
