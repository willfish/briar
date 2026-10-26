/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/beebole/beebole.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_beebole(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    /* Source retains request-creation errors, unlike detectors that skip them. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0 ? -1 : 0;
    char *authorization = NULL, *error = NULL;
    static const unsigned char password[] = "x";
    if (br_http_basic_auth((br_slice){(const unsigned char *)key, strlen(key)},
                           (br_slice){password, 1}, &authorization, &error) != 0) {
        free(error); free(authorization);
        return -1;
    }
    static const unsigned char payload[] = "{\"service\": \"custom_field.list\"}";
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "POST", .url = "https://beebole-apps.com/api/v2", .headers = headers, .nheaders = 2,
        .body = {payload, sizeof(payload) - 1}, .profile = BR_HTTP_SANE, .detector_type = 684,
    };
    br_http_response response = {0};
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error ? error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* Body/drain errors never affect the status decision. No DNS suppression,
     * alternate profile, redirect fallback, or manually added Content-Length. */
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error); free(authorization);
    return rc != 0 ? -1 : 0; /* Core allocation failures may be positive. */
}

static int scan_beebole(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_beebole, error);
}

static const char *const keywords[] = {"beebole"};
static br_detector beebole = {
    .type = 684, .version = 0, .name = "Beebole", .custom_name = "",
    .description = "Beebole is a time tracking and business management tool. Beebole API keys can be used to access and manage time tracking data and other business-related information.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_beebole,
};

int br_beebole_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Beebole detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&beebole, "\\b([0-9a-z]{40})\\b", error) != 0) return -1;
    *out = &beebole;
    return 0;
}
