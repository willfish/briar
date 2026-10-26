/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/appsynergy/appsynergy.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_appsynergy(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    static const unsigned char payload[] =
        "{\"html\":\"<html><body><h1>Hello World</h1></body></html>\",\"filename\":\"HelloWorld.pdf\"}";
    char url[160];
    snprintf(url, sizeof(url), "https://www.appsynergy.com/api?action=HTML2PDF&apiKey=%s", key);
    const br_http_request request = {
        .method = "POST", .url = url,
        .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 646,
    };
    /* Upstream sends this JSON text without a Content-Type header. */
    br_http_response response = {0};
    char *error = NULL;
    char status_error[96];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        case 400: {
            static const unsigned char invalid_key[] = "Invalid API Key";
            if (response.body_error) cause = response.body_error;
            else if (br_slice_find(response.body, (br_slice){invalid_key, sizeof(invalid_key) - 1}, 0) == SIZE_MAX) {
                snprintf(status_error, sizeof(status_error),
                         "status bad request invalid api key message not found: %d", response.status);
                cause = status_error;
            }
            break;
        }
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Only the explicit 400 body read matters; deferred drain errors are ignored. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_appsynergy(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    /* The capture excludes whitespace, so upstream TrimSpace changes nothing. */
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_appsynergy, error);
}

static const char *const keywords[] = {"appsynergy"};
static br_detector appsynergy = {
    .type = 646, .version = 0, .name = "AppSynergy", .custom_name = "",
    .description = "AppSynergy is a platform for building cloud applications. "
                   "AppSynergy API keys can be used to access and manage applications and data within the platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_appsynergy,
};

int br_appsynergy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AppSynergy detector output");
        return -1;
    }
    *out = NULL;
    if (!appsynergy.state && br_key_pattern_init(&appsynergy, "\\b([a-z0-9]{64})\\b", error) != 0)
        return -1;
    *out = &appsynergy;
    return 0;
}
