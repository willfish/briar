/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/atera/atera.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_atera(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"Accept", "application/json"}, {"X-API-KEY", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.atera.com/api/v3/alerts",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 800,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream ignores body/drain errors and supplies only the key for redaction. */
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_atera(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_atera, error);
}

static const char *const keywords[] = {"atera"};
static br_detector atera = {
    .type = 800, .version = 0, .name = "Atera", .custom_name = "",
    .description = "Atera is an IT management platform that provides remote monitoring and "
                   "management for IT professionals. Atera API keys can be used to interact "
                   "with the Atera API to manage alerts, tickets, devices, and more.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_atera,
};

int br_atera_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Atera detector output");
        return -1;
    }
    *out = NULL;
    if (!atera.state && br_key_pattern_init(&atera, "\\b([0-9a-z]{32})\\b", error) != 0)
        return -1;
    *out = &atera;
    return 0;
}
