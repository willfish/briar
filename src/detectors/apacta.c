/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apacta/apacta.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_apacta(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* The capture bounds key to 36 URL-unreserved ASCII bytes. */
    char url[128];
    snprintf(url, sizeof(url), "https://app.apacta.com/api/v1/time_entries?api_key=%s", key);
    const br_http_request request = {
        .method = "GET", .url = url,
        .profile = BR_HTTP_SANE, .detector_type = 632,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores errors from its deferred body drain and close. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies no secrets, even when the transport error includes the URL key. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_apacta(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_apacta, error);
}

static const char *const keywords[] = {"apacta"};
static br_detector apacta = {
    .type = 632, .version = 0, .name = "Apacta", .custom_name = "",
    .description = "Apacta is a project management tool designed for the construction industry. Apacta API keys can be used to access and manage project data within the Apacta platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_apacta,
};

int br_apacta_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Apacta detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&apacta, "\\b([a-z0-9-]{36})\\b", error) != 0) return -1;
    *out = &apacta;
    return 0;
}
