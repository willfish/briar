/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apilayer/apilayer.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_apilayer(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"apikey", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.apilayer.com/number_verification/countries",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 788,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores deferred body-drain and close errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies no secrets to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_apilayer(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_apilayer, error);
}

static const char *const keywords[] = {"apilayer"};
static br_detector apilayer = {
    .type = 788, .version = 0, .name = "Apilayer", .custom_name = "",
    .description = "Apilayer is a service providing various APIs for data verification and other utilities. "
                   "Apilayer API keys can be used to access these services and perform operations such as number verification.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_apilayer,
};

int br_apilayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Apilayer detector output");
        return -1;
    }
    *out = NULL;
    if (!apilayer.state && br_key_pattern_init(&apilayer, "\\b([a-zA-Z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &apilayer;
    return 0;
}
