/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/alconost/alconost.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_alconost(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char *auth = NULL;
    /* Upstream encodes key + ":", with an empty password. */
    if (br_http_basic_auth((br_slice){(const unsigned char *)key, strlen(key)},
                           (br_slice){0}, &auth, NULL) != 0)
        return -1;
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://nitro.alconost.com/api/v1/account",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 301,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        /* Upstream drains and closes the body but ignores both errors. */
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
    /* Upstream passes no secrets to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return rc;
}

static int scan_alconost(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_alconost, error);
}

static const char *const keywords[] = {"alconost"};
static br_detector alconost = {
    .type = 301, .version = 0, .name = "Alconost", .custom_name = "",
    .description = "Alconost is a translation and localization service. Alconost API keys can "
                   "be used to access and modify translation data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_alconost,
};

int br_alconost_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Alconost detector output");
        return -1;
    }
    *out = NULL;
    /* The capture permits uppercase A only; prefix case folding stays scoped. */
    if (!alconost.state &&
        br_key_pattern_init(&alconost, "\\b([0-9Aa-z]{32})\\b", error) != 0)
        return -1;
    *out = &alconost;
    return 0;
}
