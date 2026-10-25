/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/adafruitio/adafruitio.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_adafruitio(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[128];
    snprintf(url, sizeof(url),
             "https://io.adafruit.com/api/v2/ladybugtest/feeds/?x-aio-key=%s", key);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 390,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream only inspects status, ignoring the body and body-read errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    br_slice secret = {result->raw.data, result->raw.len};
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_adafruitio(const br_detector *detector, const br_scan_ctx *ctx,
                           bool verify, br_slice input, br_results *out, char **error)
{
    /* The capture alphabet excludes whitespace, so upstream TrimSpace is a no-op. */
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_adafruitio, error);
}

static const char *const keywords[] = {"aio_"};
static br_detector adafruitio = {
    .type = 390, .version = 0, .name = "AdafruitIO", .custom_name = "",
    .description = "Adafruit IO is a cloud service used for IoT applications. Adafruit IO keys "
                   "can be used to access and control data and devices connected to the platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_adafruitio,
};

int br_adafruitio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid AdafruitIO detector output");
        return -1;
    }
    *out = NULL;
    if (!adafruitio.state) {
        br_regex *regex = NULL;
        /* aio_ belongs to the key itself, not a separate provider prefix. */
        if (br_regex_compile("\\b(aio\\_[a-zA-Z0-9]{28})\\b", &regex, error) != 0)
            return -1;
        adafruitio.state = regex;
    }
    *out = &adafruitio;
    return 0;
}
