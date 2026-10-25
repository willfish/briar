/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apiflash/apiflash.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_apiflash(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[sizeof("https://api.apiflash.com/v1/urltoimage?url=http://google.com&access_key=&wait_until=page_loaded") + 32];
    /* Keep the nested URL raw: upstream does not query-escape urlToCapture. */
    snprintf(url, sizeof(url),
             "https://api.apiflash.com/v1/urltoimage?url=http://google.com&access_key=%s&wait_until=page_loaded", key);
    const br_http_request request = {
        .method = "GET", .url = url,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 401,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = 0;
    /* Source quirk: client.Do errors return (false, nil), not a verification error. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        /* Upstream drains the response but ignores its contents and read errors. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default: {
            char message[80];
            snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
            br_slice secret = {result->raw.data, result->raw.len};
            rc = br_result_set_verification_error(result, message, &secret, 1);
            break;
        }
        }
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_apiflash(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    /* TrimSpace cannot change the captured lowercase alphanumeric key. */
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_apiflash, error);
}

static const char *const keywords[] = {"apiflash"};
static br_detector apiflash = {
    .type = 401, .version = 0, .name = "Apiflash", .custom_name = "",
    .description = "Apiflash is a screenshot API service. Apiflash keys can be used to access "
                   "and utilize the screenshot API service.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_apiflash,
};

int br_apiflash_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Apiflash detector output");
        return -1;
    }
    *out = NULL;
    if (!apiflash.state && br_key_pattern_init(&apiflash, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &apiflash;
    return 0;
}
