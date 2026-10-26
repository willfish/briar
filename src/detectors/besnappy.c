/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/besnappy/besnappy.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_besnappy(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    /* The fixed method/URL and NoBody leave nil context as the reachable
     * constructor error. Retain it, rather than skipping the candidate. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1);
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)key, strlen(key)},
                           (br_slice){(const unsigned char *)"x", 1}, &authorization, NULL) != 0) {
        free(authorization);
        return -1;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.besnappy.com/api/v1/accounts",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 867,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    /* Besnappy retains every Client.Do error, including DNS and cancellation;
     * there is no host cache or transport-error suppression policy. */
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Source ignores body/drain/close errors. The shared key scanner treats
     * every nonzero setter result, including +1, as a resource failure. */
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    free(authorization);
    return rc;
}

static int scan_besnappy(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_besnappy, error);
}

static const char *const keywords[] = {"besnappy"};
static br_detector besnappy = {
    .type = 867, .version = 0, .name = "Besnappy", .custom_name = "",
    .description = "Besnappy is a customer service platform. The detected key can be used to "
                   "access Besnappy's API, potentially exposing sensitive customer service data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_besnappy,
};

int br_besnappy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Besnappy detector output");
        return -1;
    }
    *out = NULL;
    if (!besnappy.state && br_key_pattern_init(&besnappy, "\\b([a-f0-9]{64})\\b", error) != 0)
        return -1;
    *out = &besnappy;
    return 0;
}
