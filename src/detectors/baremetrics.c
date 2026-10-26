/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/baremetrics/baremetrics.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_baremetrics(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    /* Fixed method/URL and NoBody: nil context is the reachable constructor
     * failure. Source retains it, unlike every later Client.Do error. */
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1);
    char authorization[36]; /* "Bearer " + at most 28 captured ASCII bytes + NUL. */
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.baremetrics.com/v1/account",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 377,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    /* Baremetrics deliberately discards ALL Client.Do errors, including context,
     * DNS and unsupported transport errors. Keep the candidate; do not cache. */
    if (br_http_send(ctx, &request, &response, &error) == 0) {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Draining and closing cannot change the status-only result. The shared
     * key scanner treats every nonzero setter return, including +1, as fatal. */
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_baremetrics(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    return br_scan_key(detector, ctx, verify, input, out, "key", verify_baremetrics, error);
}

static const char *const keywords[] = {"baremetrics"};
static br_detector baremetrics = {
    .type = 377, .version = 0, .name = "Baremetrics", .custom_name = "",
    .description = "Baremetrics is a subscription analytics and insights tool. Baremetrics "
                   "API keys can be used to access and analyze subscription data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_baremetrics,
};

int br_baremetrics_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Baremetrics detector output");
        return -1;
    }
    *out = NULL;
    if (!baremetrics.state && br_key_pattern_init(&baremetrics,
        "\\b((?:sk|lk)_[a-zA-Z0-9]{18,25})\\b", error) != 0) return -1;
    *out = &baremetrics;
    return 0;
}
