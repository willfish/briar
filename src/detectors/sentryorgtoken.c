/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sentryorgtoken/sentryorgtoken.go. */
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int sentry_set(br_result *result, const char *cause, const char *token)
{
    br_slice secret = {(const unsigned char *)token, strlen(token)};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int sentry_verify(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    /* The source receiver is by value, so a nil client is always replaced with
     * SaneHttpClient for this call. A nil context fails the constructor. */
    if (!ctx) return sentry_set(result, "net/http: nil Context", token);
    char authorization[224];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", token);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://sentry.io/api/0/auth/validate",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    bool verified = false;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200) verified = true;
    else if (response.status != 401 && response.status != 403) {
        int wrote = snprintf(status_error, sizeof(status_error),
                             "unexpected HTTP response status %d", response.status);
        if (wrote < 0 || (size_t)wrote >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            free(transport_error);
            return -1;
        }
        cause = status_error;
    }
    int set = sentry_set(result, cause, token);
    br_http_release(ctx, &response);
    free(transport_error);
    if (set != 0) return -1;
    result->verified = verified;
    return 0;
}

static int sentry_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    return br_scan_unique_key(detector, ctx, verify, input, out, "key", sentry_verify, error);
}

static const char *const sentry_keywords[] = {"sntrys_eyJ"};
static br_regex *sentry_regex;
static br_detector sentry_detector = {
    .type = 1017, .version = 0, .name = "SentryOrgToken", .custom_name = "",
    .description = "Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry Organization Auth Tokens can be used in many places to interact with Sentry programmatically. For example, they can be used for sentry-cli, bundler plugins, or similar use cases.",
    .keywords = sentry_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = sentry_scan,
};

int br_sentryorgtoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid SentryOrgToken detector output");
        return -1;
    }
    *out = NULL;
    if (!sentry_regex &&
        br_regex_compile("\\b(sntrys_eyJ[a-zA-Z0-9=_+/]{197})\\b", &sentry_regex, error) != 0)
        return -1;
    sentry_detector.state = sentry_regex;
    *out = &sentry_detector;
    return 0;
}
