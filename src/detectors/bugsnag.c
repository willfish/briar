/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bugsnag/bugsnag.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_bugsnag(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0 ? -1 : 0;
    char authorization[43]; /* Literal lowercase "token " + 36 captured bytes + NUL. */
    int n = snprintf(authorization, sizeof(authorization), "token %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", authorization}};
    const br_http_request request = {.method = "GET", .url = "https://api.bugsnag.com/user/organizations?admin",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 388};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error ? error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* Status-only verification ignores every body/read/drain error. Source
     * supplies ZERO redaction secrets: retain echoed credentials unchanged. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0;
}

static int scan_bugsnag(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", verify_bugsnag, error);
    /* Shared occurrence scanning appends eagerly. Roll back only this
     * invocation on failure, preserving findings supplied by the caller. */
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc != 0 ? -1 : 0;
}

static const char *const keywords[] = {"bugsnag"};
static br_detector bugsnag = {
    .type = 388, .version = 0, .name = "Bugsnag", .custom_name = "",
    .description = "Bugsnag is an error monitoring service for web and mobile applications. Bugsnag API keys can be used to report and manage errors.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_bugsnag,
};

int br_bugsnag_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid Bugsnag detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&bugsnag, "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", error) != 0)
        return -1;
    *out = &bugsnag;
    return 0;
}
