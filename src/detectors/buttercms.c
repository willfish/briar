/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/buttercms/buttercms.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verify_buttercms(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0 ? -1 : 0;
    static const char prefix[] = "https://api.buttercms.com/v2/posts/?auth_token=";
    char url[sizeof(prefix) + 40]; /* Fixed 40-byte lowercase-alphanumeric capture. */
    int n = snprintf(url, sizeof(url), "%s%s", prefix, key);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    const br_http_request request = {.method = "GET", .url = url,
        .profile = BR_HTTP_SANE, .detector_type = 150};
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
     * supplies ZERO redaction secrets: retain echoed query credentials unchanged. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0;
}

static int scan_buttercms(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    int rc = br_scan_key(detector, ctx, verify, input, out, "key", verify_buttercms, error);
    /* Shared occurrence scanning appends eagerly. Roll back only this
     * invocation on failure, preserving findings supplied by the caller. */
    if (rc && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc != 0 ? -1 : 0;
}

static const char *const keywords[] = {"buttercms"};
static br_detector buttercms = {
    .type = 150, .version = 0, .name = "ButterCMS", .custom_name = "",
    .description = "ButterCMS is a headless CMS that enables developers to build websites and applications with a content management system. The API keys can be used to access and modify content stored in ButterCMS.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_buttercms,
};

int br_buttercms_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid ButterCMS detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&buttercms, "\\b([a-z0-9]{40})\\b", error) != 0) return -1;
    *out = &buttercms;
    return 0;
}
