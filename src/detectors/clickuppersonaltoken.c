/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clickuppersonaltoken/clickuppersonaltoken.go. */
#include "detectors.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int set_cause(br_result *result, const char *cause)
{
    const br_slice token = {result->raw.data, result->raw.len};
    /* Only the COMPLETE captured token is a redaction secret. Core +1 means
     * resource failure, never a retained outcome or candidate skip. */
    return br_result_set_verification_error(result, cause, &token, 1) != 0 ? -1 : 0;
}

static int verify_clickuppersonaltoken(const br_scan_ctx *ctx, const char *token, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    const br_header headers[] = {{"Authorization", token}};
    const br_http_request request = {.method = "GET", .url = "https://api.clickup.com/api/v2/user",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 366};
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error ? transport_error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
        cause = status_error;
    }
    /* Source ignores body/read/drain/close errors. Copy the cause before
     * release/free. ABI1 eager buffering/release does not prove source
     * verifier-deferred drain/close timing or full http.Client configuration. */
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc != 0 ? -1 : 0;
}

static int scan_clickuppersonaltoken(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                     br_slice input, br_results *out, char **error)
{
    size_t original_len = out ? out->len : 0;
    int rc = br_scan_unique_key(detector, ctx, verify, input, out, "key", verify_clickuppersonaltoken, error);
    /* Shared scanning appends eagerly. Roll back this invocation only on a
     * resource failure, preserving findings supplied by the caller. */
    if (rc != 0 && out) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc != 0 ? -1 : 0;
}

static const char *const keywords[] = {"clickup"};
static br_detector clickuppersonaltoken = {
    .type = 366, .version = 0, .name = "ClickupPersonalToken", .custom_name = "",
    .description = "ClickUp is a project management tool. Personal tokens can be used to access and modify data within ClickUp on behalf of a user.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_clickuppersonaltoken,
};

int br_clickuppersonaltoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid ClickupPersonalToken detector output");
        return -1;
    }
    *out = NULL;
    if (br_key_pattern_init(&clickuppersonaltoken, "\\b(pk_[0-9]{7,9}_[0-9A-Z]{32})\\b", error) != 0) return -1;
    *out = &clickuppersonaltoken;
    return 0;
}
