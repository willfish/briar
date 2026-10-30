/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/streak/streak.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_streak(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* base64(key + ":") is built before NewRequest. A nil context then skips. */
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, NULL)) return -1;
    if (!ctx) {
        free(authorization);
        return 1;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.streak.com/api/v1/pipelines",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return 0;
}

static int scan_streak(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Streak scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int skip = 0;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create Streak result");
        else if (verify) skip = verify_streak(ctx, key, &result);
        if (skip < 0) rc = fail(&owned_error, "cannot verify Streak candidate");
        if (!rc && !skip && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append Streak result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"streak"};
static br_detector detector = {
    .type = 549, .name = "Streak", .custom_name = "",
    .description = "Streak is a CRM software that integrates with Gmail. Streak API keys can be used to access and manage CRM data within Streak.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_streak,
};

int br_streak_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Streak detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9Aa-f]{32})\\b", (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
