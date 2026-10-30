/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/wrike/wrike.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void verify_wrike(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[8 + 335];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 336);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://app-us2.wrike.com/api/v4/contacts?me=true",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 248,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
}

static int scan_wrike(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Wrike scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        if (br_captures_at(&keys, i).len != 335) { rc = fail(error, "invalid Wrike capture"); break; }
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
            rc = fail(error, "out of memory creating Wrike result");
        } else if (verify && !ctx) {
            br_result_clear(&result);
            continue;
        } else if (verify) verify_wrike(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(error, "cannot append Wrike result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const wrike_keywords[] = {"wrike"};
static br_detector wrike_detector = {
    .type = 248, .version = 0, .name = "Wrike", .custom_name = "",
    .description = "Wrike is a collaborative work management platform that helps teams organize and manage their work. Wrike API keys can be used to access and modify data within Wrike.",
    .keywords = wrike_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_wrike,
};

int br_wrike_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Wrike detector output");
    *out = NULL;
    if (br_key_pattern_init(&wrike_detector, "\\b(ey[a-zA-Z0-9-._]{333})\\b", error) != 0) return -1;
    *out = &wrike_detector;
    return 0;
}
