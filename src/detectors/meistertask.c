/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/meistertask/meistertask.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int meistertask_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void meistertask_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[51];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 43);
    authorization[50] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.meistertask.com/api/projects",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* The source suppresses the WHOLE mixed preparation/Do error domain,
     * never calls a setter and ignores bodies/read errors at every status. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Keep provider-original header/auth/key/URL storage through one release
     * per attempt. Prepared headers/UA end at ordinary send return instead. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int meistertask_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return meistertask_fail(error, "invalid or uninitialized Meistertask scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op for this ASCII-alphanumeric grammar. Preserve
         * original key case, occurrence order, duplicates and key-only fields. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = meistertask_fail(&owned_error, "cannot create Meistertask finding");
        if (rc == 0 && verify) {
            /* Finding creation precedes the constructor's nil-context skip;
             * source Authorization construction happens only afterward. */
            if (!ctx) { br_result_clear(&result); continue; }
            meistertask_verify(ctx, keys.items[i], &result);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = meistertask_fail(&owned_error, "cannot append Meistertask finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        meistertask_fail(&owned_error, "cannot collect Meistertask keys");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const meistertask_keywords[] = {"meistertask"};
static br_detector meistertask_detector = {
    .type = 656, .version = 0, .name = "Meistertask", .custom_name = "",
    .description = "Meistertask is a task management tool that allows users to manage projects and tasks. Meistertask API keys can be used to access and modify project and task data.",
    .keywords = meistertask_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = meistertask_scan,
};

int br_meistertask_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return meistertask_fail(error, "invalid Meistertask detector output");
    *out = NULL;
    if (!meistertask_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(meistertask_keywords, 1, "\\b([a-zA-Z0-9]{43})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        meistertask_detector.state = pattern;
    }
    *out = &meistertask_detector;
    return 0;
}
