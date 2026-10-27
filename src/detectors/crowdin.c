/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/crowdin/crowdin.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int crowdin_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void crowdin_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* The exact 80-byte capture fits with Bearer and NUL. Borrow the complete
     * 87-byte header value through synchronous send AND release, without copies. */
    char authorization[7 + 80 + 1];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.crowdin.com/api/v2/storages",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses all Do errors. ABI1 combines setup/allocation and Do:
     * suppress that whole domain, without a setter or diagnostic classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, never reading/draining. Body/read errors
     * cannot affect status. Eager buffering/release, full native SANE client
     * configuration and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int crowdin_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return crowdin_fail(error, "invalid or uninitialized Crowdin scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Keep every occurrence, including duplicates.
         * Finding resources precede both the known nil-context constructor
         * skip and, as in source, Authorization preparation. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = crowdin_fail(&owned_error, "cannot create Crowdin result");
        else if (!verify || ctx) {
            if (verify) crowdin_verify(ctx, key, &result);
            if (br_results_push(out, &result) != 0)
                rc = crowdin_fail(&owned_error, "cannot append Crowdin result");
        } /* verify && !ctx: source NewRequestWithContext skips the candidate. */
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const crowdin_keywords[] = {"crowdin"};
static br_detector crowdin_detector = {
    .type = 335, .version = 0, .name = "Crowdin", .custom_name = "",
    .description = "Crowdin is a cloud-based localization management platform. Crowdin API keys can be used to access and manage localization projects and resources.",
    .keywords = crowdin_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = crowdin_scan,
};

int br_crowdin_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return crowdin_fail(error, "invalid Crowdin detector output");
    *out = NULL;
    if (br_key_pattern_init(&crowdin_detector, "\\b([0-9A-Za-z]{80})\\b", error) != 0)
        return -1;
    *out = &crowdin_detector;
    return 0;
}
