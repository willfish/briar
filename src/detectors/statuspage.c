/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/statuspage/statuspage.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

enum { PAGE_KEEP = 0, PAGE_DROP = 1, PAGE_FATAL = -1 };

static int page_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return PAGE_FATAL;
}

static int page_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (key.len != 36) return PAGE_FATAL;
    if (!ctx) return PAGE_DROP;
    if (memchr(key.data, '\0', key.len)) return PAGE_KEEP; /* Invalid header; Do error stays unpublished. */
    char authorization[37];
    memcpy(authorization, key.data, 36);
    authorization[36] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.statuspage.io/v1/pages",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return PAGE_KEEP;
}

static int page_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return page_fail(error, "invalid or uninitialized Statuspage scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        int outcome = PAGE_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            outcome = page_fail(&owned_error, "cannot create Statuspage result");
        else if (verify)
            outcome = page_verify(ctx, key, &result);
        if (outcome == PAGE_FATAL) rc = -1;
        if (outcome == PAGE_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = page_fail(&owned_error, "cannot append Statuspage result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const page_keywords[] = {"statuspage"};
static br_detector page_detector = {
    .type = 775, .version = 0, .name = "Statuspage", .custom_name = "",
    .description = "Statuspage is an incident communication tool that helps you inform your users about outages and scheduled maintenance. Statuspage API keys can be used to manage and update your status pages.",
    .keywords = page_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = page_scan,
};

int br_statuspage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return page_fail(error, "invalid Statuspage detector output");
    *out = NULL;
    if (br_key_pattern_init(&page_detector, "\\b([0-9a-z-]{36})\\b", error) != 0) return -1;
    *out = &page_detector;
    return 0;
}
