/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/segmentapikey/segmentapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_segment(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[96];
    int n = snprintf(auth, sizeof(auth), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(auth)) return -1;
    if (!ctx) return 1; /* Body is empty; header is complete before the constructor drop. */
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://platform.segmentapis.com/v1beta/workspaces",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    /* 2xx verifies. Every other status and every Do error stays unverified
     * with no setter. Body and close errors are ignored. */
    if (br_http_send(ctx, &request, &response, &error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(error);
    return 0;
}

static int scan_segment(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SegmentApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(error, "out of memory creating SegmentApiKey result");
        else if (verify) {
            int checked = verify_segment(ctx, keys.items[i], &result);
            if (checked < 0) rc = fail(error, "cannot construct SegmentApiKey Authorization header");
            else if (checked > 0) { br_result_clear(&result); continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending SegmentApiKey result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"segment"};
static br_detector segmentapikey = {
    .type = 122, .version = 0, .name = "SegmentApiKey", .custom_name = "",
    .description = "Segment is a customer data platform that helps you collect, clean, and control your customer data. Segment API keys can be used to access and manage this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_segment,
};

int br_segmentapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SegmentApiKey detector output");
    *out = NULL;
    if (br_key_pattern_init(&segmentapikey,
            "\\b([A-Za-z0-9_\\-a-zA-Z]{43}\\.[A-Za-z0-9_\\-a-zA-Z]{43})\\b", error) != 0)
        return -1;
    *out = &segmentapikey;
    return 0;
}
