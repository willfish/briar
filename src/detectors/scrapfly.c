/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/scrapfly/scrapfly.go. */
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

static int scan_scrapfly(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Scrapfly scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if ((key.len != 32 && key.len != 41) ||
            br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned_error, "cannot create Scrapfly result");
        if (!rc && verify) {
            char url[160];
            int n = snprintf(url, sizeof(url),
                             "https://api.scrapfly.io/scrape?key=%.*s&url=https://httpbin.org/status/200",
                             (int)key.len, key.data);
            if (n < 0 || (size_t)n >= sizeof(url)) {
                br_result_clear(&result);
                rc = fail(&owned_error, "cannot build Scrapfly URL");
                break;
            }
            /* Source assigns client.Timeout to 10s, then builds this URL, then NewRequest.
             * A nil context drops only this occurrence. Timeout is per request, not shared mutation. */
            if (!ctx) {
                br_result_clear(&result);
                continue;
            }
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 10000,
                .detector_type = detector->type,
            };
            br_http_response response = {0};
            char *send_error = NULL;
            if (br_http_send(ctx, &request, &response, &send_error) == 0 &&
                response.status >= 200 && response.status < 300)
                result.verified = true;
            br_http_release(ctx, &response);
            free(send_error);
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "cannot append Scrapfly result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"scrapfly"};
static br_detector scrapfly = {
    .type = 660, .version = 0, .name = "Scrapfly", .custom_name = "",
    .description = "Scrapfly is a web scraping service providing APIs to extract and process web data. Scrapfly API keys can be used to access and manipulate this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_scrapfly,
};

int br_scrapfly_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Scrapfly detector output");
    *out = NULL;
    if (br_key_pattern_init(&scrapfly,
            "\\b([a-z0-9]{32}|scp-(?:live|test)-[a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &scrapfly;
    return 0;
}
