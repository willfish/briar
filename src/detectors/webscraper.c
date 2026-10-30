/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/webscraper/webscraper.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { WEB_ABORT = -1, WEB_KEEP = 0, WEB_SKIP = 1 } web_outcome;

static int web_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static web_outcome web_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* The complete URL is built before the nil-context drop. The key class
     * cannot make this URL fail to parse. */
    char url[sizeof("https://api.webscraper.io/api/v1/sitemaps?api_token=") + 60];
    int written = snprintf(url, sizeof(url),
                           "https://api.webscraper.io/api/v1/sitemaps?api_token=%.*s",
                           (int)key.len, (const char *)key.data);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        web_fail(error, "cannot build WebScraper URL");
        return WEB_ABORT;
    }
    if (!ctx) return WEB_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Do failures stay unverified with no setter. Body and read errors are
     * ignored. Only 2xx verifies. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return WEB_KEEP;
}

static int web_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return web_fail(error, "invalid or uninitialized WebScraper scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        web_outcome outcome = WEB_KEEP;
        if (key.len != 60) {
            web_fail(&owned_error, "invalid WebScraper capture");
            outcome = WEB_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            web_fail(&owned_error, "cannot create WebScraper result");
            outcome = WEB_ABORT;
        } else if (verify) {
            outcome = web_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == WEB_KEEP && br_results_push(out, &result) != 0) {
            web_fail(&owned_error, "cannot append WebScraper result");
            outcome = WEB_ABORT;
        }
        br_result_clear(&result);
        if (outcome == WEB_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const web_keywords[] = {"webscraper"};
static br_detector web_detector = {
    .type = 663, .version = 0, .name = "WebScraper", .custom_name = "",
    .description = "WebScraper is a web scraping service that allows you to extract data from websites. WebScraper API keys can be used to create, manage, and run sitemaps for web scraping tasks.",
    .keywords = web_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = web_scan,
};

int br_webscraper_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return web_fail(error, "invalid WebScraper detector output");
    *out = NULL;
    if (br_key_pattern_init(&web_detector, "\\b([a-zA-Z0-9]{60})\\b", error) != 0)
        return -1;
    *out = &web_detector;
    return 0;
}
