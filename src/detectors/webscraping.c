/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/webscraping/webscraping.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

enum { WEB_KEEP = 0, WEB_DROP = 1, WEB_FATAL = -1 };

static int web_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return WEB_FATAL;
}

static int web_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char prefix[] = "https://api.webscrapingapi.com/v1?api_key=";
    if (key.len != 32) return web_fail(error, "invalid Webscraping key");
    char url[sizeof(prefix) + 32];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 32);
    url[sizeof(prefix) - 1 + 32] = '\0';
    if (!ctx) return WEB_DROP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int outcome = WEB_KEEP;
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error) outcome = WEB_DROP; /* ReadAll error skips this candidate. */
        else {
            static const unsigned char marker[] = "key `url` required.";
            result->verified = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        }
    }
    br_http_release(ctx, &response);
    free(send_error);
    return outcome;
}

static int web_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return web_fail(error, "invalid or uninitialized Webscraping scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = WEB_KEEP;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            outcome = web_fail(&owned_error, "cannot create Webscraping result");
        else if (verify)
            outcome = web_verify(ctx, br_captures_at(&keys, i), &result, &owned_error);
        if (outcome == WEB_FATAL) rc = -1;
        if (outcome == WEB_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = web_fail(&owned_error, "cannot append Webscraping result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const web_keywords[] = {"webscraping"};
static br_detector web_detector = {
    .type = 551, .version = 0, .name = "Webscraping", .custom_name = "",
    .description = "Webscraping API keys can be used to access web scraping services to extract data from websites.",
    .keywords = web_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = web_scan,
};

int br_webscraping_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return web_fail(error, "invalid Webscraping detector output");
    *out = NULL;
    if (br_key_pattern_init(&web_detector, "\\b([0-9A-Za-z]{32})\\b", error) != 0) return -1;
    *out = &web_detector;
    return 0;
}
