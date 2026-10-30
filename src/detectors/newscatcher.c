/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/newscatcher/newscatcher.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { NEWS_ABORT = -1, NEWS_KEEP = 0, NEWS_DROP = 1 } news_outcome;
typedef struct {
    br_http_response *items;
    size_t len, cap;
} news_pending;

static const char news_url[] = "https://api.newscatcherapi.com/v2/search?q=Tesla";

static int news_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void news_drain(const br_scan_ctx *ctx, news_pending *pending)
{
    while (pending->len) br_http_release(ctx, &pending->items[--pending->len]);
    free(pending->items);
    *pending = (news_pending){0};
}

static int news_hold(news_pending *pending, const br_http_response *response, char **error)
{
    if (pending->len == pending->cap) {
        size_t cap = pending->cap ? pending->cap * 2 : 2;
        if (cap < pending->cap || cap > SIZE_MAX / sizeof(*pending->items))
            return news_fail(error, "cannot retain Newscatcher response");
        br_http_response *items = realloc(pending->items, cap * sizeof(*items));
        if (!items) return news_fail(error, "cannot retain Newscatcher response");
        pending->items = items;
        pending->cap = cap;
    }
    pending->items[pending->len++] = *response;
    return 0;
}

static news_outcome news_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                news_pending *pending, char **error)
{
    /* NewRequestWithContext fails before Header.Add. A nil context drops this
     * occurrence and is not a send. This literal URL cannot fail to parse. */
    if (!ctx) return NEWS_DROP;
    /* Header.Add canonicalizes x-api-key to X-Api-Key before Do. Briar does not. */
    const br_header headers[] = {{"X-Api-Key", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = news_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 0, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    /* A failed Do or preparation releases immediately. The synthesized
     * User-Agent array is gone when send returns; do not retain it. */
    if (sent != 0) {
        br_http_release(ctx, &response);
        return NEWS_KEEP;
    }
    /* Successful Close is deferred until this scan returns. Verdict uses the
     * still-pending response. URL, X-Api-Key and the key remain the originals. */
    result->verified = response.status >= 200 && response.status < 300;
    if (news_hold(pending, &response, error) != 0) {
        br_http_release(ctx, &response);
        return NEWS_ABORT;
    }
    return NEWS_KEEP;
}

static int news_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return news_fail(error, "invalid or uninitialized Newscatcher scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    news_pending pending = {0};
    char *owned_error = NULL;
    /* Occurrences, including duplicates. The class has no whitespace to trim. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        news_outcome outcome = NEWS_KEEP;
        if (key.len != 43) {
            news_fail(&owned_error, "invalid Newscatcher capture");
            outcome = NEWS_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            news_fail(&owned_error, "cannot create Newscatcher result");
            outcome = NEWS_ABORT;
        } else if (verify) {
            outcome = news_verify(ctx, key, &result, &pending, &owned_error);
        }
        if (outcome == NEWS_KEEP && br_results_push(out, &result) != 0) {
            news_fail(&owned_error, "cannot append Newscatcher result");
            outcome = NEWS_ABORT;
        }
        br_result_clear(&result);
        if (outcome == NEWS_ABORT) rc = -1;
    }
    /* Scanner-return LIFO, after publication and on a later fatal path.
     * Captures and the static URL are still alive for this drain. */
    news_drain(ctx, &pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const news_keywords[] = {"newscatcher"};
static br_detector news_detector = {
    .type = 543, .version = 0, .name = "Newscatcher", .custom_name = "",
    .description = "Newscatcher is an API service used to search and retrieve news articles from various sources. Newscatcher API keys can be used to access and query this service.",
    .keywords = news_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = news_scan,
};

int br_newscatcher_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return news_fail(error, "invalid Newscatcher detector output");
    *out = NULL;
    if (br_key_pattern_init(&news_detector, "\\b([0-9A-Za-z_]{43})\\b", error) != 0) return -1;
    *out = &news_detector;
    return 0;
}
