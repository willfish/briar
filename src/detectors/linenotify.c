/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/linenotify/linenotify.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int linenotify_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do only. The stack header array dies at send return and is not
 * retained. This item keeps the original Bearer through its own release. */
typedef struct {
    br_http_response response;
    char *authorization;
} linenotify_pending;

typedef struct {
    linenotify_pending *items;
    size_t len, cap;
} linenotify_closes;

/* After this attempt's release, the Bearer must not remain readable. */
static void linenotify_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void linenotify_release_deferred(const br_scan_ctx *ctx, linenotify_closes *closes)
{
    while (closes->len) {
        linenotify_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        linenotify_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int linenotify_defer(linenotify_closes *closes, const br_http_response *response,
                            char *authorization)
{
    if (closes->len == closes->cap) {
        if (closes->cap > SIZE_MAX / sizeof(*closes->items) / 2) return -1;
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        linenotify_pending *items = realloc(closes->items, cap * sizeof(*items));
        if (!items) return -1;
        closes->items = items;
        closes->cap = cap;
    }
    closes->items[closes->len].response = *response;
    closes->items[closes->len].authorization = authorization;
    ++closes->len;
    return 0;
}

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed POST.
 * The Go client field is a test seam; verification uses the scan transport. */
static int linenotify_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                             bool *keep, linenotify_closes *closes, char **error)
{
    /* Go accepts this URL and leaves the query space unescaped. Do not
     * percent-encode it, add a body, or change the message. */
    static const char url[] =
        "https://notify-api.line.me/api/notify?message=Notification Successful";
    _Static_assert(sizeof(url) - 1 == 69, "LineNotify URL must keep the literal query space");
    *keep = false;
    if (key.len != 43) return linenotify_fail(error, "invalid LineNotify capture");
    /* Drop after the finding exists. No Bearer, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack Bearer dies at send return and cannot survive scan-return
     * release. Keep the complete owned value through this attempt's release. */
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization)
        return linenotify_fail(error, "cannot allocate LineNotify authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it. */
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        send_rc = br_http_send(ctx, &request, &response, &transport_error);
    }
    free(transport_error);
    if (send_rc != 0) {
        /* Do or preparation failed. Do not invent a cause. Release once now,
         * while the original Bearer is intact, then free it. Not retained. */
        br_http_release(ctx, &response);
        linenotify_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (linenotify_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        linenotify_forget(authorization);
        return linenotify_fail(error, "cannot retain LineNotify response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    *keep = true;
    return 0;
}

static int linenotify_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return linenotify_fail(error, "invalid or uninitialized LineNotify scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    linenotify_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op for this grammar. Keep every occurrence, including
     * duplicates, in match order. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 43)
            rc = linenotify_fail(&owned_error, "invalid LineNotify capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = linenotify_fail(&owned_error, "cannot create LineNotify finding");
        if (!rc && verify)
            rc = linenotify_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = linenotify_fail(&owned_error, "cannot append LineNotify finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    linenotify_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const linenotify_keywords[] = {"linenotify"};
static br_detector linenotify_detector = {
    .type = 176, .version = 0, .name = "LineNotify", .custom_name = "",
    .description = "Line Notify is a service provided by LINE Corporation that allows you to send notifications to your LINE app. The API keys can be used to send messages to users or groups.",
    .keywords = linenotify_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = linenotify_scan,
};

int br_linenotify_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return linenotify_fail(error, "invalid LineNotify detector output");
    *out = NULL;
    if (br_key_pattern_init(&linenotify_detector, "\\b([0-9A-Za-z]{43})\\b", error) != 0)
        return -1;
    *out = &linenotify_detector;
    return 0;
}
