/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/linemessaging/linemessaging.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int linemessaging_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do only. The stack header array dies at send return and is not
 * retained. This item keeps the original Bearer through its own release. */
typedef struct {
    br_http_response response;
    char *authorization;
} linemessaging_pending;

typedef struct {
    linemessaging_pending *items;
    size_t len, cap;
} linemessaging_closes;

/* After this attempt's release, the Bearer must not remain readable. */
static void linemessaging_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void linemessaging_release_deferred(const br_scan_ctx *ctx, linemessaging_closes *closes)
{
    while (closes->len) {
        linemessaging_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        linemessaging_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int linemessaging_defer(linemessaging_closes *closes, const br_http_response *response,
                               char *authorization)
{
    if (closes->len == closes->cap) {
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        if (cap < closes->cap || cap > SIZE_MAX / sizeof(*closes->items)) return -1;
        linemessaging_pending *items = realloc(closes->items, cap * sizeof(*items));
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
 * NewRequestWithContext rejects only a nil context for this fixed GET.
 * The Go client field is a test seam; verification uses the scan transport. */
static int linemessaging_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                bool *keep, linemessaging_closes *closes, char **error)
{
    static const char url[] = "https://api.line.me/v2/bot/info";
    *keep = false;
    if (key.len != 171 && key.len != 172)
        return linemessaging_fail(error, "invalid LineMessaging capture");
    /* Drop after the finding exists. No Bearer, send, release, or setter. */
    if (!ctx) return 0;
    /* Both capture lengths exceed a short stack token. The complete Bearer
     * stays alive through send and this attempt's own release. */
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization)
        return linemessaging_fail(error, "cannot allocate LineMessaging authorization");
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
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
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
        linemessaging_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (linemessaging_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        linemessaging_forget(authorization);
        return linemessaging_fail(error, "cannot retain LineMessaging response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    *keep = true;
    return 0;
}

static int linemessaging_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return linemessaging_fail(error, "invalid or uninitialized LineMessaging scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    linemessaging_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op for this grammar. Keep every occurrence, including
     * both lengths and duplicates, in match order. The keyword stays "line". */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 171 && key.len != 172)
            rc = linemessaging_fail(&owned_error, "invalid LineMessaging capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = linemessaging_fail(&owned_error, "cannot create LineMessaging finding");
        if (!rc && verify)
            rc = linemessaging_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = linemessaging_fail(&owned_error, "cannot append LineMessaging finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    linemessaging_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const linemessaging_keywords[] = {"line"};
static br_detector linemessaging_detector = {
    .type = 168, .version = 0, .name = "LineMessaging", .custom_name = "",
    .description = "Line Messaging is a communication app that allows users to send messages, photos, videos, and audio. Line Messaging API keys can be used to access and modify this data and communication.",
    .keywords = linemessaging_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = linemessaging_scan,
};

int br_linemessaging_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return linemessaging_fail(error, "invalid LineMessaging detector output");
    *out = NULL;
    if (br_key_pattern_init(&linemessaging_detector, "\\b([A-Za-z0-9+/]{171,172})\\b", error) != 0)
        return -1;
    *out = &linemessaging_detector;
    return 0;
}
