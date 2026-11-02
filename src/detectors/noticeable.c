/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/noticeable/noticeable.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int noticeable_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do only. The stack header array dies at send return and is not
 * retained. This item keeps the original Authorization through its own release. */
typedef struct {
    br_http_response response;
    char *authorization;
} noticeable_pending;

typedef struct {
    noticeable_pending *items;
    size_t len, cap;
} noticeable_closes;

/* After this attempt's release, the token must not remain readable. */
static void noticeable_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void noticeable_release_deferred(const br_scan_ctx *ctx, noticeable_closes *closes)
{
    while (closes->len) {
        noticeable_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        noticeable_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int noticeable_defer(noticeable_closes *closes, const br_http_response *response,
                            char *authorization)
{
    if (closes->len == closes->cap) {
        if (closes->cap > SIZE_MAX / sizeof(*closes->items) / 2) return -1;
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        noticeable_pending *items = realloc(closes->items, cap * sizeof(*items));
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
static int noticeable_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                             bool *keep, noticeable_closes *closes, char **error)
{
    static const char url[] = "https://api.noticeable.io/graphql";
    static const char query[] = "{\"query\": \"YOUR_GRAPHQL_PAYLOAD\"}";
    _Static_assert(sizeof(url) - 1 == 33, "Noticeable URL");
    _Static_assert(sizeof(query) - 1 == 33, "Noticeable body must stay the 33-byte placeholder");
    *keep = false;
    if (key.len != 20) return noticeable_fail(error, "invalid Noticeable capture");
    /* Drop after the finding exists. No Authorization, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack token dies at send return and cannot survive scan-return
     * release. The value is Apikey plus one space plus the raw key, not Bearer. */
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization)
        return noticeable_fail(error, "cannot allocate Noticeable authorization");
    memcpy(authorization, "Apikey ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it.
         * The body is the static placeholder. Do not allocate a copy. */
        const br_header headers[] = {
            {"Content-Type", "application/json"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 2,
            .body = {(const unsigned char *)query, sizeof(query) - 1},
            .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        send_rc = br_http_send(ctx, &request, &response, &transport_error);
    }
    free(transport_error);
    if (send_rc != 0) {
        /* Do or preparation failed. Do not invent a cause. Release once now,
         * while the original Authorization is intact, then free it. Not retained. */
        br_http_release(ctx, &response);
        noticeable_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (noticeable_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        noticeable_forget(authorization);
        return noticeable_fail(error, "cannot retain Noticeable response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    *keep = true;
    return 0;
}

static int noticeable_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return noticeable_fail(error, "invalid or uninitialized Noticeable scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    noticeable_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op. Keep every occurrence, including duplicates, in
     * match order. Raw and the key part are the capture. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 20)
            rc = noticeable_fail(&owned_error, "invalid Noticeable capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = noticeable_fail(&owned_error, "cannot create Noticeable finding");
        if (!rc && verify)
            rc = noticeable_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = noticeable_fail(&owned_error, "cannot append Noticeable finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    noticeable_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const noticeable_keywords[] = {"noticeable"};
static br_detector noticeable_detector = {
    .type = 337, .version = 0, .name = "Noticeable", .custom_name = "",
    .description = "Noticeable is a service used for creating and managing changelogs and release notes. Noticeable API keys can be used to access and modify this data.",
    .keywords = noticeable_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = noticeable_scan,
};

int br_noticeable_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return noticeable_fail(error, "invalid Noticeable detector output");
    *out = NULL;
    if (br_key_pattern_init(&noticeable_detector, "\\b([0-9a-zA-Z]{20})\\b", error) != 0)
        return -1;
    *out = &noticeable_detector;
    return 0;
}
