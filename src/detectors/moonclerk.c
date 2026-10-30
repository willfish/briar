/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/moonclerk/moonclerk.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int moonclerk_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do only. The stack header array dies at send return and is not
 * retained. This item keeps the original Authorization through its own release. */
typedef struct {
    br_http_response response;
    char *authorization;
} moonclerk_pending;

typedef struct {
    moonclerk_pending *items;
    size_t len, cap;
} moonclerk_closes;

/* After this attempt's release, the token must not remain readable. */
static void moonclerk_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void moonclerk_release_deferred(const br_scan_ctx *ctx, moonclerk_closes *closes)
{
    while (closes->len) {
        moonclerk_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        moonclerk_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int moonclerk_defer(moonclerk_closes *closes, const br_http_response *response,
                           char *authorization)
{
    if (closes->len == closes->cap) {
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        if (cap < closes->cap || cap > SIZE_MAX / sizeof(*closes->items)) return -1;
        moonclerk_pending *items = realloc(closes->items, cap * sizeof(*items));
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
static int moonclerk_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                            bool *keep, moonclerk_closes *closes, char **error)
{
    static const char url[] = "https://api.moonclerk.com/forms";
    *keep = false;
    if (key.len != 32) return moonclerk_fail(error, "invalid Moonclerk capture");
    /* Drop after the finding exists. No Authorization, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack token dies at send return and cannot survive scan-return
     * release. The value is Token token= plus the raw key, not Bearer. */
    char *authorization = malloc(12 + key.len + 1);
    if (!authorization)
        return moonclerk_fail(error, "cannot allocate Moonclerk authorization");
    memcpy(authorization, "Token token=", 12);
    memcpy(authorization + 12, key.data, key.len);
    authorization[12 + key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Header.Add order is Accept, then Authorization. Synthesized header
         * storage dies at send return. Do not retain it. */
        const br_header headers[] = {
            {"Accept", "application/vnd.moonclerk+json;version=1"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 2,
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
        moonclerk_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (moonclerk_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        moonclerk_forget(authorization);
        return moonclerk_fail(error, "cannot retain Moonclerk response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    *keep = true;
    return 0;
}

static int moonclerk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return moonclerk_fail(error, "invalid or uninitialized Moonclerk scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    moonclerk_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op. Keep every occurrence, including duplicates, in
     * match order. Raw and the key part are the capture. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32)
            rc = moonclerk_fail(&owned_error, "invalid Moonclerk capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = moonclerk_fail(&owned_error, "cannot create Moonclerk finding");
        if (!rc && verify)
            rc = moonclerk_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = moonclerk_fail(&owned_error, "cannot append Moonclerk finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    moonclerk_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const moonclerk_keywords[] = {"moonclerk"};
static br_detector moonclerk_detector = {
    .type = 698, .version = 0, .name = "Moonclerk", .custom_name = "",
    .description = "Moonclerk is an online payment system that allows businesses to accept recurring payments. Moonclerk API keys can be used to manage and access payment data.",
    .keywords = moonclerk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = moonclerk_scan,
};

int br_moonclerk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return moonclerk_fail(error, "invalid Moonclerk detector output");
    *out = NULL;
    if (br_key_pattern_init(&moonclerk_detector, "\\b([0-9a-z]{32})\\b", error) != 0)
        return -1;
    *out = &moonclerk_detector;
    return 0;
}
