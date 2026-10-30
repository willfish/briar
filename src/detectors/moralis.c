/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/moralis/moralis.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int moralis_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do only. The stack header array dies at send return and is not
 * retained. This item keeps the original key through its own release. */
typedef struct {
    br_http_response response;
    char *api_key;
} moralis_pending;

typedef struct {
    moralis_pending *items;
    size_t len, cap;
} moralis_closes;

/* After this attempt's release, the key must not remain readable. */
static void moralis_forget(char *api_key)
{
    if (!api_key) return;
    memset(api_key, 'X', strlen(api_key));
    free(api_key);
}

static void moralis_release_deferred(const br_scan_ctx *ctx, moralis_closes *closes)
{
    while (closes->len) {
        moralis_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        moralis_forget(item->api_key);
        item->api_key = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int moralis_defer(moralis_closes *closes, const br_http_response *response, char *api_key)
{
    if (closes->len == closes->cap) {
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        if (cap < closes->cap || cap > SIZE_MAX / sizeof(*closes->items)) return -1;
        moralis_pending *items = realloc(closes->items, cap * sizeof(*items));
        if (!items) return -1;
        closes->items = items;
        closes->cap = cap;
    }
    closes->items[closes->len].response = *response;
    closes->items[closes->len].api_key = api_key;
    ++closes->len;
    return 0;
}

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed GET.
 * The Go client field is a test seam; verification uses the scan transport. */
static int moralis_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                          bool *keep, moralis_closes *closes, char **error)
{
    static const char url[] =
        "https://deep-index.moralis.io/api/v2/0xd8da6bf26964af9d7eed9e03e53415d37aa96045/nft?chain=eth&format=decimal";
    _Static_assert(sizeof(url) - 1 == 108, "Moralis URL");
    *keep = false;
    if (key.len != 64) return moralis_fail(error, "invalid Moralis capture");
    /* Drop after the finding exists. No key allocation, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack key dies at send return and cannot survive scan-return release.
     * The header value is the raw key, not Bearer and not Token. */
    char *api_key = malloc(key.len + 1);
    if (!api_key) return moralis_fail(error, "cannot allocate Moralis key");
    memcpy(api_key, key.data, key.len);
    api_key[key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Source writes X-API-Key. Header.Add stores the canonical X-Api-Key.
         * Synthesized header storage dies at send return. Do not retain it. */
        const br_header headers[] = {
            {"Accept", "application/json"},
            {"X-Api-Key", api_key},
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
         * while the original key is intact, then free it. Not retained. */
        br_http_release(ctx, &response);
        moralis_forget(api_key);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (moralis_defer(closes, &response, api_key) != 0) {
        br_http_release(ctx, &response);
        moralis_forget(api_key);
        return moralis_fail(error, "cannot retain Moralis response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    *keep = true;
    return 0;
}

static int moralis_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return moralis_fail(error, "invalid or uninitialized Moralis scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    moralis_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op. Keep every occurrence, including duplicates, in
     * match order. Raw and the key part are the capture. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 64)
            rc = moralis_fail(&owned_error, "invalid Moralis capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = moralis_fail(&owned_error, "cannot create Moralis finding");
        if (!rc && verify)
            rc = moralis_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = moralis_fail(&owned_error, "cannot append Moralis finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    moralis_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const moralis_keywords[] = {"moralis"};
static br_detector moralis_detector = {
    .type = 909, .version = 0, .name = "Moralis", .custom_name = "",
    .description = "Moralis is a platform for building and deploying decentralized applications (dApps). Moralis API keys can be used to interact with blockchain data and services.",
    .keywords = moralis_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = moralis_scan,
};

int br_moralis_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return moralis_fail(error, "invalid Moralis detector output");
    *out = NULL;
    if (br_key_pattern_init(&moralis_detector, "\\b([0-9a-zA-Z]{64})\\b", error) != 0)
        return -1;
    *out = &moralis_detector;
    return 0;
}
