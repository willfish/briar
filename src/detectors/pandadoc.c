/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pandadoc/pandadoc.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int pandadoc_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do only. The stack header array dies at send return and is not
 * retained. This item keeps the original Authorization through its own release.
 * Source defers Body.Close until FromData returns, not inside the helper. */
typedef struct {
    br_http_response response;
    char *authorization;
} pandadoc_pending;

typedef struct {
    pandadoc_pending *items;
    size_t len, cap;
} pandadoc_closes;

/* After this attempt's release, the token must not remain readable. */
static void pandadoc_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void pandadoc_release_deferred(const br_scan_ctx *ctx, pandadoc_closes *closes)
{
    while (closes->len) {
        pandadoc_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        pandadoc_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int pandadoc_defer(pandadoc_closes *closes, const br_http_response *response,
                          char *authorization)
{
    if (closes->len == closes->cap) {
        if (closes->cap > SIZE_MAX / sizeof(*closes->items) / 2) return -1;
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        pandadoc_pending *items = realloc(closes->items, cap * sizeof(*items));
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
static int pandadoc_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, pandadoc_closes *closes, char **error)
{
    static const char url[] = "https://api.pandadoc.com/public/v1/documents";
    _Static_assert(sizeof(url) - 1 == 44, "Pandadoc URL");
    *keep = false;
    if (key.len != 40) return pandadoc_fail(error, "invalid Pandadoc capture");
    /* Drop after the finding exists. No Authorization, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack token dies at send return and cannot survive scan-return release.
     * The value is API-Key, one space, and the raw key. Not Bearer. */
    char *authorization = malloc(8 + key.len + 1);
    if (!authorization)
        return pandadoc_fail(error, "cannot allocate Pandadoc authorization");
    memcpy(authorization, "API-Key ", 8);
    memcpy(authorization + 8, key.data, key.len);
    authorization[8 + key.len] = '\0';
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
         * while the original Authorization is intact, then free it. Not retained. */
        br_http_release(ctx, &response);
        pandadoc_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (pandadoc_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        pandadoc_forget(authorization);
        return pandadoc_fail(error, "cannot retain Pandadoc response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    *keep = true;
    return 0;
}

static int pandadoc_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pandadoc_fail(error, "invalid or uninitialized Pandadoc scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    pandadoc_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op. Keep every occurrence, including duplicates, in
     * match order. Raw and the key part are the capture. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 40)
            rc = pandadoc_fail(&owned_error, "invalid Pandadoc capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pandadoc_fail(&owned_error, "cannot create Pandadoc finding");
        if (!rc && verify)
            rc = pandadoc_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = pandadoc_fail(&owned_error, "cannot append Pandadoc finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    pandadoc_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const pandadoc_keywords[] = {"pandadoc"};
static br_detector pandadoc_detector = {
    .type = 298, .version = 0, .name = "Pandadoc", .custom_name = "",
    .description = "Pandadoc is a document automation software that helps create, manage, and sign digital documents. Pandadoc API keys can be used to access and manage documents through the Pandadoc API.",
    .keywords = pandadoc_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pandadoc_scan,
};

int br_pandadoc_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pandadoc_fail(error, "invalid Pandadoc detector output");
    *out = NULL;
    if (br_key_pattern_init(&pandadoc_detector, "\\b([a-zA-Z0-9]{40})\\b", error) != 0)
        return -1;
    *out = &pandadoc_detector;
    return 0;
}
