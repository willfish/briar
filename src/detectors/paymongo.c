/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/paymongo/paymongo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int paymongo_fail(char **error, const char *message)
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
} paymongo_pending;

typedef struct {
    paymongo_pending *items;
    size_t len, cap;
} paymongo_closes;

/* After this attempt's release, the token must not remain readable. */
static void paymongo_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void paymongo_release_deferred(const br_scan_ctx *ctx, paymongo_closes *closes)
{
    while (closes->len) {
        paymongo_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        paymongo_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int paymongo_defer(paymongo_closes *closes, const br_http_response *response,
                          char *authorization)
{
    if (closes->len == closes->cap) {
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        if (cap < closes->cap || cap > SIZE_MAX / sizeof(*closes->items)) return -1;
        paymongo_pending *items = realloc(closes->items, cap * sizeof(*items));
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
static int paymongo_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, paymongo_closes *closes, char **error)
{
    static const char url[] = "https://api.paymongo.com/v1/payment_methods";
    static const char payload[] = "{\"data\":{\"attributes\":{\"type\":\"paymaya\"}}}";
    _Static_assert(sizeof(url) - 1 == 43, "Paymongo URL");
    _Static_assert(sizeof(payload) - 1 == 42, "Paymongo body must stay the static literal");
    *keep = false;
    if (key.len != 32) return paymongo_fail(error, "invalid Paymongo capture");
    /* Drop after the finding exists. No Basic allocation, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack token dies at send return and cannot survive scan-return release.
     * The helper already returns Basic plus one space. Do not add another prefix.
     * The password is empty, so the encoded value is the key plus a colon. */
    char *authorization = NULL;
    char *auth_error = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, &auth_error) != 0) {
        free(auth_error);
        return paymongo_fail(error, "cannot allocate Paymongo authorization");
    }
    free(auth_error);
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it.
         * The body is the static literal. Do not allocate a copy. */
        const br_header headers[] = {
            {"Content-Type", "application/json"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 2,
            .body = {(const unsigned char *)payload, sizeof(payload) - 1},
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
        paymongo_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (paymongo_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        paymongo_forget(authorization);
        return paymongo_fail(error, "cannot retain Paymongo response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else
        result->verified = false;
    *keep = true;
    return 0;
}

static int paymongo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return paymongo_fail(error, "invalid or uninitialized Paymongo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    paymongo_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op for this class. Keep every occurrence, including
     * duplicates, in match order. Do not strip underscores. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32)
            rc = paymongo_fail(&owned_error, "invalid Paymongo capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = paymongo_fail(&owned_error, "cannot create Paymongo finding");
        if (!rc && verify)
            rc = paymongo_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = paymongo_fail(&owned_error, "cannot append Paymongo finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    paymongo_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const paymongo_keywords[] = {"paymongo"};
static br_detector paymongo_detector = {
    .type = 534, .version = 0, .name = "Paymongo", .custom_name = "",
    .description = "PayMongo is a payment processing platform in the Philippines. PayMongo API keys can be used to access and manage payment methods, transactions, and other related data.",
    .keywords = paymongo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = paymongo_scan,
};

int br_paymongo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return paymongo_fail(error, "invalid Paymongo detector output");
    *out = NULL;
    if (!paymongo_detector.state) {
        br_regex *regex = NULL;
        /* Do not hand-expand the prefix or rewrite the source class. */
        if (br_regex_compile_prefixed(paymongo_keywords, 1, "\\b([a-zA-Z0-9_]{32})\\b",
                                      &regex, error) != 0)
            return -1;
        paymongo_detector.state = regex;
    }
    *out = &paymongo_detector;
    return 0;
}
