/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/paystack/paystack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int paystack_fail(char **error, const char *message)
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
} paystack_pending;

typedef struct {
    paystack_pending *items;
    size_t len, cap;
} paystack_closes;

/* After this attempt's release, the token must not remain readable. */
static void paystack_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void paystack_release_deferred(const br_scan_ctx *ctx, paystack_closes *closes)
{
    while (closes->len) {
        paystack_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        paystack_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int paystack_defer(paystack_closes *closes, const br_http_response *response,
                          char *authorization)
{
    if (closes->len == closes->cap) {
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        if (cap < closes->cap || cap > SIZE_MAX / sizeof(*closes->items)) return -1;
        paystack_pending *items = realloc(closes->items, cap * sizeof(*items));
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
static int paystack_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           bool *keep, paystack_closes *closes, char **error)
{
    static const char url[] = "https://api.paystack.co/customer";
    _Static_assert(sizeof(url) - 1 == 32, "Paystack URL");
    *keep = false;
    /* Drop after the finding exists. No Authorization, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack token dies at send return and cannot survive scan-return release.
     * The value is Bearer, one space, and the raw key. */
    if (key.len > SIZE_MAX - 8)
        return paystack_fail(error, "cannot allocate Paystack authorization");
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization)
        return paystack_fail(error, "cannot allocate Paystack authorization");
    memcpy(authorization, "Bearer ", 7);
    if (key.len) memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it.
         * Authorization is the only provider header. */
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
        paystack_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (paystack_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        paystack_forget(authorization);
        return paystack_fail(error, "cannot retain Paystack response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else
        result->verified = false;
    *keep = true;
    return 0;
}

static int paystack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return paystack_fail(error, "invalid or uninitialized Paystack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    paystack_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * The pattern is not prefixed. TrimSpace is a no-op for this class. Keep
     * every occurrence, including duplicates, in match order. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = paystack_fail(&owned_error, "cannot create Paystack finding");
        if (!rc && verify)
            rc = paystack_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = paystack_fail(&owned_error, "cannot append Paystack finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    paystack_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const paystack_keywords[] = {"paystack"};
static br_detector paystack_detector = {
    .type = 77, .version = 0, .name = "Paystack", .custom_name = "",
    .description = "Paystack is a payment processing service. Paystack API keys can be used to access and manage payment transactions and customer data.",
    .keywords = paystack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = paystack_scan,
};

int br_paystack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return paystack_fail(error, "invalid Paystack detector output");
    *out = NULL;
    if (!paystack_detector.state) {
        br_regex *regex = NULL;
        /* Direct source pattern. Do not prefix paystack and do not add a live-key pattern. */
        if (br_regex_compile("\\b(sk\\_[a-z]{1,}\\_[A-Za-z0-9]{40})\\b", &regex, error) != 0)
            return -1;
        paystack_detector.state = regex;
    }
    *out = &paystack_detector;
    return 0;
}
