/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/kylas/kylas.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int kylas_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct {
    br_http_response response;
    br_header headers[2];
} kylas_pending;

typedef struct {
    kylas_pending *items;
    size_t len, cap;
} kylas_closes;

static void kylas_release_deferred(const br_scan_ctx *ctx, kylas_closes *closes)
{
    while (closes->len)
        br_http_release(ctx, &closes->items[--closes->len].response);
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

/* Copies only our provider header pointers. The shared prepared request, its
 * header array, and User-Agent die at send return and are not retained. */
static int kylas_defer(kylas_closes *closes, const br_http_response *response,
                       const br_header headers[2])
{
    if (closes->len == closes->cap) {
        if (closes->cap > SIZE_MAX / sizeof(*closes->items) / 2) return -1;
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        kylas_pending *items = realloc(closes->items, cap * sizeof(*items));
        if (!items) return -1;
        closes->items = items;
        closes->cap = cap;
    }
    closes->items[closes->len].response = *response;
    closes->items[closes->len].headers[0] = headers[0];
    closes->items[closes->len].headers[1] = headers[1];
    ++closes->len;
    return 0;
}

/* Header names and the borrowed key must stay alive through send and release.
 * Timeout 0 selects the SANE profile default. Go canonicalizes api-key to Api-Key.
 * Successful Do closes are scan-deferred and released LIFO after publication.
 * Setup/Do failures release immediately; Go has no response to close then. */
static int kylas_verify(const br_scan_ctx *ctx, const char *api_key, int32_t type,
                        br_result *result, kylas_closes *closes, char **error)
{
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Api-Key", api_key},
    };
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.kylas.io/v1/contacts",
        .headers = headers,
        .nheaders = 2,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    free(transport_error);
    /* Source never reads the body. A zero send return verifies solely by
     * status 200-299; body_error does not prevent or clear that. Every other
     * status and the whole mixed setup/Do domain stay unverified. Do not
     * classify diagnostic text or set a verification error. */
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        return 0;
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    if (kylas_defer(closes, &response, headers) != 0) {
        br_http_release(ctx, &response);
        return kylas_fail(error, "cannot retain Kylas response for release");
    }
    return 0;
}

static int kylas_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return kylas_fail(error, "invalid or uninitialized Kylas scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    kylas_closes closes = {0};
    char *owned_error = NULL;
    /* unique=false: duplicates with separate keywords stay in source order.
     * br_scan_key cannot drop a nil-context candidate after finding allocation. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Finding failure is fatal
         * before the constructor skip, send, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = kylas_fail(&owned_error, "cannot create Kylas result");
        else if (!(verify && !ctx)) {
            if (verify && kylas_verify(ctx, keys.items[i], detector->type, &result,
                                       &closes, &owned_error) != 0)
                rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = kylas_fail(&owned_error, "cannot append Kylas result");
        }
        br_result_clear(&result);
    }
    /* Go defers Body.Close until FromData returns, after append, LIFO.
     * Captures and copied provider header pointers remain alive here. */
    kylas_release_deferred(ctx, &closes);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const kylas_keywords[] = {"kylas"};
static br_detector kylas_detector = {
    .type = 272,
    .version = 0,
    .name = "Kylas",
    .custom_name = "",
    .description = "Kylas is a sales CRM platform. Kylas API keys can be used to access and manage sales data.",
    .keywords = kylas_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = kylas_scan,
};

int br_kylas_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return kylas_fail(error, "invalid Kylas detector output");
    *out = NULL;
    if (!kylas_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(kylas_detector.keywords, kylas_detector.nkeywords,
                                      "\\b([a-z0-9-]{36})\\b", &regex, error) != 0)
            return -1;
        kylas_detector.state = regex;
    }
    *out = &kylas_detector;
    return 0;
}
