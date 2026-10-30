/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/tradier/tradier.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { TRADIER_ABORT = -1, TRADIER_KEEP = 0, TRADIER_SKIP = 1 } tradier_outcome;

static int tradier_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static tradier_outcome tradier_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                      char **error)
{
    char authorization[sizeof("Bearer ") + 28];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(authorization)) {
        tradier_fail(error, "cannot format Tradier authorization");
        return TRADIER_ABORT;
    }
    /* Header value is complete before NewRequestWithContext. Nil context skips
     * only this occurrence; the constant URL cannot fail to parse. */
    if (!ctx) return TRADIER_SKIP;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.tradier.com/v1/watchlists",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* SaneHttpClient, default 5s. Do errors and non-2xx stay unverified with
     * no setter. Body is closed and ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return TRADIER_KEEP;
}

static int tradier_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tradier_fail(error, "invalid or uninitialized Tradier scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        tradier_outcome outcome = TRADIER_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            tradier_fail(&owned_error, "cannot create Tradier result");
            outcome = TRADIER_ABORT;
        } else if (verify)
            outcome = tradier_verify(ctx, key, &result, &owned_error);
        if (outcome == TRADIER_ABORT) rc = -1;
        else if (outcome == TRADIER_KEEP && br_results_push(out, &result) != 0) {
            tradier_fail(&owned_error, "cannot append Tradier result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const tradier_keywords[] = {"tradier"};
static br_detector tradier_detector = {
    .type = 372, .version = 0, .name = "Tradier", .custom_name = "",
    .description = "Tradier is a financial services provider that offers a trading platform and API. "
                   "Tradier API keys can be used to access and manage trading accounts and execute trades.",
    .keywords = tradier_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = tradier_scan,
};

int br_tradier_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tradier_fail(error, "invalid Tradier detector output");
    *out = NULL;
    if (br_key_pattern_init(&tradier_detector, "\\b([a-zA-Z0-9]{28})\\b", error) != 0) return -1;
    *out = &tradier_detector;
    return 0;
}
