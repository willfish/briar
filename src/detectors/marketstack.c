/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/marketstack/marketstack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { MS_ABORT = -1, MS_KEEP = 0, MS_SKIP = 1 } marketstack_outcome;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static marketstack_outcome verify_marketstack(const br_scan_ctx *ctx, const char *key,
                                              br_result *result, char **error)
{
    /* Format the full URL before the nil-context constructor failure. */
    char url[96];
    int n = snprintf(url, sizeof(url),
                     "https://api.marketstack.com/v1/eod?access_key=%s&symbols=AAPL", key);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        fail(error, "cannot format Marketstack URL");
        return MS_ABORT;
    }
    if (!ctx) return MS_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Do errors stay unverified with no verification error. Body is ignored. */
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return MS_KEEP;
}

static int scan_marketstack(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Marketstack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        marketstack_outcome outcome = MS_KEEP;
        /* TrimSpace cannot change this lowercase alphanumeric capture. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key")) {
            fail(&owned_error, "cannot create Marketstack result");
            outcome = MS_ABORT;
        } else if (verify)
            outcome = verify_marketstack(ctx, keys.items[i], &result, &owned_error);
        if (outcome == MS_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Marketstack result");
            outcome = MS_ABORT;
        }
        br_result_clear(&result);
        if (outcome == MS_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"marketstack"};
static br_detector marketstack = {
    .type = 363, .version = 0, .name = "Marketstack", .custom_name = "",
    .description = "Marketstack is a service that provides real-time market data. Marketstack API keys can be used to access this data and perform various operations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_marketstack,
};

int br_marketstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Marketstack detector output");
    *out = NULL;
    if (br_key_pattern_init(&marketstack, "\\b([a-z0-9]{32})\\b", error)) return -1;
    *out = &marketstack;
    return 0;
}
