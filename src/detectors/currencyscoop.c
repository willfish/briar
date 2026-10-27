/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/currencyscoop/currencyscoop.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    CURRENCYSCOOP_ABORT = -1, CURRENCYSCOOP_KEEP = 0, CURRENCYSCOOP_SKIP = 1
} currencyscoop_outcome;

static int currencyscoop_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static currencyscoop_outcome currencyscoop_verify(const br_scan_ctx *ctx, br_slice key,
                                                 br_result *result, char **error)
{
    /* The bounded ASCII capture needs no escaping. Keep the complete stack URL,
     * including its trailing NUL, live through synchronous send AND release. */
    char url[sizeof("https://api.currencyscoop.com/v1/latest?api_key=") + 32];
    int n = snprintf(url, sizeof(url), "https://api.currencyscoop.com/v1/latest?api_key=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        currencyscoop_fail(error, "cannot format CurrencyScoop URL");
        return CURRENCYSCOOP_ABORT;
    }
    /* Source formats the URL before NewRequestWithContext's known skip. */
    if (!ctx) return CURRENCYSCOOP_SKIP;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 380,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses all Do errors. ABI1 combines shared setup/allocation
     * and Do failures; suppress that entire domain without classifying causes
     * or invoking a verification-error setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers close-only, never reading/draining. Bodies/read errors
     * cannot change the status decision. Eager buffering/release, full native
     * client behavior and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return CURRENCYSCOOP_KEEP;
}

static int currencyscoop_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return currencyscoop_fail(error, "invalid or uninitialized CurrencyScoop scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        currencyscoop_outcome outcome = CURRENCYSCOOP_KEEP;
        /* TrimSpace is a no-op. Keep every occurrence, including duplicates.
         * Finding resources precede URL formatting and constructor skipping. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            currencyscoop_fail(&owned_error, "cannot create CurrencyScoop result");
            outcome = CURRENCYSCOOP_ABORT;
        }
        if (outcome == CURRENCYSCOOP_KEEP && verify)
            outcome = currencyscoop_verify(ctx, key, &result, &owned_error);
        if (outcome == CURRENCYSCOOP_KEEP && br_results_push(out, &result) != 0) {
            currencyscoop_fail(&owned_error, "cannot append CurrencyScoop result");
            outcome = CURRENCYSCOOP_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CURRENCYSCOOP_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const currencyscoop_keywords[] = {"currencyscoop"};
static br_detector currencyscoop_detector = {
    .type = 380, .version = 0, .name = "CurrencyScoop", .custom_name = "",
    .description = "CurrencyScoop is a currency data service providing real-time and historical exchange rates. CurrencyScoop API keys can be used to access currency data.",
    .keywords = currencyscoop_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = currencyscoop_scan,
};

int br_currencyscoop_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return currencyscoop_fail(error, "invalid CurrencyScoop detector output");
    *out = NULL;
    if (br_key_pattern_init(&currencyscoop_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &currencyscoop_detector;
    return 0;
}
