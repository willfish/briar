/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/currencyfreaks/currencyfreaks.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    CURRENCYFREAKS_ABORT = -1, CURRENCYFREAKS_KEEP = 0, CURRENCYFREAKS_SKIP = 1
} currencyfreaks_outcome;

static int currencyfreaks_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static currencyfreaks_outcome currencyfreaks_verify(const br_scan_ctx *ctx, br_slice key,
                                                   br_result *result, char **error)
{
    /* The bounded ASCII capture needs no URL escaping. Keep the complete URL,
     * including its trailing NUL, live through synchronous send AND release. */
    char url[sizeof("https://api.currencyfreaks.com/latest?apikey=&format=xml") + 32];
    int n = snprintf(url, sizeof(url), "https://api.currencyfreaks.com/latest?apikey=%.*s&format=xml",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        currencyfreaks_fail(error, "cannot format Currencyfreaks URL");
        return CURRENCYFREAKS_ABORT;
    }
    /* Source prepares the URL before NewRequestWithContext's known skip. */
    if (!ctx) return CURRENCYFREAKS_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = 499,
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
    return CURRENCYFREAKS_KEEP;
}

static int currencyfreaks_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return currencyfreaks_fail(error, "invalid or uninitialized Currencyfreaks scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        currencyfreaks_outcome outcome = CURRENCYFREAKS_KEEP;
        /* TrimSpace is a no-op. Keep every occurrence, including duplicates.
         * Finding resources precede URL preparation and constructor skipping. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            currencyfreaks_fail(&owned_error, "cannot create Currencyfreaks result");
            outcome = CURRENCYFREAKS_ABORT;
        }
        if (outcome == CURRENCYFREAKS_KEEP && verify)
            outcome = currencyfreaks_verify(ctx, key, &result, &owned_error);
        if (outcome == CURRENCYFREAKS_KEEP && br_results_push(out, &result) != 0) {
            currencyfreaks_fail(&owned_error, "cannot append Currencyfreaks result");
            outcome = CURRENCYFREAKS_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CURRENCYFREAKS_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const currencyfreaks_keywords[] = {"currencyfreaks"};
static br_detector currencyfreaks_detector = {
    .type = 499, .version = 0, .name = "Currencyfreaks", .custom_name = "",
    .description = "Currencyfreaks provides exchange rates and currency conversion API services. The API keys can be used to access and retrieve exchange rate data.",
    .keywords = currencyfreaks_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = currencyfreaks_scan,
};

int br_currencyfreaks_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return currencyfreaks_fail(error, "invalid Currencyfreaks detector output");
    *out = NULL;
    if (br_key_pattern_init(&currencyfreaks_detector, "\\b([0-9a-z]{32})\\b", error) != 0)
        return -1;
    *out = &currencyfreaks_detector;
    return 0;
}
