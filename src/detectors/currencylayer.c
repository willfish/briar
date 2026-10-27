/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/currencylayer/currencylayer.go. */
#include "briar.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    CURRENCYLAYER_ABORT = -1, CURRENCYLAYER_KEEP = 0, CURRENCYLAYER_SKIP = 1
} currencylayer_outcome;

static int currencylayer_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static currencylayer_outcome currencylayer_verify(const br_scan_ctx *ctx, br_slice key,
                                                  br_result *result, char **error)
{
    /* The exact 32-byte ASCII alphanumeric capture needs no escaping. Borrow
     * the complete bounded URL, including its NUL, through send AND release. */
    char url[sizeof("https://api.currencylayer.com/live?access_key=") + 32];
    int n = snprintf(url, sizeof(url), "https://api.currencylayer.com/live?access_key=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        currencylayer_fail(error, "cannot format Currencylayer URL");
        return CURRENCYLAYER_ABORT;
    }
    /* Source formats the URL before the known nil-context constructor skip. */
    if (!ctx) return CURRENCYLAYER_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines setup/allocation and Do failures. Suppress that whole
     * domain, without a setter or diagnostic classifier. Only successful sends
     * reach ReadAll's result; even a non-NULL EMPTY read error retains false. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 &&
        response.body_error == NULL) {
        static const unsigned char success[] = "\"success\": true";
        static const unsigned char restricted[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
        bool valid = br_slice_find(response.body, (br_slice){success, sizeof(success) - 1}, 0) != SIZE_MAX ||
            br_slice_find(response.body, (br_slice){restricted, sizeof(restricted) - 1}, 0) != SIZE_MAX;
        if (response.status >= 200 && response.status < 300) result->verified = valid;
    }
    /* Source scan-defers Close only AFTER ReadAll succeeds, omitting Close on
     * read errors. Always release ABI-owned responses instead. That conditional
     * lifecycle, eager buffering/release, full native SANE configuration and
     * global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return CURRENCYLAYER_KEEP;
}

static int currencylayer_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return currencylayer_fail(error, "invalid or uninitialized Currencylayer scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        currencylayer_outcome outcome = CURRENCYLAYER_KEEP;
        /* TrimSpace is a no-op. Retain all occurrences, including duplicates.
         * Finding resources must precede URL preparation and constructor skips. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            currencylayer_fail(&owned_error, "cannot create Currencylayer result");
            outcome = CURRENCYLAYER_ABORT;
        }
        if (outcome == CURRENCYLAYER_KEEP && verify)
            outcome = currencylayer_verify(ctx, key, &result, &owned_error);
        if (outcome == CURRENCYLAYER_KEEP && br_results_push(out, &result) != 0) {
            currencylayer_fail(&owned_error, "cannot append Currencylayer result");
            outcome = CURRENCYLAYER_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CURRENCYLAYER_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const currencylayer_keywords[] = {"currencylayer"};
static br_detector currencylayer_detector = {
    .type = 354, .version = 0, .name = "Currencylayer", .custom_name = "",
    .description = "An API for converting and exchanging currencies. API keys can read currency data.",
    .keywords = currencylayer_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = currencylayer_scan,
};

int br_currencylayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return currencylayer_fail(error, "invalid Currencylayer detector output");
    *out = NULL;
    if (br_key_pattern_init(&currencylayer_detector, "\\b([a-z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &currencylayer_detector;
    return 0;
}
