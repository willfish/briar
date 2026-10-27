/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cryptocompare/cryptocompare.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    CRYPTOCOMPARE_ABORT = -1, CRYPTOCOMPARE_KEEP = 0, CRYPTOCOMPARE_SKIP = 1
} cryptocompare_outcome;

static int cryptocompare_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static cryptocompare_outcome cryptocompare_verify(const br_scan_ctx *ctx, br_slice key,
                                                  br_result *result, char **error)
{
    /* The 64-byte ASCII capture needs no escaping. Borrow the complete bounded
     * URL, including its NUL, on the stack through synchronous send AND release. */
    char url[sizeof("https://min-api.cryptocompare.com/data/blockchain/list?api_key=") + 64];
    int n = snprintf(url, sizeof(url), "https://min-api.cryptocompare.com/data/blockchain/list?api_key=%.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        cryptocompare_fail(error, "cannot format CryptoCompare URL");
        return CRYPTOCOMPARE_ABORT;
    }
    /* URL preparation precedes NewRequestWithContext's known nil-context skip. */
    if (!ctx) return CRYPTOCOMPARE_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    cryptocompare_outcome outcome = CRYPTOCOMPARE_KEEP;
    /* Source suppresses every Do error. ABI1 combines setup/allocation and Do
     * failures here; suppress the whole domain without a setter or diagnostic
     * text classifier. A failed send takes precedence over any body error. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error != NULL) {
            /* ReadAll failure drops only this occurrence, at every status. */
            outcome = CRYPTOCOMPARE_SKIP;
        } else {
            static const unsigned char success[] = "\"Response\":\"Success\"";
            bool found = br_slice_find(response.body, (br_slice){success, sizeof(success) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && found;
        }
    }
    /* Source leaks on read failure and scan-defers Close after read success.
     * Always release ABI-owned responses instead. Native streaming/deferred
     * close, full client configuration and global engine/output stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int cryptocompare_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return cryptocompare_fail(error, "invalid or uninitialized CryptoCompare scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        cryptocompare_outcome outcome = CRYPTOCOMPARE_KEEP;
        /* TrimSpace is a no-op. Keep order and duplicates; finding resources
         * must fail before constructor skips or response-body drops. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            cryptocompare_fail(&owned_error, "cannot create CryptoCompare result");
            outcome = CRYPTOCOMPARE_ABORT;
        }
        if (outcome == CRYPTOCOMPARE_KEEP && verify)
            outcome = cryptocompare_verify(ctx, key, &result, &owned_error);
        if (outcome == CRYPTOCOMPARE_KEEP && br_results_push(out, &result) != 0) {
            cryptocompare_fail(&owned_error, "cannot append CryptoCompare result");
            outcome = CRYPTOCOMPARE_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CRYPTOCOMPARE_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const cryptocompare_keywords[] = {"cryptocompare"};
static br_detector cryptocompare_detector = {
    .type = 393, .version = 0, .name = "CryptoCompare", .custom_name = "",
    .description = "CryptoCompare is a cryptocurrency market data provider. CryptoCompare API keys can be used to access and retrieve market data.",
    .keywords = cryptocompare_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = cryptocompare_scan,
};

int br_cryptocompare_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return cryptocompare_fail(error, "invalid CryptoCompare detector output");
    *out = NULL;
    if (br_key_pattern_init(&cryptocompare_detector, "\\b([a-z-0-9]{64})\\b", error) != 0)
        return -1;
    *out = &cryptocompare_detector;
    return 0;
}
