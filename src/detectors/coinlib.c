/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/coinlib/coinlib.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { COINLIB_ABORT = -1, COINLIB_KEEP = 0, COINLIB_SKIP = 1 } coinlib_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static coinlib_outcome verify_coinlib(const br_scan_ctx *ctx, br_slice key,
                                      br_result *result, char **error)
{
    /* The fixed 16-byte capture needs no escaping. Keep the complete URL and
     * trailing NUL on the stack, borrowed through synchronous send/release. */
    char url[sizeof("https://coinlib.io/api/v1/global?key=") - 1 + 16 + sizeof("&pref=EUR")];
    int n = snprintf(url, sizeof(url), "https://coinlib.io/api/v1/global?key=%.*s&pref=EUR",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        fail(error, "cannot format Coinlib URL");
        return COINLIB_ABORT;
    }
    /* Source formats the URL before NewRequestWithContext's nil-context skip. */
    if (!ctx) return COINLIB_SKIP;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses every Do error. ABI1 combines adapter setup/allocation
     * failures with Do here; never infer stages from diagnostic text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Bodies/read errors are ignored. Source scan-defers Close ONLY; eager
     * buffering/per-request release, full native client and global parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return COINLIB_KEEP;
}

static int scan_coinlib(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Coinlib scan");
    br_captures keys = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        coinlib_outcome outcome = COINLIB_KEEP;
        /* TrimSpace is a no-op for this ASCII grammar. Preserve occurrences,
         * including duplicates, and prepare findings before any constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key")) {
            fail(&owned_error, "cannot create Coinlib result");
            outcome = COINLIB_ABORT;
        }
        if (outcome == COINLIB_KEEP && verify)
            outcome = verify_coinlib(ctx, key, &result, &owned_error);
        if (outcome == COINLIB_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Coinlib result");
            outcome = COINLIB_ABORT;
        }
        br_result_clear(&result);
        if (outcome == COINLIB_ABORT) rc = -1;
    }
    if (rc)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"coinlib"};
static br_detector coinlib = {
    .type = 378, .version = 0, .name = "Coinlib", .custom_name = "",
    .description = "Coinlib is a cryptocurrency data provider. Coinlib API keys can be used to access and retrieve cryptocurrency data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_coinlib,
};

int br_coinlib_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Coinlib detector output");
    *out = NULL;
    if (br_key_pattern_init(&coinlib, "\\b([a-z0-9]{16})\\b", error)) return -1;
    *out = &coinlib;
    return 0;
}
