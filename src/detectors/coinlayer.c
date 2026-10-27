/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/coinlayer/coinlayer.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { LAYER_ABORT = -1, LAYER_KEEP = 0, LAYER_SKIP = 1 } coinlayer_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static coinlayer_outcome verify_coinlayer(const br_scan_ctx *ctx, const char *key,
                                           br_result *result, char **error)
{
    /* Preserve source's literal "livelive". The capture is exactly 32 ASCII
     * bytes; this complete URL plus NUL stays borrowed through release. */
    static const char prefix[] = "https://api.coinlayer.com/api/livelive?access_key=";
    char url[sizeof(prefix) + 32];
    int n = snprintf(url, sizeof(url), "%s%s", prefix, key);
    if (n < 0 || (size_t)n >= sizeof(url)) { fail(error, "cannot format Coinlayer URL"); return LAYER_ABORT; }
    if (!ctx) return LAYER_SKIP; /* Source formats before the known nil-context constructor failure. */
    const br_http_request request = {.method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = result->detector_type};
    br_http_response response = {0}; char *transport_error = NULL;
    /* ALL combined adapter setup/allocation + Do errors retain false/nil.
     * ReadAll's error takes priority before status, including an EMPTY error
     * string: pointer presence, not message content, represents failure. */
    if (!br_http_send(ctx, &request, &response, &transport_error) && response.body_error == NULL) {
        static const unsigned char success[] = "\"success\": true";
        static const unsigned char restricted[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
        bool valid = br_slice_find(response.body, (br_slice){success, sizeof(success) - 1}, 0) != SIZE_MAX ||
            br_slice_find(response.body, (br_slice){restricted, sizeof(restricted) - 1}, 0) != SIZE_MAX;
        if (response.status >= 200 && response.status < 300) result->verified = valid;
    }
    /* Source defers Close ONLY after ReadAll succeeds (not on read error).
     * Always release ABI-owned responses: do not emulate that leak. Eager
     * buffering/per-request release cannot establish source lifecycle parity. */
    br_http_release(ctx, &response);
    free(transport_error);
    return LAYER_KEEP;
}

static int scan_coinlayer(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Coinlayer scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; coinlayer_outcome outcome = LAYER_KEEP;
        /* TrimSpace cannot change this lowercase ASCII alphanumeric capture. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key")) {
            fail(&owned_error, "cannot create Coinlayer result"); outcome = LAYER_ABORT;
        }
        if (outcome == LAYER_KEEP && verify) outcome = verify_coinlayer(ctx, keys.items[i], &result, &owned_error);
        if (outcome == LAYER_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Coinlayer result"); outcome = LAYER_ABORT;
        }
        br_result_clear(&result);
        if (outcome == LAYER_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"coinlayer"};
static br_detector coinlayer = {
    .type = 402, .version = 0, .name = "Coinlayer", .custom_name = "",
    .description = "Coinlayer provides real-time and historical cryptocurrency exchange rates. The API key can be used to access this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_coinlayer,
};

int br_coinlayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Coinlayer detector output");
    *out = NULL;
    if (br_key_pattern_init(&coinlayer, "\\b([a-z0-9]{32})\\b", error)) return -1;
    *out = &coinlayer;
    return 0;
}
