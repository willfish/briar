/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/convier/convier.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { CONVIER_KEY_BYTES = 43 };
typedef enum { CONVIER_ABORT = -1, CONVIER_KEEP = 0, CONVIER_SKIP = 1 } convier_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static convier_outcome verify_convier(const br_scan_ctx *ctx, const char *key,
                                      br_result *result, char **error)
{
    /* Complete fixed-length capture plus NUL, borrowed through send AND release.
     * The caller handles the nil-context constructor skip before auth preparation. */
    char authorization[sizeof("Bearer ") + CONVIER_KEY_BYTES];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization)) {
        fail(error, "cannot format Convier authorization");
        return CONVIER_ABORT;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    /* Source POSTs a nil body; verification can create/manage remote event data. */
    const br_http_request request = {
        .method = "POST", .url = "https://convier.me/api/event",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .timeout_ms = 10000, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    convier_outcome outcome = CONVIER_KEEP;
    /* Source mutates shared client.Timeout to 10s. Request-local 10000ms plus
     * core's deadline clamp do not reproduce mutation/concurrency/config state.
     * Suppress the whole shared setup/allocation/Do failure domain, without
     * classifying diagnostic text: failed send KEEP outranks body_error DROP. */
    if (!br_http_send(ctx, &request, &response, &transport_error)) {
        if (response.body_error != NULL) outcome = CONVIER_SKIP;
        else {
            static const unsigned char marker[] = "\"error\":false";
            bool valid = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && valid;
        }
    }
    /* Source defers Close only after ReadAll succeeds, leaking on read-error
     * continue. Always release ABI responses, including failures and skips.
     * Eager buffering/lifecycle and native POST redirects/full-client parity
     * remain outside this detector's injected first-request contract. */
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int scan_convier(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Convier scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; convier_outcome outcome = CONVIER_KEEP;
        /* TrimSpace is a no-op for this ASCII capture. Preserve leading zeros,
         * the literal pipe and every occurrence, without local filtering. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key")) {
            fail(&owned_error, "cannot create Convier result"); outcome = CONVIER_ABORT;
        } else if (verify) {
            outcome = ctx ? verify_convier(ctx, keys.items[i], &result, &owned_error) : CONVIER_SKIP;
        }
        if (outcome == CONVIER_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Convier result"); outcome = CONVIER_ABORT;
        }
        br_result_clear(&result); /* Constructor/read skips drop only this occurrence. */
        if (outcome == CONVIER_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"convier"};
static br_detector convier = {
    .type = 664, .version = 0, .name = "Convier", .custom_name = "",
    .description = "Convier is a service for managing and verifying event data. Convier keys can be used to interact with the Convier API to manage event data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_convier,
};

int br_convier_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Convier detector output");
    *out = NULL;
    /* Only PrefixRegex's keyword is case-insensitive. */
    if (br_key_pattern_init(&convier, "\\b([0-9]{2}\\|[a-zA-Z0-9]{40})\\b", error)) return -1;
    *out = &convier;
    return 0;
}
