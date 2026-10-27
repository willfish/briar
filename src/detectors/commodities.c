/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/commodities/commodities.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { COMMOD_ABORT = -1, COMMOD_KEEP = 0, COMMOD_SKIP = 1 } commodities_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static commodities_outcome verify_commodities(const br_scan_ctx *ctx, const char *key,
                                               br_result *result, char **error)
{
    static const char prefix[] = "https://commodities-api.com/api/latest?access_key=";
    char url[sizeof(prefix) + 60]; /* Complete fixed-length capture plus NUL, borrowed through release. */
    int n = snprintf(url, sizeof(url), "%s%s", prefix, key);
    if (n < 0 || (size_t)n >= sizeof(url)) { fail(error, "cannot format Commodities URL"); return COMMOD_ABORT; }
    if (!ctx) return COMMOD_SKIP;
    const br_http_request request = {.method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .timeout_ms = 5000, .detector_type = result->detector_type};
    br_http_response response = {0}; char *transport_error = NULL;
    commodities_outcome outcome = COMMOD_KEEP;
    /* Source mutates client.Timeout to 5s. A request-local 5000ms and core's
     * deadline clamp model the request, not shared mutation/concurrency/config.
     * Do/setup/allocation failure KEEP takes precedence over body_error. */
    if (!br_http_send(ctx, &request, &response, &transport_error)) {
        if (response.body_error != NULL) outcome = COMMOD_SKIP; /* Even an EMPTY error string drops at EVERY status. */
        else {
            static const unsigned char marker[] = "\"success\":true";
            bool valid = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            if (response.status >= 200 && response.status < 300) result->verified = valid;
        }
    }
    /* Source defers Close ONLY after ReadAll succeeds; read error continues
     * without closing. Always release ABI-owned responses, including SKIP:
     * do not emulate a leak or claim eager-buffer/stream/lifecycle parity. */
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int scan_commodities(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Commodities scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; commodities_outcome outcome = COMMOD_KEEP;
        /* TrimSpace is a no-op for the mixed ASCII alphanumeric capture. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key")) {
            fail(&owned_error, "cannot create Commodities result"); outcome = COMMOD_ABORT;
        }
        if (outcome == COMMOD_KEEP && verify) outcome = verify_commodities(ctx, keys.items[i], &result, &owned_error);
        if (outcome == COMMOD_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append Commodities result"); outcome = COMMOD_ABORT;
        }
        br_result_clear(&result); /* Normal constructor/read SKIP drops only this occurrence. */
        if (outcome == COMMOD_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"commodities"};
static br_detector commodities = {
    .type = 566, .version = 0, .name = "Commodities", .custom_name = "",
    .description = "Commodities API keys can be used to access and modify commodity data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_commodities,
};

int br_commodities_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Commodities detector output");
    *out = NULL;
    if (br_key_pattern_init(&commodities, "\\b([a-zA-Z0-9]{60})\\b", error)) return -1;
    *out = &commodities;
    return 0;
}
