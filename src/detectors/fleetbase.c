/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fleetbase/fleetbase.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fleetbase_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void fleetbase_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Called only AFTER successful constructor handling. The source regex
     * bounds the original mixed-case key at 29 bytes: complete Bearer value
     * is 36 bytes plus NUL, with no formatter/copy allocation or extra cap. */
    char authorization[37];
    _Static_assert(7 + 29 + 1 == sizeof(authorization), "Fleetbase Bearer: 36 bytes plus NUL");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.fleetbase.io/v1/contacts/",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain, retaining
     * an ordinary false finding. No setter, error-text classifier or success break. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Bounded stack authorization survives BOTH send and release. Ignore all
     * body/read errors. Source scan-defers Close-only; eager owned release/Reader,
     * native/private-client/error-chain/regexp and global engine/output parity
     * remain partial. Native HTTP guards are unchanged. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int fleetbase_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fleetbase_fail(error, "invalid or uninitialized Fleetbase scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates; genuine
         * owned finding failures precede any nil-context constructor SKIP. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fleetbase_fail(&owned_error, "cannot create Fleetbase finding");
        else if (!verify || ctx) {
            if (verify) fleetbase_verify(ctx, key, &result);
            if (br_results_push(out, &result) != 0) rc = fleetbase_fail(&owned_error, "cannot append Fleetbase finding");
        } /* Constructor continue: no invented append/false result for nil context. */
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const fleetbase_keywords[] = {"fleetbase"};
static br_detector fleetbase_detector = {
    .type = 428, .version = 0, .name = "Fleetbase", .custom_name = "",
    .description = "Fleetbase is a platform for building logistics and supply chain applications. Fleetbase API keys can be used to access and manage logistics data and operations.",
    .keywords = fleetbase_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = fleetbase_scan,
};

int br_fleetbase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fleetbase_fail(error, "invalid Fleetbase detector output");
    *out = NULL;
    if (!fleetbase_detector.state) {
        br_regex *regex = NULL;
        /* fleetbase is DISPATCH ONLY. Direct, case-sensitive token regex: no
         * provider prefix, normalization or additional validation. */
        if (br_regex_compile("\\b(flb_live_[0-9a-zA-Z]{20})\\b", &regex, error) != 0) return -1;
        fleetbase_detector.state = regex;
    }
    *out = &fleetbase_detector;
    return 0;
}
