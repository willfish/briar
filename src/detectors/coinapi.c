/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/coinapi/coinapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_coinapi(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Captures own a convenience trailing NUL. Borrow the complete 36 bytes
     * through synchronous send/release, with no heap auth duplication.
     * Header.Add canonicalizes the source X-CoinAPI-Key spelling this way. */
    const br_header headers[] = {{"X-Coinapi-Key", (const char *)key.data}};
    const br_http_request request = {
        .method = "GET", .url = "https://rest.coinapi.io/v1/exchanges",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Source suppresses ALL Do errors. ABI1 mixes adapter setup/allocation
     * failures into this domain; do not classify by diagnostic text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored. Source scan-defers Close ONLY; eager ABI1
     * release/full native client configuration and global parity stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_coinapi(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid CoinApi scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op; preserve occurrences, including duplicates.
         * Finding resources MUST fail before the known nil-context skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create CoinApi result");
        else if (!verify || ctx) {
            if (verify) verify_coinapi(ctx, key, &result);
            if (br_results_push(out, &result)) rc = fail(&owned_error, "cannot append CoinApi result");
        } /* verify && !ctx: source NewRequestWithContext failure skips candidate. */
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"coinapi"};
static br_detector coinapi = {
    .type = 554, .version = 0, .name = "CoinApi", .custom_name = "",
    .description = "CoinApi provides a RESTful API to access cryptocurrency market data. CoinApi keys can be used to fetch real-time and historical cryptocurrency data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_coinapi,
};

int br_coinapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CoinApi detector output");
    *out = NULL;
    /* Broad uppercase/digit/hyphen grammar, NOT UUID/hex/grouping validation. */
    if (br_key_pattern_init(&coinapi, "\\b([A-Z0-9-]{36})\\b", error)) return -1;
    *out = &coinapi;
    return 0;
}
