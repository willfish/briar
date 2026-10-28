/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/etherscan/etherscan.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int etherscan_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool etherscan_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://api.etherscan.io/api?module=account&action=balance&address=0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae&tag=latest&apikey=";
    char url[sizeof(prefix) + 34];
    /* Private captures are exactly 34 URL-safe ASCII bytes. Build the COMPLETE
     * fixed-query URL before context-bound construction, without formatting,
     * escaping, a heap copy or a scanner-local cap. */
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    if (!ctx) return false; /* Constructor failure skips this occurrence. */

    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    bool keep = true;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain and
     * KEEP a false finding. Only successful Do reaches the ReadAll decision. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        /* ReadAll precedes EVERY status/marker decision. Any non-NULL cause,
         * even an empty one, drops the finding instead of keeping it false. */
        if (response.body_error) keep = false;
        else {
            static const unsigned char marker[] = "\"OK\"";
            /* No status gate, JSON parser, case folding or UTF-8/NUL guard. */
            result->verified = br_slice_find(response.body,
                (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        }
    }
    /* Complete URL remains live through BOTH synchronous send and release.
     * Source scan-defers Close after successful Do, before ReadAll. Eager body
     * buffering/release, Reader timing, full native/client/RE2 and global engine/
     * output behavior remain parity gaps. No setter or diagnostic classifier. */
    br_http_release(ctx, &response);
    free(transport_error);
    return keep;
}

static int etherscan_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return etherscan_fail(error, "invalid or uninitialized Etherscan scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve original occurrences, including duplicates. TrimSpace is a no-op
     * for the capture grammar. Finding resources precede URL prep and skips. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = etherscan_fail(&owned_error, "cannot create Etherscan result");
        if (rc == 0 && verify)
            keep = etherscan_verify(ctx, br_captures_at(&keys, i), &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = etherscan_fail(&owned_error, "cannot append Etherscan result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const etherscan_keywords[] = {"etherscan"};
static br_detector etherscan_detector = {
    .type = 905, .version = 0, .name = "Etherscan", .custom_name = "",
    .description = "Etherscan is a Block Explorer and Analytics Platform for Ethereum, a decentralized smart contracts platform. Etherscan API keys can be used to access various functionalities provided by Etherscan.",
    .keywords = etherscan_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = etherscan_scan,
};

int br_etherscan_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return etherscan_fail(error, "invalid Etherscan detector output");
    *out = NULL;
    if (br_key_pattern_init(&etherscan_detector, "\\b([0-9A-Z]{34})\\b", error) != 0)
        return -1;
    *out = &etherscan_detector;
    return 0;
}
