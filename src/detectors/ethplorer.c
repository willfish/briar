/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ethplorer/ethplorer.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int ethplorer_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is constructor skip, NOT verification rejection. All shared send
 * setup/allocation/Do failures retain the original false finding instead. */
static bool ethplorer_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* This verifier CREATES a remote monitoring pool, mutating provider state
     * and consuming resources. Acceptance is injected/offline only, never a
     * real pool/blockchain/account/provider request or DNS action. */
    static const char prefix[] = "apiKey=";
    static const char suffix[] = "&addresses=0xb2930b35844a230f00e51431acae96fe543a0347%2C0xb52d3141ee731fac89927476c6a5207b37cd72ff";
    /* Complete literal form precedes construction. Captures are exactly 22
     * unreserved ASCII bytes: no encoder, serializer, heap copy or formatter. */
    char payload[sizeof(prefix) - 1 + 22 + sizeof(suffix)];
    _Static_assert(sizeof(payload) == 128, "Ethplorer form is 127 bytes plus NUL");
    memcpy(payload, prefix, sizeof(prefix) - 1);
    memcpy(payload + sizeof(prefix) - 1, key.data, 22);
    memcpy(payload + sizeof(prefix) - 1 + 22, suffix, sizeof(suffix));
    if (!ctx) return false;
    const br_header headers[] = {
        {"Accept", "application/json"}, /* Source Header.Add("accept") canonicalizes its name. */
        {"Content-Type", "application/x-www-form-urlencoded"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api-mon.ethplorer.io/createPool",
        .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Ignore all bodies/read errors, even empty non-NULL errors. Suppress the
     * WHOLE mixed shared setup/allocation/Do domain without setters or text
     * classification. An unsuccessful Do never becomes a constructor skip. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack body lives through synchronous send AND release. Source
     * scan-defers Close only after successful Do; ABI1 eagerly buffers/releases
     * even failed sends. Full Reader/deferred-close/native POST redirects,
     * client/regexp and global source/engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int ethplorer_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ethplorer_fail(error, "invalid or uninitialized Ethplorer scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Preserve occurrences/duplicates, with no token
         * validation, local filtering or cache. Finding failures precede form
         * preparation, constructor skips and suppressed verification failures. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ethplorer_fail(&owned_error, "cannot create Ethplorer result");
        if (rc == 0 && verify) keep = ethplorer_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = ethplorer_fail(&owned_error, "cannot append Ethplorer result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ethplorer_keywords[] = {"ethplorer"};
static br_detector ethplorer_detector = {
    .type = 283, .version = 0, .name = "Ethplorer", .custom_name = "",
    .description = "Ethplorer API keys can be used to interact with the Ethplorer service, which provides access to Ethereum blockchain data and analytics.",
    .keywords = ethplorer_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ethplorer_scan,
};

int br_ethplorer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ethplorer_fail(error, "invalid Ethplorer detector output");
    *out = NULL;
    /* Hyphen is a captured nonword byte. Preserve source word boundaries,
     * including external word neighbors, not a full-token delimiter policy. */
    if (br_key_pattern_init(&ethplorer_detector, "\\b([a-z0-9A-Z-]{22})\\b", error) != 0) return -1;
    *out = &ethplorer_detector;
    return 0;
}
