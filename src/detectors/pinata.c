/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pinata/pinata.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *key, *id;
} pinata_patterns;

typedef enum { PINATA_ABORT = -1, PINATA_KEEP = 0, PINATA_SKIP = 1 } pinata_outcome;

static int pinata_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static pinata_outcome pinata_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                                    br_result *result, char **error)
{
    static const unsigned char payload[] =
        "{\"pinataMetadata\": {\"name\": \"ItemStatus\",\"keyvalues\": {\"ItemID\": \"Item001\","
        "\"CheckpointID\": \"Checkpoint002\",\"Source\": \"CompanyA\",\"WeightInKilos\": 5.25}},"
        "\"pinataContent\": {\"itemName\": \"exampleItemName\",\"inspectedBy\": \"Inspector001\","
        "\"dataValues\": []}}";
    char secret[65], api_id[21];
    if (key.len != 64 || id.len != 20) {
        pinata_fail(error, "cannot format Pinata credentials");
        return PINATA_ABORT;
    }
    memcpy(secret, key.data, 64);
    secret[64] = '\0';
    memcpy(api_id, id.data, 20);
    api_id[20] = '\0';
    /* Body is complete before NewRequestWithContext. A nil context continues,
     * dropping only this key/id pair. */
    if (!ctx) return PINATA_SKIP;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"pinata_api_key", api_id},
        {"pinata_secret_api_key", secret},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.pinata.cloud/pinning/pinJSONToIPFS",
        .headers = headers, .nheaders = 3, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 10000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source sets the shared sane client's Timeout to 10s and ignores Do errors.
     * Only 2xx verifies. The id is a verification header, not a secret part. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return PINATA_KEEP;
}

static int pinata_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const pinata_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->key || !patterns->id || !out ||
        (!input.data && input.len))
        return pinata_fail(error, "invalid or uninitialized Pinata scan");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        for (size_t j = 0; rc == 0 && j < ids.len; ++j) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, i);
            pinata_outcome outcome = PINATA_KEEP;
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
                pinata_fail(&owned_error, "cannot create Pinata result");
                outcome = PINATA_ABORT;
            } else if (verify)
                outcome = pinata_verify(ctx, key, br_captures_at(&ids, j), &result, &owned_error);
            if (outcome == PINATA_ABORT) rc = -1;
            else if (outcome == PINATA_KEEP && br_results_push(out, &result) != 0) {
                pinata_fail(&owned_error, "cannot append Pinata result");
                rc = -1;
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pinata_keywords[] = {"pinata"};
static pinata_patterns pinata_state;
static br_detector pinata_detector = {
    .type = 755, .version = 0, .name = "Pinata", .custom_name = "",
    .description = "Pinata is a service for managing files on IPFS. "
                   "Pinata API keys can be used to pin and manage files on the IPFS network.",
    .keywords = pinata_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = pinata_scan,
};

int br_pinata_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pinata_fail(error, "invalid Pinata detector output");
    *out = NULL;
    if (!pinata_state.key &&
        br_regex_compile_prefixed(pinata_keywords, 1, "\\b([0-9a-z]{64})\\b",
                                  &pinata_state.key, error) != 0)
        return -1;
    if (!pinata_state.id &&
        br_regex_compile_prefixed(pinata_keywords, 1, "\\b([0-9a-z]{20})\\b",
                                  &pinata_state.id, error) != 0)
        return -1;
    pinata_detector.state = &pinata_state;
    *out = &pinata_detector;
    return 0;
}
