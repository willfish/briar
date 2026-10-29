/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hiveage/hiveage.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef enum { HIVEAGE_ABORT = -1, HIVEAGE_KEEP = 0, HIVEAGE_SKIP = 1 } hiveage_outcome;

static int hiveage_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static hiveage_outcome hiveage_verify(const br_scan_ctx *ctx, br_slice key,
                                      br_result *result, char **error)
{
    /* Exactly 20 ASCII key bytes plus ':': 21 plaintext -> 28 Base64 bytes,
     * without padding. EVP_EncodeBlock also writes a trailing NUL. */
    unsigned char payload[21], encoded[29];
    memcpy(payload, key.data, key.len);
    payload[key.len] = ':';
    if (EVP_EncodeBlock(encoded, payload, (int)sizeof(payload)) != 28) {
        hiveage_fail(error, "Hiveage native Base64 encoding failed");
        return HIVEAGE_ABORT;
    }
    /* EncodeToString precedes NewRequestWithContext; Basic assembly follows it. */
    if (!ctx) return HIVEAGE_SKIP;
    char authorization[35];
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, encoded, 28);
    authorization[34] = '\0';
    const br_header headers[] = {
        {"Accept", "application/json"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://mltb8350.hiveage.com/api/network",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole shared setup/Do domain, not diagnostic categories.
     * Source never reads the body, including body-read errors at any status. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original auth, URL and captures survive synchronous release. Ordinary
     * ABI1 synthesized headers/UA end at send return, not at release. Source
     * defers Close until scan return; this boundary releases each attempt. */
    br_http_release(ctx, &response);
    free(send_error);
    return HIVEAGE_KEEP;
}

static int hiveage_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hiveage_fail(error, "invalid or uninitialized Hiveage scan");
    const br_regex *pattern = *(br_regex *const *)detector->state;
    if (!pattern) return hiveage_fail(error, "uninitialized Hiveage pattern");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(pattern, input, &keys, false, &owned_error);
    /* Preserve source occurrence order and duplicates. TrimSpace is a no-op
     * for this ASCII alphanumeric/underscore/hyphen capture grammar. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        br_result result = {0};
        hiveage_outcome outcome = HIVEAGE_KEEP;
        if (key.len != 20) {
            hiveage_fail(&owned_error, "invalid Hiveage capture"); outcome = HIVEAGE_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            hiveage_fail(&owned_error, "cannot create Hiveage result"); outcome = HIVEAGE_ABORT;
        } else if (verify) outcome = hiveage_verify(ctx, key, &result, &owned_error);
        if (outcome == HIVEAGE_KEEP && br_results_push(out, &result) != 0) {
            hiveage_fail(&owned_error, "cannot append Hiveage result"); outcome = HIVEAGE_ABORT;
        }
        br_result_clear(&result);
        if (outcome == HIVEAGE_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_regex *hiveage_pattern;
static const char *const hiveage_keywords[] = {"hiveage"};
static const br_detector hiveage_detector = {
    .type = 572, .version = 0, .name = "Hiveage", .custom_name = "",
    .description = "Hiveage is an online invoicing and billing software. Hiveage API keys can be used to access and manage invoicing and billing data.",
    .keywords = hiveage_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &hiveage_pattern, .scan = hiveage_scan,
};

int br_hiveage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hiveage_fail(error, "invalid Hiveage detector output");
    *out = NULL;
    if (!hiveage_pattern && br_regex_compile_prefixed(hiveage_keywords, 1,
        "\\b([0-9A-Za-z\\_\\-]{20})\\b", &hiveage_pattern, error) != 0) return -1;
    *out = &hiveage_detector;
    return 0;
}
