/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fmfw/fmfw.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } fmfw_patterns;

static int fmfw_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int fmfw_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                        br_result *result, bool *keep, char **error)
{
    if (!ctx) { *keep = false; return 0; }
    /* AFTER construction: true Basic ID:KEY is exactly 65 ASCII bytes, encoded
     * into 88 standard Base64 bytes. No new codec/API or heap staging/seam. */
    unsigned char credentials[65];
    memcpy(credentials, id.data, 32); credentials[32] = ':'; memcpy(credentials + 33, key.data, 32);
    char authorization[95]; memcpy(authorization, "Basic ", 6);
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, credentials, sizeof(credentials)) != 88)
        return fmfw_fail(error, "FMFW native Base64 encoding failed");
    authorization[94] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.fmfw.io/api/3/spot/balance",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .timeout_ms = 10000, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL;
    /* Source mutates its package client's Timeout before construction. A request
     * override preserves selected 10s evidence, NOT global mutation/race parity.
     * Suppress the WHOLE mixed shared setup/allocation/Do domain, without any
     * setter/classifier. Every 2xx verifies; body/read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete credentials/auth remain in scope through send AND release. Source
     * scan-defers Close; eager buffering/release, full Reader/native client,
     * timeout mutation/concurrency, regexp and global source/engine/output parity
     * remain partial. Never bypass shared guards or run live exchange checks. */
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int fmfw_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fmfw_fail(error, "invalid or uninitialized Fmfw scan");
    const fmfw_patterns *patterns = detector->state;
    size_t original_len = out->len; br_captures keys = {0}, ids = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* IDs have a DIFFERENT grammar and independent regex prefix/backtracking.
     * Do not derive them by filtering key captures. Both lists keep duplicates. */
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i); br_result result = {0}; bool keep = true;
            /* Original key-major occurrence products, including duplicates and
             * self-pairs, never equality skip/verified break/local span cap.
             * TrimSpace is a no-op. ID is REQUIRED but HIDDEN even when verified. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = fmfw_fail(&owned_error, "cannot create Fmfw result");
            if (rc == 0 && verify && fmfw_verify(ctx, key, id, &result, &keep, &owned_error) != 0) rc = -1;
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = fmfw_fail(&owned_error, "cannot append Fmfw result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&ids);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fmfw_keywords[] = {"fmfw"};
static fmfw_patterns fmfw_state;
static br_detector fmfw_detector = {
    .type = 653, .version = 0, .name = "Fmfw", .custom_name = "",
    .description = "FMFW is a cryptocurrency exchange platform. FMFW API keys can be used to access and manage account data and perform trading operations.",
    .keywords = fmfw_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024, .scan = fmfw_scan,
};

int br_fmfw_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fmfw_fail(error, "invalid Fmfw detector output");
    *out = NULL;
    if (!fmfw_detector.state) {
        br_regex *key = NULL, *id = NULL;
        if (br_regex_compile_prefixed(fmfw_keywords, 1, "\\b([a-zA-Z0-9_-]{32})\\b", &key, error) != 0) return -1;
        if (br_regex_compile_prefixed(fmfw_keywords, 1, "\\b([a-zA-Z0-9-]{32})\\b", &id, error) != 0) { br_regex_free(key); return -1; }
        fmfw_state = (fmfw_patterns){key, id}; fmfw_detector.state = &fmfw_state;
    }
    *out = &fmfw_detector;
    return 0;
}
