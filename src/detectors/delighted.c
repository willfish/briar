/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/delighted/delighted.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    DELIGHTED_ABORT = -1, DELIGHTED_KEEP = 0, DELIGHTED_SKIP = 1
} delighted_outcome;

static int delighted_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static delighted_outcome delighted_verify(const br_scan_ctx *ctx, br_slice key,
                                          br_result *result, char **error)
{
    /* This POST CREATES a customer/survey contact and may trigger outbound
     * communications or automation. Acceptance must use synthetic credentials
     * and injected offline HTTP, never a real customer or service call. */
    unsigned char credentials[33];
    memcpy(credentials, key.data, 32);
    credentials[32] = ':';
    char authorization[51];
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, credentials, sizeof(credentials)) != 44) {
        delighted_fail(error, "Delighted native Base64 encoding failed");
        return DELIGHTED_ABORT;
    }
    /* Exact source raw literal: preserve tabs/spaces, fixed email and absence
     * of a final newline. Both encoding and body preparation precede ctor. */
    static const unsigned char payload[] =
        "{\n"
        "\t\t\t\t\"email\": \"jony@appleseed.com\",\n"
        "\t\t\t\t\"properties\": { \"Purchase Experience\": \"Mobile App\", \"State\": \"CA\" }\n"
        "\t\t\t\t}";
    if (!ctx) return DELIGHTED_SKIP;
    /* Source adds Basic with the headers AFTER the context-bound constructor.
     * 33 ASCII KEY: bytes encode to 44 standard Base64 bytes, with no padding.
     * Keep the complete 50-byte value plus NUL on stack, without a heap copy. */
    memcpy(authorization, "Basic ", 6);
    authorization[50] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.delighted.com/v1/people.json",
        .headers = headers, .nheaders = 2,
        .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE shared setup/allocation/Do domain. Do not classify
     * diagnostic text or set a verification error. No request coalescing. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Auth/body/key stay live through send AND release. Source scan-defers
     * Close only, ignoring bodies/read errors. Eager buffering/release, native
     * POST redirects, full client and global engine/output parity remain gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DELIGHTED_KEEP;
}

static int delighted_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return delighted_fail(error, "invalid or uninitialized Delighted scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key's verifier cannot signal the private constructor skip.
     * Reuse captures/findings while keeping own fatal failures outside Do. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        delighted_outcome outcome = DELIGHTED_KEEP;
        /* TrimSpace is a no-op. Keep all occurrences, without uniqueness,
         * entropy, local false-positive filtering or a persistent cache.
         * Finding resources precede encoding/body prep and any skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            delighted_fail(&owned_error, "cannot create Delighted result");
            outcome = DELIGHTED_ABORT;
        }
        if (outcome == DELIGHTED_KEEP && verify)
            outcome = delighted_verify(ctx, key, &result, &owned_error);
        if (outcome == DELIGHTED_KEEP && br_results_push(out, &result) != 0) {
            delighted_fail(&owned_error, "cannot append Delighted result");
            outcome = DELIGHTED_ABORT;
        }
        br_result_clear(&result);
        if (outcome == DELIGHTED_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const delighted_keywords[] = {"delighted"};
static br_detector delighted_detector = {
    .type = 237, .version = 0, .name = "Delighted", .custom_name = "",
    .description = "Delighted is a customer feedback platform. Delighted API keys can be used to access and manage customer feedback data.",
    .keywords = delighted_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = delighted_scan,
};

int br_delighted_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return delighted_fail(error, "invalid Delighted detector output");
    *out = NULL;
    if (br_key_pattern_init(&delighted_detector, "\\b([a-z0-9A-Z]{32})\\b", error) != 0)
        return -1;
    *out = &delighted_detector;
    return 0;
}
