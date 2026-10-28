/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/enablex/enablex.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } enablex_patterns;

static int enablex_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int enablex_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                          br_result *result, char **error)
{
    /* Constructor's known nil-context skip has already passed. Encode ID:KEY,
     * not KEY:ID: 61 bytes -> 84 Base64 -> 90 auth bytes and the trailing NUL. */
    char *authorization = NULL;
    if (br_http_basic_auth(id, key, &authorization, error) != 0) return -1;
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api.enablex.io/voice/v1/call",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain without a
     * setter or diagnostic classifier; retain failed-send findings as false.
     * Every 2xx verifies regardless of body contents or read errors. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Borrow the complete owned Basic value through send AND release, freeing
     * it only afterwards. Source scan-defers Close only; eager Reader/release,
     * full native client, regexp and global engine/output remain partial. */
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return 0;
}

static int enablex_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return enablex_fail(error, "invalid or uninitialized Enablex scan");
    const enablex_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return enablex_fail(error, "uninitialized Enablex patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent key-major occurrence products, including duplicates. No
     * equality filter, success consumption or local restriction from span1024.
     * TrimSpace is a no-op for both original captured alphabets. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            /* ID is required for this product but HIDDEN even when verified:
             * only Raw=KEY and SecretParts.key are projected into the finding. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = enablex_fail(&owned_error, "cannot create Enablex result");
            /* Own finding resources precede constructor skip; Basic/header
             * preparation occurs only afterwards, with no artificial append. */
            if (rc == 0 && (!verify || ctx)) {
                if (verify) rc = enablex_verify(ctx, key, br_captures_at(&ids, i), &result, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = enablex_fail(&owned_error, "cannot append Enablex result");
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids); br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static enablex_patterns enablex_compiled;
static const char *const enablex_keywords[] = {"enablex"};
static const br_detector enablex_detector = {
    .type = 652, .version = 0, .name = "Enablex", .custom_name = "",
    .description = "Enablex is a communication platform offering voice, video, and messaging APIs. Enablex credentials can be used to access and manage communication services provided by Enablex.",
    .keywords = enablex_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &enablex_compiled, .scan = enablex_scan,
};

int br_enablex_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return enablex_fail(error, "invalid Enablex detector output");
    *out = NULL;
    if (!enablex_compiled.key && br_regex_compile_prefixed(enablex_keywords, 1,
            "\\b([a-zA-Z0-9]{36})\\b", &enablex_compiled.key, error) != 0) return -1;
    if (!enablex_compiled.id && br_regex_compile_prefixed(enablex_keywords, 1,
            "\\b([a-z0-9]{24})\\b", &enablex_compiled.id, error) != 0) return -1;
    *out = &enablex_detector;
    return 0;
}
