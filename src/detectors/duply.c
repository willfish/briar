/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/duply/duply.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } duply_patterns;

static int duply_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int duply_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                        br_result *result, char **error)
{
    /* Caller has passed the known nil-context constructor skip. Encode ID:KEY,
     * not KEY:ID: 68 bytes -> 92 Base64 -> 98 auth bytes plus its NUL. */
    char *authorization = NULL;
    if (br_http_basic_auth(id, key, &authorization, error) != 0) return -1;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://gen.duply.co/v1/usage",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .timeout_ms = 10000, .detector_type = result->detector_type,
    };
    /* Source mutates its shared client's Timeout to 10s, even before a failed
     * constructor. Only this request's override is represented: persistent
     * mutation/races are a gap, never a reason to change global engine policy. */
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without a
     * verification-error setter or diagnostic classifier. Body/read errors
     * cannot affect the status decision. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Borrow the complete owned Basic value through send AND release. Source
     * scan-defers Close only; eager buffering/release, native client, regexp
     * and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    return 0;
}

static int duply_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return duply_fail(error, "invalid or uninitialized Duply scan");
    const duply_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return duply_fail(error, "uninitialized Duply patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Independent key-major occurrence products, duplicates included. Neither
     * the span hint nor successful verification consumes or limits pairings.
     * TrimSpace is a no-op for both captured alphabets. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            /* ID is REQUIRED to form this product, but intentionally HIDDEN:
             * Raw and SecretParts expose only key, even after verification. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = duply_fail(&owned_error, "cannot create Duply result");
            /* Finding resources precede constructor skip; Basic preparation
             * occurs only after it. Do not append/clear to emulate the skip. */
            if (rc == 0 && (!verify || ctx)) {
                if (verify) rc = duply_verify(ctx, key, br_captures_at(&ids, i), &result, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = duply_fail(&owned_error, "cannot append Duply result");
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

static duply_patterns duply_compiled;
static const char *const duply_keywords[] = {"duply"};
static const br_detector duply_detector = {
    .type = 821, .version = 0, .name = "Duply", .custom_name = "",
    .description = "An API for generating images. API keys can fetch and create images.",
    .keywords = duply_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &duply_compiled, .scan = duply_scan,
};

int br_duply_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return duply_fail(error, "invalid Duply detector output");
    *out = NULL;
    if (!duply_compiled.key && br_regex_compile_prefixed(duply_keywords, 1,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
            &duply_compiled.key, error) != 0) return -1;
    if (!duply_compiled.id && br_regex_compile_prefixed(duply_keywords, 1,
            "\\b([0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7})\\b",
            &duply_compiled.id, error) != 0) return -1;
    *out = &duply_detector;
    return 0;
}
