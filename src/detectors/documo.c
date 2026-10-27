/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/documo/documo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int documo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void documo_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, bool *keep)
{
    /* Known NewRequestWithContext(nil) failure precedes header preparation and
     * skips the candidate, unlike a suppressed Do error which retains it. */
    if (!ctx) { *keep = false; return; }
    /* ABI1 headers are C strings. Preserve the FULL NUL-bearing finding, false
     * with no error, rather than truncating it into an injected success. Source
     * Do rejects the invalid header and suppresses that error. */
    if (memchr(key.data, '\0', key.len)) return;
    /* 237 runes, with only two wildcard runes potentially wider than one byte:
     * max 243 raw bytes, hence 249 literal Basic-header bytes + NUL. No new cap,
     * heap auth copy, Basic encoding, JWT decoding or claim validation. */
    char authorization[250];
    memcpy(authorization, "Basic ", 6);
    memcpy(authorization + 6, key.data, key.len);
    authorization[6 + key.len] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.documo.com/v1/me",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain. Other header
     * controls go through shared validation; no setter or error classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Stack auth lives through send AND release. Source scan-defers Close only
     * and ignores body/read errors. Eager buffering/release, full native client,
     * regexp and global source/engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int documo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return documo_fail(error, "invalid or uninitialized Documo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Both edges are nonspace despite interior wildcard whitespace, so source
     * TrimSpace is a no-op. Keep original byte captures and all occurrences. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = documo_fail(&owned_error, "cannot create Documo result");
        if (rc == 0 && verify) documo_verify(ctx, key, &result, &keep);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = documo_fail(&owned_error, "cannot append Documo result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const documo_keywords[] = {"documo"};
static br_detector documo_detector = {
    .type = 311, .version = 0, .name = "Documo", .custom_name = "",
    .description = "A service for creating and modifying documents. API keys can create read update and delete documents.",
    .keywords = documo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = documo_scan,
};

int br_documo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return documo_fail(error, "invalid Documo detector output");
    *out = NULL;
    if (!documo_detector.state) {
        br_regex *compiled = NULL;
        /* DIRECT pattern: dispatch is separate. Both unescaped dots are ANY
         * valid rune except LF; literals ey remain case-sensitive. Preserve
         * ASCII word boundaries and shared go-re2 invalid-byte barriers. */
        if (br_regex_compile("\\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9]{154}.[a-zA-Z0-9_-]{43})\\b", &compiled, error) != 0)
            return -1;
        documo_detector.state = compiled;
    }
    *out = &documo_detector;
    return 0;
}
