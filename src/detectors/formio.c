/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/formio/formio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int formio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool formio_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (!ctx) return false; /* Constructor failure SKIPS this occurrence. */
    /* Capture storage already owns the complete trimmed, NUL-terminated token.
     * Borrow it directly AFTER construction, without another header copy. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Jwt-Token", (const char *)key.data}, /* Go canonicalizes x-jwt-token. */
    };
    const br_http_request request = {
        .method = "GET", .url = "https://formio.form.io/current",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain. No
     * verification-error setter, diagnostic classifier or guard bypass. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete token storage stays live through BOTH send and release. Source
     * scan-defers Close after successful Do and ignores body/read/close errors.
     * Eager buffering/release, Reader/close timing, private clients, full native
     * SANE/RE2 and global engine/output behavior remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int formio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return formio_fail(error, "invalid or uninitialized FormIO scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Original occurrences/duplicates, not uniqueness or token validation.
     * The regex consumes the required suffix while exposing trimmed group 1. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = formio_fail(&owned_error, "cannot create FormIO result");
        if (rc == 0 && verify) keep = formio_verify(ctx, br_captures_at(&keys, i), &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = formio_fail(&owned_error, "cannot append FormIO result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const formio_keywords[] = {"formio"};
static br_detector formio_detector = {
    .type = 712, .version = 0, .name = "FormIO", .custom_name = "",
    .description = "FormIO is a platform for building form-based applications. FormIO JWT tokens can be used to authenticate and interact with FormIO services.",
    .keywords = formio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = formio_scan,
};

int br_formio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return formio_fail(error, "invalid FormIO detector output");
    *out = NULL;
    /* Source group 1 ends in EXACTLY ONE required space/CR/LF, then TrimSpace
     * removes that byte. Move ONLY the group boundary: the whole match STILL
     * consumes the suffix, with identical non-overlapping match progression. */
    if (br_key_pattern_init(&formio_detector,
        "\\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[0-9A-Za-z]{220,310}\\.[0-9A-Z-a-z\\-_]{43})[ \\r\\n]{1}", error) != 0)
        return -1;
    *out = &formio_detector;
    return 0;
}
