/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/column/column.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static int column_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int column_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    /* Called only after the known request-constructor failure has been skipped.
     * Source SetBasicAuth is commented out: encode KEY ALONE, never KEY + ':'.
     * A 32-byte key yields 44 padded Base64 bytes, one '=', plus Basic and NUL. */
    char authorization[51];
    memcpy(authorization, "Basic ", 6);
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, (const unsigned char *)key, 32) != 44)
        return column_fail(error, "Column native Base64 encoding failed");
    authorization[50] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.column.com/entities",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 749,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ABI1 combines adapter setup/allocation and Do failures. Suppress the whole
     * domain, without error-text classification or a verification-error setter.
     * Provider-owned finding/encoder failures remain fatal, outside this domain. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Keep the stack header live through send AND release. Source scan-defers
     * Close only, without reading/draining. Eager buffering, per-request release
     * and full native client behavior remain partial; body/read errors are ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int column_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return column_fail(error, "invalid or uninitialized Column scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Keep both prefixes, original case and occurrences.
         * Do not apply the CLI's global false-positive list inside the detector. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = column_fail(error, "out of memory creating Column result");
        else if (verify && !ctx) {
            /* Finding resources precede construction. Fixed URL/method and ASCII
             * leave nil context as the known constructor failure; skip it before
             * Base64 preparation, not before owned finding failure handling. */
            br_result_clear(&result);
            continue;
        } else if (verify) rc = column_verify(ctx, keys.items[i], &result, error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = column_fail(error, "out of memory appending Column result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const column_keywords[] = {"column"};
static br_detector column_detector = {
    .type = 749, .version = 0, .name = "Column", .custom_name = "",
    .description = "Column is a service used for managing entity data. "
                   "Column keys can be used to access and modify this data.",
    .keywords = column_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = column_scan,
};

int br_column_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return column_fail(error, "invalid Column detector output");
    *out = NULL;
    if (br_key_pattern_init(&column_detector, "\\b((?:test|live)_[a-zA-Z0-9]{27})\\b", error) != 0) return -1;
    *out = &column_detector;
    return 0;
}
