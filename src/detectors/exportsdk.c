/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/exportsdk/exportsdk.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } exportsdk_patterns;

static int exportsdk_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void exportsdk_verify(const br_scan_ctx *ctx, const char *key,
                             const char body[57], br_result *result)
{
    /* Constructor's known nil-context skip precedes headers. Borrow the entire
     * original key capture and complete stack body through send AND release. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Api-Key", key}, /* Go Header.Add canonicalizes source X-API-KEY. */
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.exportsdk.com/v1/pdf",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .body = {(const unsigned char *)body, 56}, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, retaining a
     * false finding without setter/classifier. Every successful-send 2xx verifies
     * regardless of body contents or read error. This endpoint generates PDFs;
     * tests must use injected transport, not live verification. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only. Eager Reader/release timing, native/private
     * client, regexp and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int exportsdk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return exportsdk_fail(error, "invalid or uninitialized ExportSDK scan");
    const exportsdk_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return exportsdk_fail(error, "uninitialized ExportSDK patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Original key-major occurrence products, duplicates and hyphen-boundary ID
     * fragments included. No UUID validation, sets, local span cap or success
     * break. TrimSpace is a no-op for both captured alphabets. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, k), "key") != 0)
                rc = exportsdk_fail(&owned_error, "cannot create ExportSDK result");
            char body[57];
            if (rc == 0 && verify) {
                /* Finding THEN literal body BEFORE constructor skip. Fixed ID36
                 * permits bounded assembly; no serializer/encoder/heap copy. */
                memcpy(body, "{  \"templateId\": \"", 18);
                memcpy(body + 18, ids.items[i], 36);
                memcpy(body + 54, "\"}", 3);
            }
            /* ID is required but HIDDEN, even verified: Raw/key ONLY. */
            if (rc == 0 && (!verify || ctx)) {
                if (verify) exportsdk_verify(ctx, keys.items[k], body, &result);
                if (br_results_push(out, &result) != 0)
                    rc = exportsdk_fail(&owned_error, "cannot append ExportSDK result");
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

static exportsdk_patterns exportsdk_compiled;
static const char *const exportsdk_keywords[] = {"exportsdk"};
static const br_detector exportsdk_detector = {
    .type = 771, .version = 0, .name = "ExportSDK", .custom_name = "",
    .description = "ExportSDK is a service used for exporting data and generating PDFs. ExportSDK keys can be used to authenticate API requests and generate documents.",
    .keywords = exportsdk_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &exportsdk_compiled, .scan = exportsdk_scan,
};

int br_exportsdk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return exportsdk_fail(error, "invalid ExportSDK detector output");
    *out = NULL;
    if (!exportsdk_compiled.key && br_regex_compile_prefixed(exportsdk_keywords, 1,
            "\\b([0-9a-z]{5,15}_[0-9a-z-]{36})\\b", &exportsdk_compiled.key, error) != 0) return -1;
    if (!exportsdk_compiled.id && br_regex_compile_prefixed(exportsdk_keywords, 1,
            "\\b([0-9a-z-]{36})\\b", &exportsdk_compiled.id, error) != 0) return -1;
    *out = &exportsdk_detector;
    return 0;
}
