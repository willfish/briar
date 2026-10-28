/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gtmetrix/gtmetrix.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static int gtmetrix_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int gtmetrix_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                           char **error)
{
    /* The constructor has already succeeded. SetBasicAuth encodes KEY + ':',
     * not KEY alone: 33 plaintext bytes yield 44 unpadded Base64 bytes. */
    unsigned char plaintext[33];
    char authorization[51];
    memcpy(plaintext, key.data, 32);
    plaintext[32] = ':';
    memcpy(authorization, "Basic ", 6);
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, plaintext, 33) != 44)
        return gtmetrix_fail(error, "GTMetrix native Base64 encoding failed");
    authorization[50] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://gtmetrix.com/api/2.0/status",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole shared setup/Do domain, without classifying diagnostics.
     * Source checks status only, so body bytes and read failures are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Only provider-original auth/capture storage survives ordinary send return;
     * ABI1 releases eagerly rather than deferring Close until scan return. */
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int gtmetrix_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return gtmetrix_fail(error, "invalid or uninitialized GTMetrix scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* Preserve occurrences and duplicates. TrimSpace is a grammar no-op. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 32) rc = gtmetrix_fail(&owned_error, "invalid GTMetrix capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = gtmetrix_fail(&owned_error, "cannot create GTMetrix result");
        else if (verify && !ctx) {
            /* Finding allocation precedes constructor failure, which skips this
             * occurrence before SetBasicAuth and its checked native encoder. */
            br_result_clear(&result);
            continue;
        } else if (verify) rc = gtmetrix_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = gtmetrix_fail(&owned_error, "cannot append GTMetrix result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const gtmetrix_keywords[] = {"gtmetrix"};
static br_detector gtmetrix_detector = {
    .type = 763, .version = 0, .name = "GTMetrix", .custom_name = "",
    .description = "GTMetrix provides website performance analytics and monitoring. GTMetrix API keys can be used to access and manage these analytics.",
    .keywords = gtmetrix_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = gtmetrix_scan,
};

int br_gtmetrix_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return gtmetrix_fail(error, "invalid GTMetrix detector output");
    *out = NULL;
    if (br_key_pattern_init(&gtmetrix_detector, "\\b([0-9a-f]{32})\\b", error) != 0)
        return -1;
    *out = &gtmetrix_detector;
    return 0;
}
