/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/deepai/deepai.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

typedef enum { DEEPAI_ABORT = -1, DEEPAI_KEEP = 0, DEEPAI_SKIP = 1 } deepai_outcome;

static int deepai_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static deepai_outcome deepai_verify(const br_scan_ctx *ctx, br_slice key,
                                    br_result *result, char **error)
{
    /* The pinned multipart writer draws exactly 30 fresh cryptographic bytes in
     * NewWriter, even when the later context-bound constructor will fail. Its
     * RNG panic becomes an explicit fatal C failure, not a skipped candidate. */
    unsigned char random[30];
    if (RAND_bytes(random, sizeof(random)) != 1) {
        deepai_fail(error, "cannot generate DeepAI multipart boundary");
        return DEEPAI_ABORT;
    }
    static const char hex[] = "0123456789abcdef";
    char boundary[61];
    for (size_t i = 0; i < sizeof(random); ++i) {
        boundary[2 * i] = hex[random[i] >> 4];
        boundary[2 * i + 1] = hex[random[i] & 15];
    }
    boundary[60] = '\0';

    /* Only CreateFormField("text"), literal "test", and Close are needed. The
     * source bytes.Buffer writes cannot return ordinary write errors: build the
     * exact bounded bytes directly, without a MIME framework or failure seams. */
    static const char middle[] = "\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\ntest\r\n--";
    static const char finish[] = "--\r\n";
    unsigned char body[184];
    _Static_assert(2 + 60 + sizeof(middle) - 1 + 60 + sizeof(finish) == sizeof(body),
                   "DeepAI multipart body must be 183 bytes plus NUL");
    size_t at = 0;
    memcpy(body + at, "--", 2); at += 2;
    memcpy(body + at, boundary, 60); at += 60;
    memcpy(body + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(body + at, boundary, 60); at += 60;
    memcpy(body + at, finish, sizeof(finish));

    if (!ctx) return DEEPAI_SKIP; /* Request construction follows complete body preparation. */
    /* FormDataContentType/Header.Add follow successful request construction. */
    static const char type_prefix[] = "multipart/form-data; boundary=";
    char content_type[91];
    _Static_assert(sizeof(type_prefix) - 1 + sizeof(boundary) == sizeof(content_type),
                   "DeepAI multipart Content-Type must be 90 bytes plus NUL");
    memcpy(content_type, type_prefix, sizeof(type_prefix) - 1);
    memcpy(content_type + sizeof(type_prefix) - 1, boundary, sizeof(boundary));

    /* Keep the complete type, body and captured key borrowed through BOTH send
     * and release. body.len supplies logical Content-Length 183 to shared HTTP
     * framing; do not invent a Content-Length header or duplicate the buffers. */
    const br_header headers[] = {{"Content-Type", content_type}, {"Api-Key", (const char *)key.data}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.deepai.org/api/text-tagging",
        .headers = headers, .nheaders = 2, .body = {body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE combined shared setup/allocation/Do error domain,
     * without a verification-error setter or diagnostic-stage classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without reading/draining. Body/read errors
     * never affect status. Eager buffering/release, native POST redirects, full
     * client behavior and global engine/output parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DEEPAI_KEEP;
}

static int deepai_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return deepai_fail(error, "invalid or uninitialized DeepAI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key's verifier cannot express the source constructor skip AFTER
     * RNG/form preparation. Preserve that outcome separately from fatal errors. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        deepai_outcome outcome = DEEPAI_KEEP;
        /* TrimSpace is a no-op. Finding resources precede RNG/form preparation
         * and known constructor skips. Keep all occurrences and duplicates. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            deepai_fail(&owned_error, "cannot create DeepAI result");
            outcome = DEEPAI_ABORT;
        }
        if (outcome == DEEPAI_KEEP && verify)
            outcome = deepai_verify(ctx, key, &result, &owned_error);
        if (outcome == DEEPAI_KEEP && br_results_push(out, &result) != 0) {
            deepai_fail(&owned_error, "cannot append DeepAI result");
            outcome = DEEPAI_ABORT;
        }
        br_result_clear(&result);
        if (outcome == DEEPAI_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const deepai_keywords[] = {"deepai"};
static br_detector deepai_detector = {
    .type = 621, .version = 0, .name = "DeepAI", .custom_name = "",
    .description = "DeepAI is an AI service provider offering various machine learning APIs. DeepAI API keys can be used to access and utilize these services.",
    .keywords = deepai_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = deepai_scan,
};

int br_deepai_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return deepai_fail(error, "invalid DeepAI detector output");
    *out = NULL;
    if (br_key_pattern_init(&deepai_detector, "\\b([a-z0-9-]{36})\\b", error) != 0)
        return -1;
    *out = &deepai_detector;
    return 0;
}
