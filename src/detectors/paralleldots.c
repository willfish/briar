/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/paralleldots/paralleldots.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

enum { boundary_len = 60, key_len = 43, body_len = 349 };
enum { outcome_keep = 0, outcome_drop = 1, outcome_fatal = -1 };

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return outcome_fatal;
}

static bool contains_intent(br_slice body)
{
    static const char needle[] = "intent";
    if (!body.data || body.len < sizeof(needle) - 1) return false;
    for (size_t i = 0; i + sizeof(needle) - 1 <= body.len; ++i)
        if (!memcmp(body.data + i, needle, sizeof(needle) - 1)) return true;
    return false;
}

/* The pinned writer draws 30 bytes and prints lowercase hex. Build the two
 * fields directly: api_key, then the literal text. Buffer writes cannot fail. */
static char *build_body(const char *key, const char *boundary)
{
    static const char api_header[] =
        "\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\n";
    static const char text_header[] =
        "\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n";
    static const char text[] = "sample text";
    static const char next[] = "\r\n--";
    static const char close[] = "--\r\n";
    _Static_assert(2 + boundary_len + sizeof(api_header) - 1 + key_len + sizeof(next) - 1 +
                       boundary_len + sizeof(text_header) - 1 + sizeof(text) - 1 +
                       sizeof(next) - 1 + boundary_len + sizeof(close) - 1 == body_len,
                   "ParallelDots multipart body must be 349 bytes");
    char *body = malloc(body_len);
    if (!body) return NULL;
    char *p = body;
    memcpy(p, "--", 2); p += 2;
    memcpy(p, boundary, boundary_len); p += boundary_len;
    memcpy(p, api_header, sizeof(api_header) - 1); p += sizeof(api_header) - 1;
    memcpy(p, key, key_len); p += key_len;
    memcpy(p, next, sizeof(next) - 1); p += sizeof(next) - 1;
    memcpy(p, boundary, boundary_len); p += boundary_len;
    memcpy(p, text_header, sizeof(text_header) - 1); p += sizeof(text_header) - 1;
    memcpy(p, text, sizeof(text) - 1); p += sizeof(text) - 1;
    memcpy(p, next, sizeof(next) - 1); p += sizeof(next) - 1;
    memcpy(p, boundary, boundary_len); p += boundary_len;
    memcpy(p, close, sizeof(close) - 1);
    return body;
}

static int verify_candidate(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    if (strlen(key) != key_len) return fail(error, "invalid ParallelDots key");
    unsigned char random[30];
    if (RAND_bytes(random, (int)sizeof(random)) != 1)
        return fail(error, "ParallelDots random boundary failed");
    static const char hex[] = "0123456789abcdef";
    char boundary[boundary_len + 1];
    for (size_t i = 0; i < sizeof(random); ++i) {
        boundary[2 * i] = hex[random[i] >> 4];
        boundary[2 * i + 1] = hex[random[i] & 15];
    }
    boundary[boundary_len] = '\0';
    char *body = build_body(key, boundary);
    if (!body) return fail(error, "out of memory creating ParallelDots body");
    /* NewRequestWithContext follows the completed body. A nil context drops
     * only this candidate. Do not publish the constructor cause. */
    if (!ctx) {
        free(body);
        return outcome_drop;
    }
    static const char type_prefix[] = "multipart/form-data; boundary=";
    char content_type[sizeof(type_prefix) - 1 + boundary_len + 1];
    _Static_assert(sizeof(content_type) == 91, "ParallelDots Content-Type must be 90 bytes plus NUL");
    memcpy(content_type, type_prefix, sizeof(type_prefix) - 1);
    memcpy(content_type + sizeof(type_prefix) - 1, boundary, sizeof(boundary));
    const br_header headers[] = {{"Content-Type", content_type}};
    const br_http_request request = {
        .method = "POST",
        .url = "https://apis.paralleldots.com/v4/intent",
        .headers = headers,
        .nheaders = 1,
        .body = {(const unsigned char *)body, body_len},
        .profile = BR_HTTP_SANE,
        .detector_type = 479,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int outcome = outcome_keep;
    /* Project the body only after Do succeeds, and only while it is still owned. */
    if (send_rc == 0) {
        if (response.body_error)
            outcome = outcome_drop; /* Not fatal; earlier candidates stay. */
        else if (!response.body.data && response.body.len)
            outcome = fail(error, "invalid ParallelDots response body");
        else if (response.status >= 200 && response.status < 300 && contains_intent(response.body))
            result->verified = true;
    }
    br_http_release(ctx, &response); /* One release after every reached send. */
    free(body); /* Borrowed through send and release. */
    free(transport_error); /* A transport diagnostic is not a published cause. */
    return outcome;
}

static int scan_paralleldots(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized ParallelDots scan");

    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* No detector-level dedupe. A repeated key under one keyword is prefix
     * consumption. Capture runs even when verify is set and ctx is NULL. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        int outcome = outcome_keep;
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0) {
            fail(&owned_error, "out of memory creating ParallelDots result");
            outcome = outcome_fatal;
        }
        /* Finding precedes the boundary, the body, and a nil-context drop. */
        if (outcome == outcome_keep && verify)
            outcome = verify_candidate(ctx, keys.items[i], &result, &owned_error);
        if (outcome == outcome_drop) {
            br_result_clear(&result);
            continue;
        }
        if (outcome == outcome_fatal) rc = -1;
        if (rc == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "out of memory appending ParallelDots result");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"paralleldots"};
static br_detector paralleldots = {
    .type = 479, .version = 0, .name = "ParallelDots", .custom_name = "",
    .description = "ParallelDots is an AI service offering various APIs for text analysis. API keys can be used to access these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_paralleldots,
};

int br_paralleldots_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ParallelDots detector output");
    *out = NULL;
    if (br_key_pattern_init(&paralleldots, "\\b([0-9A-Za-z]{43})\\b", error) != 0)
        return -1;
    *out = &paralleldots;
    return 0;
}
