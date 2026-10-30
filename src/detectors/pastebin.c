/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pastebin/pastebin.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

enum { PASTE_BOUNDARY = 60, PASTE_KEY = 32, PASTE_BODY = 469 };
enum { PASTE_KEEP = 0, PASTE_DROP = 1, PASTE_FATAL = -1 };

static int pastebin_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return PASTE_FATAL;
}

/* mime/multipart draws 30 bytes and prints lowercase hex. Field writes and
 * Close cannot fail for these literal values; Close's error is ignored. */
static char *pastebin_body(const char *key, const char *boundary)
{
    static const char dev[] = "Content-Disposition: form-data; name=\"api_dev_key\"\r\n\r\n";
    static const char code[] = "Content-Disposition: form-data; name=\"api_paste_code\"\r\n\r\n";
    static const char option[] = "Content-Disposition: form-data; name=\"api_option\"\r\n\r\n";
    _Static_assert(sizeof(dev) - 1 == 54 && sizeof(code) - 1 == 57 && sizeof(option) - 1 == 53,
                   "Pastebin form headers");
    _Static_assert(2 + PASTE_BOUNDARY + 2 + 54 + PASTE_KEY + 4 + PASTE_BOUNDARY + 2 + 57 + 4 +
                       4 + PASTE_BOUNDARY + 2 + 53 + 5 + 4 + PASTE_BOUNDARY + 4 == PASTE_BODY,
                   "Pastebin multipart body must be 469 bytes");
    char *body = malloc(PASTE_BODY);
    if (!body) return NULL;
    char *p = body;
    memcpy(p, "--", 2); p += 2;
    memcpy(p, boundary, PASTE_BOUNDARY); p += PASTE_BOUNDARY;
    memcpy(p, "\r\n", 2); p += 2;
    memcpy(p, dev, sizeof(dev) - 1); p += sizeof(dev) - 1;
    memcpy(p, key, PASTE_KEY); p += PASTE_KEY;
    memcpy(p, "\r\n--", 4); p += 4;
    memcpy(p, boundary, PASTE_BOUNDARY); p += PASTE_BOUNDARY;
    memcpy(p, "\r\n", 2); p += 2;
    memcpy(p, code, sizeof(code) - 1); p += sizeof(code) - 1;
    memcpy(p, "test", 4); p += 4;
    memcpy(p, "\r\n--", 4); p += 4;
    memcpy(p, boundary, PASTE_BOUNDARY); p += PASTE_BOUNDARY;
    memcpy(p, "\r\n", 2); p += 2;
    memcpy(p, option, sizeof(option) - 1); p += sizeof(option) - 1;
    memcpy(p, "paste", 5); p += 5;
    memcpy(p, "\r\n--", 4); p += 4;
    memcpy(p, boundary, PASTE_BOUNDARY); p += PASTE_BOUNDARY;
    memcpy(p, "--\r\n", 4);
    return body;
}

static int pastebin_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    if (key.len != PASTE_KEY) return pastebin_fail(error, "invalid Pastebin key");
    unsigned char random[30];
    if (RAND_bytes(random, (int)sizeof(random)) != 1)
        return pastebin_fail(error, "Pastebin random boundary failed");
    static const char hex[] = "0123456789abcdef";
    char boundary[PASTE_BOUNDARY + 1];
    for (size_t i = 0; i < sizeof(random); ++i) {
        boundary[2 * i] = hex[random[i] >> 4];
        boundary[2 * i + 1] = hex[random[i] & 15];
    }
    boundary[PASTE_BOUNDARY] = '\0';
    char *body = pastebin_body((const char *)key.data, boundary);
    if (!body) return pastebin_fail(error, "out of memory creating Pastebin body");
    /* Completed body precedes NewRequestWithContext. Nil context drops only
     * this candidate and does not publish the constructor cause. */
    if (!ctx) {
        free(body);
        return PASTE_DROP;
    }
    static const char type_prefix[] = "multipart/form-data; boundary=";
    char content_type[sizeof(type_prefix) + PASTE_BOUNDARY];
    memcpy(content_type, type_prefix, sizeof(type_prefix) - 1);
    memcpy(content_type + sizeof(type_prefix) - 1, boundary, sizeof(boundary));
    const br_header headers[] = {{"Content-Type", content_type}};
    const br_http_request request = {
        .method = "POST", .url = "https://pastebin.com/api/api_post.php",
        .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)body, PASTE_BODY},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Body is not read. Close errors are ignored. Borrow the body through release. */
    br_http_release(ctx, &response);
    free(body);
    free(send_error);
    return PASTE_KEEP;
}

static int pastebin_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pastebin_fail(error, "invalid or uninitialized Pastebin scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        int outcome = PASTE_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            outcome = pastebin_fail(&owned_error, "cannot create Pastebin result");
        else if (verify)
            outcome = pastebin_verify(ctx, key, &result, &owned_error);
        if (outcome == PASTE_FATAL) rc = -1;
        if (outcome == PASTE_DROP) {
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = pastebin_fail(&owned_error, "cannot append Pastebin result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pastebin_keywords[] = {"pastebin"};
static br_detector pastebin_detector = {
    .type = 492, .version = 0, .name = "Pastebin", .custom_name = "",
    .description = "Pastebin is a website where users can store plain text. Pastebin keys can be used to access and manipulate stored data.",
    .keywords = pastebin_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pastebin_scan,
};

int br_pastebin_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pastebin_fail(error, "invalid Pastebin detector output");
    *out = NULL;
    if (br_key_pattern_init(&pastebin_detector, "\\b([a-zA-Z0-9_]{32})\\b", error) != 0)
        return -1;
    *out = &pastebin_detector;
    return 0;
}
