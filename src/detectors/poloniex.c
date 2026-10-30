/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/poloniex/poloniex.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int add_part(br_result *result, const char *name, br_slice value, char **error)
{
    if (!result->secret_parts && !(result->secret_parts = json_object_new_object()))
        return fail(error, "cannot create Poloniex result");
    char *text = malloc(value.len + 1);
    if (!text) return fail(error, "cannot create Poloniex result");
    memcpy(text, value.data, value.len);
    text[value.len] = '\0';
    br_json *part = json_object_new_string(text);
    free(text);
    if (!part || json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return fail(error, "cannot create Poloniex result");
    }
    return 0;
}

static int make_result(br_result *result, br_slice key, br_slice secret, char **error)
{
    result->detector_type = 516;
    if (key.len > SIZE_MAX - secret.len) return fail(error, "cannot create Poloniex result");
    result->raw.data = malloc(secret.len);
    result->raw_v2.data = malloc(key.len + secret.len);
    if (!result->raw.data || !result->raw_v2.data) return fail(error, "cannot create Poloniex result");
    memcpy(result->raw.data, secret.data, secret.len);
    result->raw.len = secret.len;
    memcpy(result->raw_v2.data, key.data, key.len);
    memcpy(result->raw_v2.data + key.len, secret.data, secret.len);
    result->raw_v2.len = key.len + secret.len;
    if (add_part(result, "key", key, error) || add_part(result, "secret", secret, error)) return -1;
    return 0;
}

static int sign_body(const char *secret, const char *body, char signature[129], char **error)
{
    unsigned char digest[64];
    size_t count = 0;
    /* The 128-character hex secret is the HMAC key, not decoded. */
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA512", NULL, secret, strlen(secret),
                   (const unsigned char *)body, strlen(body), digest, sizeof(digest), &count) ||
        count != sizeof(digest))
        return fail(error, "cannot sign Poloniex request");
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        signature[i * 2] = hex[digest[i] >> 4];
        signature[i * 2 + 1] = hex[digest[i] & 15];
    }
    signature[128] = '\0';
    return 0;
}

static int verify_poloniex(const br_scan_ctx *ctx, const char *key, const char *secret,
                           br_result *result, char **error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return fail(error, "cannot read Poloniex signing clock");
    if (now.tv_sec < 0 || now.tv_sec > INT64_MAX / 1000)
        return fail(error, "unsupported: Poloniex signing clock range");
    /* time.Now().Unix()*1000, not UnixMilli. url.Values sorts command before nonce. */
    char body[64];
    int n = snprintf(body, sizeof(body), "command=returnBalances&nonce=%" PRId64, (int64_t)now.tv_sec * 1000);
    if (n < 0 || (size_t)n >= sizeof(body)) return fail(error, "cannot format Poloniex body");
    char signature[129];
    if (sign_body(secret, body, signature, error) != 0) return -1;
    if (!ctx) return 1; /* Constructor failure after the body and signature exist. */
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Key", key},
        {"Sign", signature},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://poloniex.com/tradingApi",
        .headers = headers, .nheaders = 3, .body = {(const unsigned char *)body, (size_t)n},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 516,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_poloniex(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Poloniex scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    int rc = br_captures_find(patterns[0], input, &keys, false, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &secrets, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        for (size_t j = 0; rc == 0 && j < secrets.len; ++j) {
            br_result result = {0};
            int verdict = 0;
            if (make_result(&result, br_captures_at(&keys, i), br_captures_at(&secrets, j), error) != 0)
                rc = -1;
            else if (verify)
                verdict = verify_poloniex(ctx, keys.items[i], secrets.items[j], &result, error);
            if (rc == 0 && verdict < 0) rc = -1;
            else if (rc == 0 && verdict == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append Poloniex result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    return rc == 0 ? 0 : -1;
}

static const char *const poloniex_keywords[] = {"poloniex"};
static br_regex *poloniex_patterns[2];
static br_detector poloniex_detector = {
    .type = 516, .version = 0, .name = "Poloniex", .custom_name = "",
    .description = "Poloniex is a cryptocurrency exchange that allows users to trade various digital assets. Poloniex API keys can be used to access and manage account data and perform trading operations.",
    .keywords = poloniex_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = poloniex_patterns, .scan = scan_poloniex,
};

int br_poloniex_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Poloniex detector output");
    *out = NULL;
    if (!poloniex_patterns[0] &&
        br_regex_compile_prefixed(poloniex_keywords, 1,
            "\\b([0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8})\\b",
            &poloniex_patterns[0], error) != 0)
        return -1;
    if (!poloniex_patterns[1] &&
        br_regex_compile_prefixed(poloniex_keywords, 1, "\\b([0-9a-f]{128})\\b",
                                  &poloniex_patterns[1], error) != 0)
        return -1;
    *out = &poloniex_detector;
    return 0;
}
