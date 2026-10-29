/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/kraken/kraken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "azure_shared_key.h"

#include <openssl/evp.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *key, *private_key; } kraken_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool ascii_space(unsigned char c)
{
    /* Go TrimSpace. The captured delimiter can only add space, CR, or LF. */
    return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

static char *trim_space(br_slice value)
{
    size_t begin = 0, end = value.len;
    while (begin < end && ascii_space(value.data[begin])) ++begin;
    while (end > begin && ascii_space(value.data[end - 1])) --end;
    char *out = malloc(end - begin + 1);
    if (!out) return NULL;
    if (end > begin) memcpy(out, value.data + begin, end - begin);
    out[end - begin] = '\0';
    return out;
}

static int encode_std(const unsigned char *in, size_t len, char *out, size_t out_cap)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t need = ((len + 2) / 3) * 4;
    if (out_cap < need + 1) return -1;
    size_t at = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned value = (unsigned)in[i] << 16;
        if (i + 1 < len) value |= (unsigned)in[i + 1] << 8;
        if (i + 2 < len) value |= in[i + 2];
        out[at++] = alphabet[(value >> 18) & 63];
        out[at++] = alphabet[(value >> 12) & 63];
        out[at++] = i + 1 < len ? alphabet[(value >> 6) & 63] : '=';
        out[at++] = i + 2 < len ? alphabet[value & 63] : '=';
    }
    out[at] = '\0';
    return 0;
}

static bool contains(br_slice body, const char *needle)
{
    size_t n = strlen(needle);
    if (!body.data || n > body.len) return false;
    for (size_t i = 0; i + n <= body.len; ++i)
        if (!memcmp(body.data + i, needle, n)) return true;
    return false;
}

/* SHA256(nonce + "nonce=" + nonce), then HMAC-SHA512 of the path plus that digest.
 * A corrupt Base64 private key still signs with the bytes already written. */
static int sign_balance(const char *nonce, const char *private_key, char signature[89])
{
    br_bytes decoded = {0};
    size_t bad_offset = SIZE_MAX;
    int decoded_rc = br_azure_base64_std_decode(
        (br_slice){(const unsigned char *)private_key, strlen(private_key)}, &decoded, &bad_offset);
    if (decoded_rc < 0) {
        free(decoded.data);
        return -1;
    }
    char material[64];
    int material_len = snprintf(material, sizeof(material), "%snonce=%s", nonce, nonce);
    /* The path is 18 bytes. The MAC input is that path followed by the
     * 32-byte digest, 50 bytes. A 19-byte copy would include the C NUL. */
    unsigned char digest[32], message[50], mac[64];
    size_t count = 0;
    static const unsigned char empty[] = "";
    int rc = -1;
    if (material_len > 0 && (size_t)material_len < sizeof(material) &&
        EVP_Q_digest(NULL, "SHA256", NULL, material, (size_t)material_len, digest, &count) && count == 32) {
        memcpy(message, "/0/private/Balance", 18);
        memcpy(message + 18, digest, 32);
        count = 0;
        if (EVP_Q_mac(NULL, "HMAC", NULL, "SHA512", NULL,
                      decoded.data ? decoded.data : empty, decoded.len,
                      message, 50, mac, sizeof(mac), &count) && count == 64 &&
            encode_std(mac, 64, signature, 89) == 0)
            rc = 0;
    }
    free(decoded.data);
    return rc;
}

/* Nonce, body, decode, and signature run before NewRequestWithContext.
 * Decode status 1 still signs. Decode -1 and any other signing failure return nonzero. */
static int prepare_kraken(const char *private_key, char nonce[32], char body[48],
                          int *body_len, char signature[89])
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return -1;
    int nonce_len = snprintf(nonce, 32, "%" PRId64, (int64_t)now.tv_sec);
    int n = snprintf(body, 48, "nonce=%s", nonce);
    if (nonce_len < 1 || (size_t)nonce_len >= 32 || n < 7 || (size_t)n >= 48) return -1;
    *body_len = n;
    return sign_balance(nonce, private_key, signature);
}

static int send_kraken(const br_scan_ctx *ctx, const char *key, const char *body, int body_len,
                       const char *signature, br_result *result)
{
    /* Headers exist only after the constructor succeeds. Source spells the last
     * two API-Key and API-Sign; send the canonical forms. */
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Api-Key", key},
        {"Api-Sign", signature},
    };
    const br_http_request request = {
        .method = "POST",
        .url = "https://api.kraken.com/0/private/Balance",
        .headers = headers,
        .nheaders = 3,
        .body = {(const unsigned char *)body, (size_t)body_len},
        .profile = BR_HTTP_SANE,
        .detector_type = 186,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    int rc = 0;
    /* Source reads the body only after Do succeeds. A NULL data pointer with a
     * nonzero length is not a readable slice; do not project it. */
    if (send_rc == 0) {
        if (!response.body.data && response.body.len)
            rc = -1;
        else if (!contains(response.body, "Invalid key"))
            result->verified = true; /* Status and body_error are ignored. */
    }
    br_http_release(ctx, &response); /* One release, including this owned fatal. */
    free(transport_error);
    return rc;
}

static int scan_kraken(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Kraken scan arguments");
    const kraken_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->private_key)
        return fail(error, "uninitialized Kraken detector");

    size_t original_len = out->len;
    br_captures keys = {0}, privates = {0};
    char *owned_error = NULL;
    /* Both FindAll calls run even when verify is set, ctx is NULL, and there
     * are no keys. Any nonzero, including +1, is fatal before a drop. */
    char *key_error = NULL, *private_error = NULL;
    int key_rc = br_captures_find(patterns->key, input, &keys, false, &key_error);
    int private_rc = br_captures_find(patterns->private_key, input, &privates, false, &private_error);
    int rc = 0;
    if (key_rc != 0) {
        owned_error = key_error;
        free(private_error);
        rc = -1;
    } else if (private_rc != 0) {
        owned_error = private_error;
        free(key_error);
        rc = -1;
    } else {
        free(key_error);
        free(private_error);
    }
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        char *key = trim_space(br_captures_at(&keys, k));
        if (!key) {
            rc = fail(&owned_error, "out of memory trimming Kraken key");
            break;
        }
        for (size_t p = 0; rc == 0 && p < privates.len; ++p) {
            char *private_key = trim_space(br_captures_at(&privates, p));
            br_result result = {0};
            if (!private_key)
                rc = fail(&owned_error, "out of memory trimming Kraken private key");
            else if (br_finding_pair(&result, detector->type, key, "key",
                                     private_key, "private_key") != 0)
                rc = fail(&owned_error, "out of memory creating Kraken result");
            if (rc == 0 && verify) {
                char nonce[32], body[48], signature[89];
                int body_len = 0;
                if (prepare_kraken(private_key, nonce, body, &body_len, signature) != 0)
                    rc = fail(&owned_error, "Kraken signature failed");
                else if (!ctx) {
                    /* "net/http: nil Context" drops only this pair. */
                    br_result_clear(&result);
                    free(private_key);
                    continue;
                } else if (send_kraken(ctx, key, body, body_len, signature, &result) != 0)
                    rc = fail(&owned_error, "invalid Kraken response body");
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(&owned_error, "out of memory appending Kraken result");
            br_result_clear(&result);
            free(private_key);
        }
        free(key);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&privates);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static kraken_patterns patterns;
static const char *const keywords[] = {"kraken"};
static const br_detector kraken = {
    .type = 186, .version = 0, .name = "Kraken", .custom_name = "",
    .description = "Kraken is a cryptocurrency exchange that allows trading of various digital assets. "
                   "Kraken API keys can be used to access and manage account information and perform trading operations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_kraken,
};

int br_kraken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Kraken detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(
            keywords, 1, "\\b([0-9A-Za-z\\/\\+=]{56}[ \"'\\r\\n]{1})", &patterns.key, error) != 0)
        return -1;
    if (!patterns.private_key && br_regex_compile_prefixed(
            keywords, 1, "\\b([0-9A-Za-z\\/\\+=]{86,88}[ \"'\\r\\n]{1})", &patterns.private_key, error) != 0)
        return -1;
    *out = &kraken;
    return 0;
}
