/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/robinhoodcrypto/robinhoodcrypto.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

typedef struct {
    br_regex *key, *private_key;
} robinhood_patterns;

typedef enum { RH_ABORT = -1, RH_KEEP = 0 } rh_outcome;

static const char rh_struct_type[] =
    "struct { AccountNumber string \"json:\\\"account_number\\\"\"; "
    "Status string \"json:\\\"status\\\"\"; "
    "BuyingPower string \"json:\\\"buying_power\\\"\"; "
    "BuyingPowerCurrency string \"json:\\\"buying_power_currency\\\"\" }";

static int rh_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int rh_cause(br_result *result, const char *cause, br_slice key, br_slice private_key, char **error)
{
    const br_slice secrets[] = {key, private_key};
    if (br_result_set_verification_error(result, cause, secrets, 2) != 0)
        return rh_fail(error, "cannot set RobinhoodCrypto verification error");
    return 0;
}

static int rh_sextet(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int rh_decode(br_slice encoded, br_bytes *out, char **cause)
{
    *out = (br_bytes){0};
    *cause = NULL;
    if (!encoded.len || encoded.len % 4) {
        char message[80];
        snprintf(message, sizeof(message), "illegal base64 data at input byte %zu", encoded.len ? encoded.len : 0);
        *cause = strdup(message);
        return *cause ? 1 : -1;
    }
    size_t pad = 0;
    if (encoded.data[encoded.len - 1] == '=') ++pad;
    if (pad < 2 && encoded.len > 1 && encoded.data[encoded.len - 2] == '=') ++pad;
    if (pad > 2) {
        char message[80];
        snprintf(message, sizeof(message), "illegal base64 data at input byte %zu", encoded.len - pad);
        *cause = strdup(message);
        return *cause ? 1 : -1;
    }
    size_t len = encoded.len / 4 * 3 - pad;
    unsigned char *bytes = malloc(len ? len : 1);
    if (!bytes) return -1;
    size_t written = 0;
    for (size_t i = 0; i < encoded.len; i += 4) {
        int v[4];
        for (int j = 0; j < 4; ++j) {
            unsigned char c = encoded.data[i + (size_t)j];
            if ((size_t)j >= 4 - pad && i + 4 == encoded.len && c == '=') v[j] = 0;
            else {
                v[j] = rh_sextet(c);
                if (v[j] < 0) {
                    free(bytes);
                    char message[80];
                    snprintf(message, sizeof(message), "illegal base64 data at input byte %zu", i + (size_t)j);
                    *cause = strdup(message);
                    return *cause ? 1 : -1;
                }
            }
        }
        bytes[written++] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        if (written < len) bytes[written++] = (unsigned char)(((v[1] & 15) << 4) | (v[2] >> 2));
        if (written < len) bytes[written++] = (unsigned char)(((v[2] & 3) << 6) | v[3]);
    }
    out->data = bytes;
    out->len = written;
    return 0;
}

static int rh_sign(const unsigned char *seed, const unsigned char *message, size_t message_len,
                   unsigned char signature[64], char **error)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t length = 64;
    int ok = key && md && EVP_DigestSignInit(md, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestSign(md, signature, &length, message, message_len) == 1 && length == 64;
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    return ok ? 0 : rh_fail(error, "cannot sign RobinhoodCrypto request");
}

static char *rh_b64(const unsigned char *data, size_t len, char **error)
{
    if (len > 1024) return NULL;
    char *out = malloc(4 * ((len + 2) / 3) + 1);
    if (!out) {
        rh_fail(error, "cannot allocate RobinhoodCrypto signature");
        return NULL;
    }
    int n = EVP_EncodeBlock((unsigned char *)out, data, (int)len);
    if (n < 0) {
        free(out);
        rh_fail(error, "cannot encode RobinhoodCrypto signature");
        return NULL;
    }
    out[n] = '\0';
    return out;
}

static const char *rh_header(const br_http_response *response, const char *name)
{
    for (size_t i = 0; response->headers && i < response->nheaders; ++i)
        if (response->headers[i].name && !strcasecmp(response->headers[i].name, name))
            return response->headers[i].value ? response->headers[i].value : "";
    return NULL;
}

static bool rh_space(uint32_t r)
{
    return (r >= 9 && r <= 13) || r == 32 || r == 0x85 || r == 0xa0 || r == 0x1680 ||
           (r >= 0x2000 && r <= 0x200a) || r == 0x2028 || r == 0x2029 || r == 0x202f ||
           r == 0x205f || r == 0x3000;
}

static br_slice rh_trim(br_slice body)
{
    size_t start = 0, end = 0;
    for (size_t i = 0; body.data && i < body.len;) {
        uint32_t rune = 0;
        size_t n = br_utf8_rune((br_slice){body.data + i, body.len - i}, &rune);
        if (!n) {
            rune = 0xfffd;
            n = 1;
        }
        if (!rh_space(rune)) {
            if (!end) start = i;
            end = i + n;
        }
        i += n;
    }
    return (br_slice){body.data ? body.data + start : NULL, end ? end - start : 0};
}

static bool rh_trim_equal(br_slice body, const char *expected)
{
    br_slice trimmed = rh_trim(body);
    size_t len = strlen(expected);
    return trimmed.len == len && trimmed.data && !memcmp(trimmed.data, expected, len);
}

static int rh_add_len(br_json *object, const char *key, const char *value, size_t len, char **error)
{
    br_json *text = json_object_new_string_len(value ? value : "", (int)len);
    if (!object || !text || json_object_object_add(object, key, text) != 0) {
        json_object_put(text);
        return rh_fail(error, "cannot create RobinhoodCrypto metadata");
    }
    return 0;
}

static int rh_add(br_json *object, const char *key, const char *value, char **error)
{
    return rh_add_len(object, key, value, value ? strlen(value) : 0, error);
}

typedef struct {
    char *account, *status, *power, *currency, *cause;
    size_t account_len, status_len, power_len, currency_len;
    bool failed;
} rh_account;

static void rh_account_clear(rh_account *account)
{
    free(account->account);
    free(account->status);
    free(account->power);
    free(account->currency);
    free(account->cause);
}

static int rh_copy(char **dest, size_t *len, br_json *value)
{
    br_slice text = value ? br_json_text(value) : (br_slice){0};
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len && text.data) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(*dest);
    *dest = copy;
    *len = text.len;
    return 0;
}

static int rh_note(rh_account *account, br_json *value, const char *field)
{
    char *next = NULL;
    if (br_json_type_cause(value, field, "string", &next) != 0) return -1;
    if (!account->failed) {
        account->failed = true;
        account->cause = next;
    } else free(next);
    return 0;
}

static int rh_string_field(rh_account *account, br_json *value, const char *field, char **dest, size_t *len)
{
    /* JSON null leaves the Go string unchanged. */
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) return rh_note(account, value, field);
    return rh_copy(dest, len, value);
}

static int rh_account_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    rh_account *account = user;
    (void)encoded;
    if (br_json_field_name(name, "account_number"))
        return rh_string_field(account, value, ".account_number", &account->account, &account->account_len);
    if (br_json_field_name(name, "status"))
        return rh_string_field(account, value, ".status", &account->status, &account->status_len);
    if (br_json_field_name(name, "buying_power"))
        return rh_string_field(account, value, ".buying_power", &account->power, &account->power_len);
    if (br_json_field_name(name, "buying_power_currency"))
        return rh_string_field(account, value, ".buying_power_currency", &account->currency,
                               &account->currency_len);
    return 0;
}

static int rh_project(br_slice body, const char *read_error, rh_account *account, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int decoded = br_json_first_document(body, read_error, &root, &end, &cause);
    /* Only exact document status +1 is ordinary. Null success is 0. */
    if (decoded == 1) {
        account->failed = true;
        account->cause = cause;
        json_object_put(root);
        return 1;
    }
    if (decoded != 0) {
        free(cause);
        json_object_put(root);
        return rh_fail(error, "cannot decode RobinhoodCrypto response");
    }
    free(cause);
    int rc = 0;
    if (root && !json_object_is_type(root, json_type_null)) {
        if (!json_object_is_type(root, json_type_object)) {
            char *next = NULL;
            if (br_json_type_cause(root, NULL, rh_struct_type, &next) != 0) rc = -1;
            else {
                account->failed = true;
                account->cause = next;
            }
        } else {
            int visit = br_json_each_member((br_slice){body.data, end}, rh_account_member, account);
            if (visit != 0) rc = -1;
        }
    }
    json_object_put(root);
    if (rc != 0) return rh_fail(error, "cannot project RobinhoodCrypto response");
    return account->failed ? 1 : 0;
}

static rh_outcome rh_verify(const br_scan_ctx *ctx, br_slice key, br_slice private_key, br_result *result,
                            char **error)
{
    br_bytes seed = {0};
    char *decode_cause = NULL;
    int decoded = rh_decode(private_key, &seed, &decode_cause);
    if (decoded < 0) {
        free(decode_cause);
        return RH_ABORT;
    }
    if (decoded == 1) {
        /* %w is unwrapped by SetVerificationError, so only the inner error is stored. */
        int kept = rh_cause(result, decode_cause, key, private_key, error);
        free(decode_cause);
        return kept == 0 ? RH_KEEP : RH_ABORT;
    }
    if (decoded != 0) {
        free(decode_cause);
        free(seed.data);
        return RH_ABORT;
    }
    if (seed.len < 32) {
        char message[96];
        snprintf(message, sizeof(message),
                 "private key is too short, expected at least 32 bytes, got %zu", seed.len);
        free(seed.data);
        return rh_cause(result, message, key, private_key, error) == 0 ? RH_KEEP : RH_ABORT;
    }
    char timestamp[32];
    int ts_n = snprintf(timestamp, sizeof(timestamp), "%lld", (long long)time(NULL));
    if (ts_n < 0 || (size_t)ts_n >= sizeof(timestamp)) {
        free(seed.data);
        rh_fail(error, "cannot format RobinhoodCrypto timestamp");
        return RH_ABORT;
    }
    static const char path[] = "/api/v1/crypto/trading/accounts/";
    size_t message_len = key.len + (size_t)ts_n + sizeof(path) - 1 + 3;
    unsigned char *message = malloc(message_len ? message_len : 1);
    if (!message) {
        free(seed.data);
        rh_fail(error, "cannot allocate RobinhoodCrypto message");
        return RH_ABORT;
    }
    size_t at = 0;
    if (key.len) memcpy(message + at, key.data, key.len);
    at += key.len;
    memcpy(message + at, timestamp, (size_t)ts_n);
    at += (size_t)ts_n;
    memcpy(message + at, path, sizeof(path) - 1);
    at += sizeof(path) - 1;
    memcpy(message + at, "GET", 3);
    unsigned char signature[64];
    int rc = rh_sign(seed.data, message, message_len, signature, error);
    free(seed.data);
    free(message);
    if (rc != 0) return RH_ABORT;
    char *encoded_signature = rh_b64(signature, 64, error);
    if (!encoded_signature) return RH_ABORT;
    /* The signature exists before NewRequestWithContext. Nil context is kept. */
    if (!ctx) {
        free(encoded_signature);
        return rh_cause(result, "net/http: nil Context", key, private_key, error) == 0 ? RH_KEEP : RH_ABORT;
    }
    char *api_key = malloc(key.len + 1);
    if (!api_key) {
        free(encoded_signature);
        rh_fail(error, "cannot format RobinhoodCrypto key");
        return RH_ABORT;
    }
    if (key.len) memcpy(api_key, key.data, key.len);
    api_key[key.len] = '\0';
    const br_header headers[] = {
        {"x-api-key", api_key},
        {"x-signature", encoded_signature},
        {"x-timestamp", timestamp},
    };
    static const unsigned char empty[] = "";
    const br_http_request request = {
        .method = "GET",
        .url = "https://trading.robinhood.com//api/v1/crypto/trading/accounts/",
        .headers = headers, .nheaders = 3, .body = {empty, 0},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const char *cause = NULL;
    char owned[256];
    rh_account account = {0};
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200) {
        result->verified = true;
        const char *content_type = rh_header(&response, "Content-Type");
        if (response.nheaders > 0 && content_type && !strcmp(content_type, "application/json")) {
            int projected = rh_project(response.body, response.body_error, &account, error);
            if (projected < 0) rc = -1;
            else if (projected == 1) {
                /* %w is unwrapped by SetVerificationError, so only the inner error is stored. */
                cause = account.cause;
            } else if (projected != 0) rc = -1;
            else {
                result->extra_data = json_object_new_object();
                rc = rh_add_len(result->extra_data, "Robinhood Crypto Account Number",
                                account.account ? account.account : "", account.account_len, error);
            }
        }
    } else if (response.status == 403) {
        result->verified = true;
        result->extra_data = json_object_new_object();
        rc = rh_add(result->extra_data, "Explanation",
                    "Valid credentials without access to Get Crypto Trading Account Details API", error);
    } else if (response.status == 401) {
        const char *content_type = rh_header(&response, "Content-Type");
        if (response.nheaders > 0 && content_type && !strcmp(content_type, "text/plain")) {
            if (response.body_error) {
                /* %w is unwrapped by SetVerificationError, so only the inner error is stored. */
                cause = response.body_error;
            } else if (rh_trim_equal(response.body, "API credential is not active.")) {
                result->verified = true;
                result->extra_data = json_object_new_object();
                rc = rh_add(result->extra_data, "Explanation", "Valid credentials in inactive state", error);
            }
        }
    } else {
        snprintf(owned, sizeof(owned), "unexpected HTTP response status %d", response.status);
        cause = owned;
    }
    if (rc == 0) rc = rh_cause(result, cause, key, private_key, error);
    br_http_release(ctx, &response);
    free(transport_error);
    free(encoded_signature);
    free(api_key);
    rh_account_clear(&account);
    return rc == 0 ? RH_KEEP : RH_ABORT;
}

static int rh_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const robinhood_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->key || !patterns->private_key || !out ||
        (!input.data && input.len))
        return rh_fail(error, "invalid or uninitialized RobinhoodCrypto scan");
    size_t original_len = out->len;
    br_captures keys = {0}, privates = {0};
    char *owned_error = NULL;
    /* Both sides are maps. First-seen order stands in for unspecified iteration. */
    int rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->private_key, input, &privates, true, &owned_error);
    static const unsigned char none[] = "";
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        for (size_t j = 0; rc == 0 && j < privates.len; ++j) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, i);
            br_slice private_key = br_captures_at(&privates, j);
            rh_outcome outcome = RH_KEEP;
            if (br_finding_pair_bytes(&result, detector->type, key, "key", private_key, "private_key",
                                      (br_slice){none, 0}) != 0) {
                rh_fail(&owned_error, "cannot create RobinhoodCrypto result");
                outcome = RH_ABORT;
            } else if (verify)
                outcome = rh_verify(ctx, key, private_key, &result, &owned_error);
            if (outcome == RH_ABORT) rc = -1;
            else if (br_results_push(out, &result) != 0) {
                rh_fail(&owned_error, "cannot append RobinhoodCrypto result");
                rc = -1;
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&privates);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const rh_keywords[] = {"rh-api-"};
static robinhood_patterns rh_state;
static br_detector rh_detector = {
    .type = 996, .version = 0, .name = "RobinhoodCrypto", .custom_name = "",
    .description = "Robinhood Crypto API keys can be used to access and trade cryptocurrencies on the Robinhood platform.",
    .keywords = rh_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = rh_scan,
};

int br_robinhoodcrypto_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return rh_fail(error, "invalid RobinhoodCrypto detector output");
    *out = NULL;
    if (!rh_state.key &&
        br_regex_compile("\\b(rh-api-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\\b",
                         &rh_state.key, error) != 0)
        return -1;
    if (!rh_state.private_key &&
        br_regex_compile("((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))",
                         &rh_state.private_key, error) != 0)
        return -1;
    rh_detector.state = &rh_state;
    *out = &rh_detector;
    return 0;
}
