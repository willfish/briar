/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/kucoin/kucoin.go. */
#include "detectors.h"
#include "azure_shared_key.h"
#include "captures.h"
#include "findings.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *key, *secret, *passphrase; } kucoin_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool ascii_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

static int trim_copy(br_slice raw, char *out, size_t cap)
{
    size_t begin = 0, end = raw.len;
    while (begin < end && ascii_space(raw.data[begin])) ++begin;
    while (end > begin && ascii_space(raw.data[end - 1])) --end;
    if (end - begin >= cap) return -1;
    memcpy(out, raw.data + begin, end - begin);
    out[end - begin] = '\0';
    return 0;
}

static int sign_kucoin(const char *secret, const char *passphrase, char timestamp[32],
                      char sign[45], char pass_sign[45])
{
    /* Sign before NewRequestWithContext. Go formats Unix()*1000 with signed
     * wrap, including a leading minus. Valid -1 is not a clock failure. */
    errno = 0;
    time_t now = time(NULL);
    if (now == (time_t)-1 && errno != 0) return -1;
    int64_t seconds = (int64_t)now;
    int64_t millis = (int64_t)((uint64_t)seconds * 1000u);
    char message[64];
    int n = snprintf(timestamp, 32, "%" PRId64, millis);
    if (n < 0 || (size_t)n >= 32) return -1;
    n = snprintf(message, sizeof(message), "%sGET/api/v1/accounts", timestamp);
    if (n < 0 || (size_t)n >= sizeof(message)) return -1;
    br_slice secret_key = {(const unsigned char *)secret, strlen(secret)};
    int hmac = br_azure_hmac_sha256_base64(secret_key,
        (br_slice){(const unsigned char *)message, (size_t)n}, sign);
    if (hmac != 0) return hmac;
    return br_azure_hmac_sha256_base64(secret_key,
        (br_slice){(const unsigned char *)passphrase, strlen(passphrase)}, pass_sign);
}

static int send_kucoin(const br_scan_ctx *ctx, const char *key, const char *timestamp,
                       const char *sign, const char *pass_sign, br_result *result)
{
    /* Canonical names, only after the constructor succeeds. The URL is constant. */
    const br_header headers[] = {
        {"Kc-Api-Key", key},
        {"Kc-Api-Sign", sign},
        {"Kc-Api-Timestamp", timestamp},
        {"Kc-Api-Passphrase", pass_sign},
        {"Kc-Api-Key-Version", "2"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.kucoin.com/api/v1/accounts",
        .headers = headers, .nheaders = 5, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Any 2xx verifies, including a body read error. No setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_kucoin(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized KuCoin scan");
    const kucoin_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->secret || !compiled->passphrase)
        return fail(error, "uninitialized KuCoin patterns");
    br_captures keys = {0}, secrets = {0}, passphrases = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    /* All three FindAll sets run before a constructor drop, including a nil
     * context and an empty key set. Any nonzero, including +1, is fatal. */
    int key_rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    int secret_rc = key_rc == 0 ? br_captures_find(compiled->secret, input, &secrets, false, &owned_error) : 0;
    int pass_rc = key_rc == 0 && secret_rc == 0
        ? br_captures_find(compiled->passphrase, input, &passphrases, false, &owned_error) : 0;
    int rc = key_rc == 0 && secret_rc == 0 && pass_rc == 0 ? 0 : -1;
    /* Key outer, secret middle, passphrase inner. No dedupe. A spaced key may
     * also be a passphrase. Span 1024 is not applied. All three are required. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            for (size_t p = 0; rc == 0 && p < passphrases.len; ++p) {
                char passphrase[33], timestamp[32], sign[45], pass_sign[45];
                br_result result = {0};
                int trim_rc = trim_copy(br_captures_at(&passphrases, p), passphrase, sizeof(passphrase));
                int finding_rc = trim_rc == 0
                    ? br_finding_pair(&result, detector->type, keys.items[k], "key", passphrase, "passphrase") : 0;
                int sign_rc = trim_rc == 0 && finding_rc == 0 && verify
                    ? sign_kucoin(secrets.items[s], passphrase, timestamp, sign, pass_sign) : 0;
                if (trim_rc != 0)
                    rc = fail(&owned_error, "cannot trim KuCoin passphrase");
                else if (finding_rc != 0)
                    rc = fail(&owned_error, "cannot create KuCoin result");
                else if (sign_rc != 0)
                    rc = fail(&owned_error, "cannot sign KuCoin candidate");
                else if (verify && !ctx) {
                    /* NewRequestWithContext(nil) drops only this triple. No headers, send, or release. */
                    br_result_clear(&result);
                    continue;
                } else if (verify && send_kucoin(ctx, keys.items[k], timestamp, sign, pass_sign, &result) != 0)
                    rc = fail(&owned_error, "cannot verify KuCoin candidate");
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = fail(&owned_error, "cannot append KuCoin result");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    br_captures_clear(&passphrases);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static kucoin_patterns patterns;
static const char *const keywords[] = {"kucoin"};
static br_detector kucoin_detector = {
    .type = 736, .version = 0, .name = "KuCoin", .custom_name = "",
    .description = "KuCoin is a cryptocurrency exchange that provides various digital asset trading services. KuCoin API keys can be used to access and manage trading accounts, execute trades, and retrieve market data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_kucoin,
};

int br_kucoin_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid KuCoin detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{24})\\b", &patterns.key, error))
        return -1;
    if (!patterns.secret && br_regex_compile_prefixed(keywords, 1,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", &patterns.secret, error)) {
        br_regex_free(patterns.key);
        patterns.key = NULL;
        return -1;
    }
    if (!patterns.passphrase && br_regex_compile_prefixed(keywords, 1,
            "([ \\r\\n]{1}[!-~]{7,32}[ \\r\\n]{1})", &patterns.passphrase, error)) {
        br_regex_free(patterns.key);
        br_regex_free(patterns.secret);
        patterns.key = patterns.secret = NULL;
        return -1;
    }
    *out = &kucoin_detector;
    return 0;
}
