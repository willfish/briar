/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/netsuite. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char netsuite_nonce_charset[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static const uint32_t netsuite_nonce_limit =
    UINT32_MAX - (UINT32_MAX % (sizeof(netsuite_nonce_charset) - 1));

/* NULL selects the production clock and RAND_bytes. The owned test sets these. */
static int (*netsuite_nonce_fn)(char *out, char **error);
static int (*netsuite_unix_fn)(int64_t *seconds, char **error);

typedef struct {
    br_regex *consumer_key, *consumer_secret, *token_key, *token_secret, *account;
} netsuite_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool distinct(const char *a, const char *b, const char *c, const char *d, const char *e)
{
    const char *values[] = {a, b, c, d, e};
    for (size_t i = 0; i < 5; ++i)
        for (size_t j = i + 1; j < 5; ++j)
            if (!strcmp(values[i], values[j])) return false;
    return true;
}

/* Go's url.QueryEscape treats '~' as unreserved. This private encoder does not. */
static bool unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.';
}

static int netsuite_query_escape(const unsigned char *in, size_t len, char **out, size_t *out_len,
                                 char **error)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!out || (len && !in)) return fail(error, "cannot allocate Netsuite signature");
    size_t need = 0;
    for (size_t i = 0; i < len; ++i) {
        size_t add = unreserved(in[i]) || in[i] == ' ' ? 1 : 3;
        if (need > SIZE_MAX - add) return fail(error, "cannot allocate Netsuite signature");
        need += add;
    }
    char *text = malloc(need + 1);
    if (!text) return fail(error, "cannot allocate Netsuite signature");
    static const char hex[] = "0123456789ABCDEF";
    size_t at = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = in[i];
        if (unreserved(c)) text[at++] = (char)c;
        else if (c == ' ') text[at++] = '+';
        else {
            text[at++] = '%';
            text[at++] = hex[c >> 4];
            text[at++] = hex[c & 15];
        }
    }
    text[at] = '\0';
    *out = text;
    if (out_len) *out_len = at;
    return 0;
}

static int escape_text(const char *text, char **out, char **error)
{
    return netsuite_query_escape((const unsigned char *)text, strlen(text), out, NULL, error);
}

static int join_parts(char **out, char **error, const char *const *parts, size_t count)
{
    size_t need = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t n = strlen(parts[i]);
        if (n > SIZE_MAX - need) return fail(error, "cannot allocate Netsuite signature");
        need += n;
    }
    char *text = malloc(need + 1);
    if (!text) return fail(error, "cannot allocate Netsuite signature");
    size_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t n = strlen(parts[i]);
        memcpy(text + at, parts[i], n);
        at += n;
    }
    text[at] = '\0';
    *out = text;
    return 0;
}

static uint32_t netsuite_be32(const unsigned char bytes[4])
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static int netsuite_rand_u32(uint32_t *out, void *user, char **error)
{
    (void)user;
    unsigned char bytes[4];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
        return fail(error, "cannot generate Netsuite nonce");
    *out = netsuite_be32(bytes);
    return 0;
}

static int netsuite_sample_nonce(int (*next)(uint32_t *, void *, char **), void *user,
                                 char *out, char **error)
{
    if (!next || !out) return fail(error, "cannot generate Netsuite nonce");
    for (int i = 0; i < 11;) {
        uint32_t num = 0;
        if (next(&num, user, error) != 0) return -1;
        if (num < netsuite_nonce_limit)
            out[i++] = netsuite_nonce_charset[num % (sizeof(netsuite_nonce_charset) - 1)];
    }
    out[11] = '\0';
    return 0;
}

static int netsuite_make_nonce(char *out, char **error)
{
    if (netsuite_nonce_fn) return netsuite_nonce_fn(out, error);
    return netsuite_sample_nonce(netsuite_rand_u32, NULL, out, error);
}

static int netsuite_read_unix(int64_t *seconds, char **error)
{
    if (netsuite_unix_fn) return netsuite_unix_fn(seconds, error);
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        return fail(error, "cannot read Netsuite signing clock");
    *seconds = (int64_t)now.tv_sec;
    return 0;
}

static int set_cause(br_result *result, const char *cause, const char *key, char **error)
{
    const br_slice secret = {(const unsigned char *)key, strlen(key)};
    /* Consumer key only. Token and account bytes stay unredacted. NULL is checked. */
    if (br_result_set_verification_error(result, cause, &secret, 1))
        return fail(error, "cannot store Netsuite verification error");
    return 0;
}

static int build_url(const char *account, char *url, size_t cap, char **error)
{
    static const char prefix[] = "https://";
    static const char suffix[] =
        ".suitetalk.api.netsuite.com/services/rest/record/v1/metadata-catalog/check";
    size_t n = strlen(account);
    if (n > cap || sizeof(prefix) - 1 > cap - n || sizeof(suffix) > cap - n - (sizeof(prefix) - 1))
        return fail(error, "cannot allocate Netsuite signature");
    memcpy(url, prefix, sizeof(prefix) - 1);
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)account[i];
        if (c == '_') url[sizeof(prefix) - 1 + i] = '-';
        else if (c >= 'A' && c <= 'Z') url[sizeof(prefix) - 1 + i] = (char)(c - 'A' + 'a');
        else url[sizeof(prefix) - 1 + i] = (char)c;
    }
    memcpy(url + sizeof(prefix) - 1 + n, suffix, sizeof(suffix));
    return 0;
}

static int sign_request(const char *url, const char *ck, const char *cs, const char *tk,
                        const char *ts, const char *nonce, const char *timestamp,
                        const char *account, char **auth, char **error)
{
    char *esc_ck = NULL, *esc_nonce = NULL, *esc_method = NULL, *esc_time = NULL;
    char *esc_token = NULL, *esc_version = NULL, *param = NULL, *esc_param = NULL;
    char *esc_url = NULL, *base = NULL, *esc_cs = NULL, *esc_ts = NULL, *hmac_key = NULL;
    char *esc_sig = NULL;
    int rc = -1;
    if (escape_text(ck, &esc_ck, error) || escape_text(nonce, &esc_nonce, error) ||
        escape_text("HMAC-SHA256", &esc_method, error) || escape_text(timestamp, &esc_time, error) ||
        escape_text(tk, &esc_token, error) || escape_text("1.0", &esc_version, error))
        goto done;
    const char *param_parts[] = {
        "oauth_consumer_key=", esc_ck, "&oauth_nonce=", esc_nonce,
        "&oauth_signature_method=", esc_method, "&oauth_timestamp=", esc_time,
        "&oauth_token=", esc_token, "&oauth_version=", esc_version,
    };
    if (join_parts(&param, error, param_parts, sizeof(param_parts) / sizeof(param_parts[0])) ||
        escape_text(url, &esc_url, error) || escape_text(param, &esc_param, error))
        goto done;
    const char *base_parts[] = {"GET&", esc_url, "&", esc_param};
    if (join_parts(&base, error, base_parts, sizeof(base_parts) / sizeof(base_parts[0])) ||
        escape_text(cs, &esc_cs, error) || escape_text(ts, &esc_ts, error))
        goto done;
    const char *key_parts[] = {esc_cs, "&", esc_ts};
    if (join_parts(&hmac_key, error, key_parts, sizeof(key_parts) / sizeof(key_parts[0]))) goto done;
    unsigned char digest[32];
    size_t count = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, hmac_key, strlen(hmac_key),
                   (const unsigned char *)base, strlen(base), digest, sizeof(digest), &count) ||
        count != sizeof(digest)) {
        fail(error, "cannot sign Netsuite request");
        goto done;
    }
    unsigned char encoded[45];
    if (EVP_EncodeBlock(encoded, digest, (int)sizeof(digest)) != 44 ||
        netsuite_query_escape(encoded, 44, &esc_sig, NULL, error)) {
        fail(error, "cannot sign Netsuite request");
        goto done;
    }
    const char *header_parts[] = {
        "OAuth realm=\"", account, "\",oauth_consumer_key=\"", ck, "\",oauth_token=\"", tk,
        "\",oauth_signature_method=\"HMAC-SHA256\",oauth_timestamp=\"", timestamp,
        "\",oauth_nonce=\"", nonce, "\",oauth_version=\"1.0\",oauth_signature=\"", esc_sig, "\"",
    };
    if (join_parts(auth, error, header_parts, sizeof(header_parts) / sizeof(header_parts[0])) == 0)
        rc = 0;
done:
    free(esc_ck); free(esc_nonce); free(esc_method); free(esc_time); free(esc_token);
    free(esc_version); free(param); free(esc_param); free(esc_url); free(base);
    free(esc_cs); free(esc_ts); free(hmac_key); free(esc_sig);
    return rc;
}

static int verify_netsuite(const br_scan_ctx *ctx, const char *ck, const char *cs, const char *tk,
                           const char *ts, const char *account, br_result *result, char **error)
{
    if (!ctx) return set_cause(result, "net/http: nil Context", ck, error);
    char nonce[12];
    char *nonce_error = NULL;
    if (netsuite_make_nonce(nonce, &nonce_error) != 0) {
        int rc = set_cause(result, nonce_error ? nonce_error : "cannot generate Netsuite nonce", ck, error);
        free(nonce_error);
        return rc; /* Candidate remains appendable. No send and no release. */
    }
    int64_t seconds = 0;
    char *clock_error = NULL;
    if (netsuite_read_unix(&seconds, &clock_error) != 0) {
        if (error && !*error)
            *error = clock_error ? clock_error : strdup("cannot read Netsuite signing clock");
        else free(clock_error);
        return -1;
    }
    char timestamp[32], url[160], *auth = NULL;
    int wrote = snprintf(timestamp, sizeof(timestamp), "%" PRId64, seconds);
    if (wrote < 0 || (size_t)wrote >= sizeof(timestamp))
        return fail(error, "cannot format Netsuite timestamp");
    if (build_url(account, url, sizeof(url), error) ||
        sign_request(url, ck, cs, tk, ts, nonce, timestamp, account, &auth, error)) {
        free(auth);
        return -1;
    }
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 0, .detector_type = 995,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    bool sent = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        /* Release once before the setter. URL and Authorization remain alive. */
        br_http_release(ctx, &response);
        if (!(transport_error && strstr(transport_error, "no such host")))
            rc = set_cause(result, transport_error, ck, error);
    } else if (response.status == 200) {
        sent = true;
        result->verified = true; /* Source never reads the body; body_error cannot change this. */
    } else if (response.status == 401) {
        sent = true; /* Determinate. Source does not publish an error. */
    } else {
        sent = true;
        char status_error[64];
        wrote = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d",
                         response.status);
        if (wrote < 0 || (size_t)wrote >= sizeof(status_error))
            rc = fail(error, "cannot format Netsuite status");
        else {
            br_http_release(ctx, &response);
            sent = false;
            rc = set_cause(result, status_error, ck, error);
        }
    }
    if (sent) br_http_release(ctx, &response); /* One release for every attempted send. */
    free(transport_error);
    free(auth);
    return rc;
}

static int scan_netsuite(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Netsuite scan");
    const netsuite_patterns *compiled = detector->state;
    if (!compiled->consumer_key || !compiled->consumer_secret || !compiled->token_key ||
        !compiled->token_secret || !compiled->account)
        return fail(error, "invalid or uninitialized Netsuite scan");
    br_captures consumer_keys = {0}, consumer_secrets = {0}, token_keys = {0}, token_secrets = {0};
    br_captures accounts = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->consumer_key, input, &consumer_keys, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->consumer_secret, input, &consumer_secrets, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->token_key, input, &token_keys, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->token_secret, input, &token_secrets, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->account, input, &accounts, true, &owned_error);
    if (rc && !owned_error) fail(&owned_error, "cannot scan Netsuite matches");
    /* TrimSpace is a no-op. First-seen within each grammar, then this product order. */
    for (size_t i = 0; !rc && i < consumer_keys.len; ++i) {
        for (size_t j = 0; !rc && j < consumer_secrets.len; ++j) {
            for (size_t k = 0; !rc && k < token_keys.len; ++k) {
                for (size_t m = 0; !rc && m < token_secrets.len; ++m) {
                    for (size_t n = 0; !rc && n < accounts.len; ++n) {
                        const char *ck = consumer_keys.items[i], *cs = consumer_secrets.items[j];
                        const char *tk = token_keys.items[k], *ts = token_secrets.items[m];
                        const char *account = accounts.items[n];
                        if (!distinct(ck, cs, tk, ts, account)) continue;
                        br_result result = {0};
                        if (br_finding_pair(&result, detector->type, ck, "consumer_key", cs,
                                            "consumer_secret"))
                            rc = fail(&owned_error, "cannot create Netsuite result");
                        else if (verify && verify_netsuite(ctx, ck, cs, tk, ts, account, &result,
                                                           &owned_error))
                            rc = -1;
                        else if (br_results_push(out, &result))
                            rc = fail(&owned_error, "cannot append Netsuite result");
                        br_result_clear(&result);
                    }
                }
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&consumer_keys); br_captures_clear(&consumer_secrets);
    br_captures_clear(&token_keys); br_captures_clear(&token_secrets); br_captures_clear(&accounts);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static netsuite_patterns patterns;
static const char *const keywords[] = {"netsuite"};
static const br_detector detector = {
    .type = 995, .version = 0, .name = "Netsuite", .custom_name = "",
    .description = "Netsuite is a cloud business management suite. These credentials can be used to access and modify data within Netsuite.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_netsuite,
};

int br_netsuite_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Netsuite detector output");
    *out = NULL;
    static const char *const consumer_key[] = {"netsuite", "consumer", "key"};
    static const char *const consumer_secret[] = {"netsuite", "consumer", "secret"};
    static const char *const token_key[] = {"netsuite", "token", "key"};
    static const char *const token_secret[] = {"netsuite", "token", "secret"};
    static const char *const account[] = {"netsuite", "account", "id"};
    static const char key_capture[] = "\\b([a-zA-Z0-9]{64})\\b";
    static const char account_capture[] = "\\b([a-zA-Z0-9-_]{6,15})\\b";
    if (!patterns.consumer_key &&
        br_regex_compile_prefixed(consumer_key, 3, key_capture, &patterns.consumer_key, error))
        return -1;
    if (!patterns.consumer_secret &&
        br_regex_compile_prefixed(consumer_secret, 3, key_capture, &patterns.consumer_secret, error))
        return -1;
    if (!patterns.token_key &&
        br_regex_compile_prefixed(token_key, 3, key_capture, &patterns.token_key, error))
        return -1;
    if (!patterns.token_secret &&
        br_regex_compile_prefixed(token_secret, 3, key_capture, &patterns.token_secret, error))
        return -1;
    if (!patterns.account &&
        br_regex_compile_prefixed(account, 3, account_capture, &patterns.account, error))
        return -1;
    *out = &detector;
    return 0;
}
