/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected C port of TruffleHog v3.97.2 githubapp and jwt/v5 v5.2.3.
 * RSA parsing/signing follows the selected Go behavior, not PEM key labels.
 * Broader Go x509/CRT/multiprime/platform-time acceptance remains partial. */
#include "detectors.h"
#include "captures.h"
#include <json-c/json.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *const keywords[] = {"github"};
static struct { br_regex *keys, *ids; } state;
static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}
static bool crypto_oom(void)
{
    unsigned long e; bool oom = false;
    while ((e = ERR_get_error())) if (ERR_GET_REASON(e) == ERR_R_MALLOC_FAILURE) oom = true;
    return oom;
}
static void erase(br_bytes *b)
{
    if (b->data) OPENSSL_cleanse(b->data, b->len);
    free(b->data); *b = (br_bytes){0};
}
static void discard(br_result *r)
{
    if (r->raw.data) OPENSSL_cleanse(r->raw.data, r->raw.len);
    br_json *part = NULL;
    if (r->secret_parts && json_object_object_get_ex(r->secret_parts, "key", &part))
        OPENSSL_cleanse((void *)json_object_get_string(part), (size_t)json_object_get_string_len(part));
    br_result_clear(r);
}
/* Captures have fixed RSA labels. Decode the envelope in memory without using
 * its type to choose a DER parser. Go PEM removes SP/HT, ignores CR/LF in
 * base64, but does not repair form feeds, missing newlines or padding. */
static int private_key(br_slice pem, EVP_PKEY **out, char **error)
{
    static const char begin[] = "-----BEGIN RSA PRIVATE KEY-----";
    static const char end[] = "-----END RSA PRIVATE KEY-----";
    *out = NULL;
    size_t line = sizeof(begin) - 1;
    while (line < pem.len && pem.data[line] != '\n') ++line;
    if (line == pem.len || pem.len < sizeof(end) - 1) return 1;
    size_t h = line;
    /* Go getLine removes at most one CR immediately before LF, then SP/HT. */
    if (h && pem.data[h-1] == '\r') --h;
    while (h && (pem.data[h-1] == ' ' || pem.data[h-1] == '\t')) --h;
    if (h != sizeof(begin) - 1) return 1;
    size_t stop = pem.len - (sizeof(end) - 1);
    if (!stop || pem.data[stop-1] != '\n' || line >= stop) return 1;
    if (pem.len > INT_MAX) return fail(error, "unsupported: GitHubApp PEM exceeds native length interface");
    br_bytes text = {malloc(pem.len), 0}, der = {malloc(pem.len), pem.len};
    if (!text.data || !der.data) { erase(&text); erase(&der); return fail(error, "cannot allocate GitHubApp PEM data"); }
    for (size_t i = line + 1; i < stop; ++i) {
        unsigned char c = pem.data[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c == '\f') { erase(&text); erase(&der); return 1; }
        text.data[text.len++] = c;
    }
    if (!text.len || text.len % 4) { erase(&text); erase(&der); return 1; }
    int decoded = EVP_DecodeBlock(der.data, text.data, (int)text.len);
    erase(&text);
    if (decoded < 0) { erase(&der); return 1; }
    size_t n = (size_t)decoded; const unsigned char *p = der.data;
    ERR_clear_error();
    EVP_PKEY *key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, (long)n);
    bool oom = crypto_oom();
    if (oom) { EVP_PKEY_free(key); erase(&der); return fail(error, "cannot allocate GitHubApp PKCS1 key"); }
    /* PKCS1 rejects a remainder; PKCS8 deliberately ignores its outer remainder. */
    if (key && p != der.data + n) { EVP_PKEY_free(key); key = NULL; }
    if (!key) {
        p = der.data; ERR_clear_error();
        PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)n);
        oom = crypto_oom();
        if (oom) { PKCS8_PRIV_KEY_INFO_free(p8); erase(&der); return fail(error, "cannot allocate GitHubApp PKCS8 key"); }
        if (p8) {
            ERR_clear_error(); key = EVP_PKCS82PKEY(p8); oom = crypto_oom(); PKCS8_PRIV_KEY_INFO_free(p8);
            if (oom) { EVP_PKEY_free(key); erase(&der); return fail(error, "cannot import GitHubApp PKCS8 key"); }
        }
    }
    erase(&der);
    if (!key) return 1;
    if (!EVP_PKEY_is_a(key, "RSA")) { EVP_PKEY_free(key); return 1; }
    EVP_PKEY_CTX *check = EVP_PKEY_CTX_new(key, NULL);
    if (!check) { EVP_PKEY_free(key); return fail(error, "cannot allocate GitHubApp RSA validation"); }
    ERR_clear_error(); int valid = EVP_PKEY_private_check(check); oom = crypto_oom(); EVP_PKEY_CTX_free(check);
    if (oom) { EVP_PKEY_free(key); return fail(error, "cannot validate GitHubApp RSA key"); }
    if (valid != 1) {
        EVP_PKEY_free(key);
        return fail(error, "unsupported: GitHubApp Go RSA key-shape acceptance");
    }
    BIGNUM *third = NULL;
    ERR_clear_error(); int multiprime = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR3, &third);
    oom = crypto_oom(); BN_clear_free(third);
    if (oom || multiprime) { EVP_PKEY_free(key); return fail(error, oom ? "cannot inspect GitHubApp RSA factors" : "unsupported: GitHubApp multiprime RSA"); }
    *out = key; return 0;
}
static int encode(br_slice in, unsigned char *out, size_t *n, char **error)
{
    if (in.len > INT_MAX || (in.len + 2) / 3 > INT_MAX / 4) return fail(error, "unsupported: GitHubApp base64 length");
    int len = EVP_EncodeBlock(out, in.data, (int)in.len);
    if (len < 0) return fail(error, "GitHubApp base64 encoding failed");
    while (len && out[len-1] == '=') --len;
    for (int i = 0; i < len; ++i) { if (out[i] == '+') out[i] = '-'; else if (out[i] == '/') out[i] = '_'; }
    *n = (size_t)len; return 0;
}
static int jwt(EVP_PKEY *key, br_slice id, br_bytes *auth, char **error)
{
    struct timespec first, second;
    if (clock_gettime(CLOCK_REALTIME, &first)) return fail(error, "GitHubApp first realtime clock failed");
    if (clock_gettime(CLOCK_REALTIME, &second)) return fail(error, "GitHubApp second realtime clock failed");
    intmax_t a = first.tv_sec, b = second.tv_sec;
    if (a < INT64_MIN + 60 || a > INT64_MAX || b > INT64_MAX - 540 || b < INT64_MIN ||
        first.tv_nsec < 0 || first.tv_nsec >= 1000000000 || second.tv_nsec < 0 || second.tv_nsec >= 1000000000)
        return fail(error, "unsupported: GitHubApp JWT clock range");
    char claims[128];
    int count = snprintf(claims, sizeof(claims), "{\"exp\":%" PRId64 ",\"iat\":%" PRId64 ",\"iss\":\"%.*s\"}",
                         (int64_t)b + 540, (int64_t)a - 60, (int)id.len, id.data);
    if (count < 0 || (size_t)count >= sizeof(claims)) return fail(error, "GitHubApp claims formatting failed");
    /* Go's pinned minimum-key check is an ordinary signing rejection. */
    if (EVP_PKEY_get_bits(key) < 1024) return 1;
    int width = EVP_PKEY_get_size(key);
    if (width <= 0) return fail(error, "GitHubApp RSA signature size failed");
    size_t siglen = (size_t)width;
    if (siglen > (SIZE_MAX - 512) / 4 * 3) return fail(error, "GitHubApp JWT size overflow");
    size_t capacity = 512 + (siglen + 2) / 3 * 4;
    auth->data = malloc(capacity); auth->len = capacity;
    br_bytes sig = {malloc(siglen), siglen}; EVP_MD_CTX *md = EVP_MD_CTX_new();
    int rc = -1;
    if (!auth->data || !sig.data || !md) { fail(error, "cannot allocate GitHubApp signature"); goto done; }
    memcpy(auth->data, "Bearer ", 7); size_t at = 7, n;
    static const unsigned char header[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    if (encode((br_slice){header, sizeof(header)-1}, auth->data + at, &n, error)) goto done;
    at += n; auth->data[at++] = '.';
    if (encode((br_slice){(const unsigned char *)claims, (size_t)count}, auth->data + at, &n, error)) goto done;
    at += n; EVP_PKEY_CTX *pk = NULL; ERR_clear_error();
    if (EVP_DigestSignInit(md, &pk, EVP_sha256(), NULL, key) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pk, RSA_PKCS1_PADDING) <= 0 ||
        EVP_DigestSign(md, sig.data, &siglen, auth->data + 7, at - 7) != 1 || siglen != (size_t)width) {
        (void)crypto_oom(); fail(error, "GitHubApp native RSA-SHA256 signing failed"); goto done;
    }
    auth->data[at++] = '.';
    if (encode((br_slice){sig.data, siglen}, auth->data + at, &n, error)) goto done;
    at += n; auth->data[at] = 0; auth->len = at; rc = 0;
 done:
    OPENSSL_cleanse(claims, sizeof(claims)); EVP_MD_CTX_free(md); erase(&sig); return rc;
}
static int text(br_json *map, const char *name, br_slice value, char **error)
{
    if (value.len > INT_MAX) return fail(error, "unsupported: GitHubApp metadata length");
    br_json *v = json_object_new_string_len((const char *)value.data, (int)value.len);
    if (!v) return fail(error, "cannot allocate GitHubApp metadata string");
    if (json_object_object_add(map, name, v)) { json_object_put(v); return fail(error, "cannot add GitHubApp metadata"); }
    return 0;
}
static int finding(br_slice key, br_result *r, char **error)
{
    r->detector_type = 36; r->raw.data = malloc(key.len); r->raw.len = key.len;
    if (!r->raw.data) return fail(error, "cannot allocate GitHubApp Raw");
    memcpy(r->raw.data, key.data, key.len);
    r->secret_parts = json_object_new_object(); r->extra_data = json_object_new_object();
    if (!r->secret_parts || !r->extra_data) return fail(error, "cannot allocate GitHubApp metadata");
    static const char guide[] = "https://howtorotate.com/docs/tutorials/github/";
    return text(r->secret_parts, "key", key, error) ||
           text(r->extra_data, "rotation_guide", (br_slice){(const unsigned char *)guide, sizeof(guide)-1}, error) ? -1 : 0;
}
static int scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!d || !out || (!input.data && input.len)) return fail(error, "invalid GitHubApp scan arguments");
    br_captures keys = {0}, ids = {0}; size_t start = out->len; int rc = -1;
    if (br_captures_find(state.keys, input, &keys, false, error) ||
        br_captures_find(state.ids, input, &ids, false, error)) goto done;
    for (size_t k = 0; k < keys.len; ++k) for (size_t i = 0; i < ids.len; ++i) {
        br_result r = {0}; EVP_PKEY *key = NULL; br_bytes auth = {0};
        if (finding(br_captures_at(&keys, k), &r, error)) { discard(&r); goto done; }
        if (verify) {
            int parsed = private_key(br_captures_at(&keys, k), &key, error);
            if (parsed < 0) { discard(&r); goto done; }
            if (parsed) { discard(&r); continue; }
            int signed_rc = jwt(key, br_captures_at(&ids, i), &auth, error); EVP_PKEY_free(key);
            if (signed_rc || !ctx) {
                erase(&auth); discard(&r);
                if (signed_rc < 0) goto done;
                continue;
            }
            br_header headers[] = {{"Accept", "application/vnd.github.v3+json"}, {"Authorization", (const char *)auth.data}};
            br_http_request request = {.method="GET", .url="https://api.github.com/app", .headers=headers, .nheaders=2,
                                       .profile=BR_HTTP_SANE, .timeout_ms=5000, .detector_type=36};
            br_http_response response = {0}; char *cause = NULL;
            /* The entire shared setup/Do error domain is false-kept, without
             * classifying diagnostics or setting a verification error. */
            int sent = br_http_send(ctx, &request, &response, &cause);
            if (!sent && response.status >= 200 && response.status < 300) r.verified = true;
            br_http_release(ctx, &response); free(cause); erase(&auth);
        }
        if (br_results_push(out, &r)) { discard(&r); fail(error, "cannot append GitHubApp finding"); goto done; }
    }
    rc = 0;
 done:
    for (size_t k = 0; k < keys.len; ++k) OPENSSL_cleanse(keys.items[k], keys.lengths[k]);
    br_captures_clear(&keys); br_captures_clear(&ids);
    if (rc) while (out->len > start) discard(&out->items[--out->len]);
    return rc;
}
int br_githubapp_init(const br_detector **out, char **error)
{
    static br_detector descriptor = {.type=36, .version=0, .name="GitHubApp", .custom_name="",
        .description="GitHub Apps allow you to automate and improve your workflow. GitHub App keys can be used to authenticate and interact with the GitHub API on behalf of the app.",
        .keywords=keywords, .nkeywords=1, .max_secret_size=-1, .start_offset=-1, .max_credential_span=1024, .state=&state, .scan=scan};
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!out) return fail(error, "invalid GitHubApp initializer output");
    if (!state.keys) {
        br_regex *keys = NULL, *ids = NULL;
        /* Go RE2 whitespace excludes vertical tab. '=' is NOT in the source class. */
        if (br_regex_compile_prefixed(keywords, 1, "(-----BEGIN RSA PRIVATE KEY-----[\\t\\n\\f\\r ][A-Za-z0-9+/\\t\\n\\f\\r ]*[\\t\\n\\f\\r ]-----END RSA PRIVATE KEY-----)", &keys, error) ||
            br_regex_compile_prefixed(keywords, 1, "\\b([0-9]{6})\\b", &ids, error)) {
            br_regex_free(keys); br_regex_free(ids); return -1;
        }
        state.keys = keys; state.ids = ids;
    }
    *out = &descriptor; return 0;
}
