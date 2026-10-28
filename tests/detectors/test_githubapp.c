/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <errno.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static size_t clocks, bad_clock, fail_size, fail_after, fail_part;
static bool frozen;
int clock_gettime(clockid_t which, struct timespec *out)
{
    if (!frozen || which != CLOCK_REALTIME) return (int)syscall(SYS_clock_gettime, which, out);
    ++clocks;
    if (bad_clock && clocks == bad_clock) { errno = EIO; return -1; }
    *out = (struct timespec){1700000000 + (time_t)((clocks - 1) % 2) * 7, 999999999};
    return 0;
}
void *malloc(size_t n)
{
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    return calloc(1, n);
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *value)
{
    if (fail_part && --fail_part == 0) return 1;
    return json_object_object_add_ex(o, name, value, 0);
}
static char *join(const char *a, const char *b)
{
    size_t x = strlen(a), y = strlen(b); char *p = malloc(x+y+2); CHECK(p);
    memcpy(p, a, x); p[x] = '\n'; memcpy(p+x+1, b, y+1); return p;
}
static char *envelope(const unsigned char *der, size_t n)
{
    size_t cap = (n+2)/3*4; unsigned char *b = malloc(cap+1); CHECK(b);
    CHECK(EVP_EncodeBlock(b, der, (int)n) == (int)cap);
    size_t total = cap + 80; char *p = malloc(total); CHECK(p);
    CHECK(snprintf(p, total, "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----", b) > 0);
    OPENSSL_cleanse(b, cap); free(b); return p;
}
static EVP_PKEY *generate(bool pkcs8, int bits, char **pem)
{
    /* Each format needs an independently generated unpadded DER length. */
    for (size_t attempt = 0; ; ++attempt) {
        CHECK(attempt < 100);
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); EVP_PKEY *key = NULL; CHECK(ctx);
        CHECK(EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) == 1 && EVP_PKEY_keygen(ctx, &key) == 1);
        EVP_PKEY_CTX_free(ctx);
        unsigned char *a = NULL, *b = NULL; int na = i2d_PrivateKey(key, &a);
        PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(key); CHECK(p8);
        int nb = i2d_PKCS8_PRIV_KEY_INFO(p8, &b); PKCS8_PRIV_KEY_INFO_free(p8); CHECK(na > 0 && nb > 0);
        bool fits = (pkcs8 ? nb : na) % 3 == 0;
        if (fits) *pem = pkcs8 ? envelope(b, (size_t)nb) : envelope(a, (size_t)na);
        OPENSSL_clear_free(a, (size_t)na); OPENSSL_clear_free(b, (size_t)nb);
        if (fits) return key;
        EVP_PKEY_free(key);
    }
}
static br_bytes decode(const char *p, size_t n)
{
    size_t cap = (n+3)/4*4; unsigned char *b = malloc(cap+1), *out = malloc(cap+1); CHECK(b && out);
    for (size_t i = 0; i < cap; ++i) b[i] = i >= n ? '=' : p[i] == '-' ? '+' : p[i] == '_' ? '/' : (unsigned char)p[i];
    int k = EVP_DecodeBlock(out, b, (int)cap); CHECK(k >= 0); free(b);
    return (br_bytes){out, (size_t)k - (cap-n)};
}
typedef struct {
    EVP_PKEY *key; size_t calls, releases; int status, send_rc;
    const char *issuer, *borrowed_auth; char *copy;
} script;
static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    script *s = user; ++s->calls;
    CHECK(ctx && !strcmp(r->method, "GET") && !strcmp(r->url, "https://api.github.com/app"));
    CHECK(r->profile == BR_HTTP_SANE && r->timeout_ms == 5000 && r->detector_type == 36);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == 3 && !strcmp(r->headers[0].name, "Accept") && !strcmp(r->headers[0].value, "application/vnd.github.v3+json"));
    CHECK(!strcmp(r->headers[1].name, "Authorization") && !strncmp(r->headers[1].value, "Bearer ", 7));
    CHECK(!strcmp(r->headers[2].name, "User-Agent") && !strcmp(r->headers[2].value, "TruffleHog offline"));
    const char *token = r->headers[1].value + 7, *a = strchr(token, '.'), *b = a ? strchr(a+1, '.') : NULL;
    CHECK(a && b && !strchr(b+1, '.') && !strchr(token, '=') && !strchr(token, '+') && !strchr(token, '/'));
    br_bytes h = decode(token, (size_t)(a-token)), c = decode(a+1, (size_t)(b-a-1)), sig = decode(b+1, strlen(b+1));
    static const char header[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    CHECK(h.len == sizeof(header)-1 && !memcmp(h.data, header, h.len));
    char expected[128]; int n = snprintf(expected, sizeof(expected), "{\"exp\":1700000547,\"iat\":1699999940,\"iss\":\"%s\"}", s->issuer);
    CHECK(n > 0 && c.len == (size_t)n && !memcmp(c.data, expected, c.len));
    CHECK(sig.len == (size_t)EVP_PKEY_get_size(s->key));
    EVP_MD_CTX *md = EVP_MD_CTX_new(); EVP_PKEY_CTX *pk = NULL; CHECK(md);
    CHECK(EVP_DigestVerifyInit(md, &pk, EVP_sha256(), NULL, s->key) == 1 && EVP_PKEY_CTX_set_rsa_padding(pk, RSA_PKCS1_PADDING) > 0);
    CHECK(EVP_DigestVerify(md, sig.data, sig.len, (const unsigned char *)token, (size_t)(b-token)) == 1);
    EVP_MD_CTX_free(md); free(h.data); free(c.data); free(sig.data);
    s->borrowed_auth = r->headers[1].value; s->copy = strdup(s->borrowed_auth); CHECK(s->copy);
    response->status = s->status; response->body_error = "ignored read error";
    response->body = (br_slice){(const unsigned char *)"not JSON", 8};
    if (s->send_rc) { *error = strdup("out of memory; context canceled; timeout"); CHECK(*error); }
    return s->send_rc;
}
static void release_request(void *user, br_http_response *response)
{
    script *s = user; ++s->releases; CHECK(response);
    /* Only the original module-owned auth value survives send return.
     * Shared preparation may fail before the backend receives a request. */
    if (s->borrowed_auth) {
        CHECK(s->copy && !strcmp(s->borrowed_auth, s->copy));
        free(s->copy); s->copy = NULL; s->borrowed_auth = NULL;
    } else {
        CHECK(!s->copy && !response->status && !response->headers && !response->nheaders &&
              !response->body.data && !response->body.len && !response->body_error);
    }
}
static bool cancelled(void *user) { (void)user; return true; }
static bool fail_shared_headers(void *user)
{
    (void)user;
    /* The shared cancellation check runs immediately before header allocation;
     * arm here so same-sized OpenSSL allocations cannot consume the fault. */
    fail_size = 3 * sizeof(br_header); fail_after = 1; return false;
}
static void metadata(const br_result *r, const char *key)
{
    CHECK(r->detector_type == 36 && r->raw.len == strlen(key) && !memcmp(r->raw.data, key, r->raw.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->primary_secret.data && !r->primary_secret.len);
    CHECK(!r->detector_name && !r->verification_error && !r->verification_from_cache && !r->structured_data);
    CHECK(!r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    br_json *v = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1 && json_object_object_get_ex(r->secret_parts, "key", &v));
    CHECK((size_t)json_object_get_string_len(v) == strlen(key) && !strcmp(json_object_get_string(v), key));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1 && json_object_object_get_ex(r->extra_data, "rotation_guide", &v));
    CHECK(!strcmp(json_object_get_string(v), "https://howtorotate.com/docs/tutorials/github/"));
}
int main(void)
{
    const br_detector *d = NULL; char *error = NULL;
    CHECK(br_githubapp_init(&d, &error) == 0 && d && !error);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, &error) != 0 && error);
    free(error); error = NULL;
    br_results untouched = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &untouched, &error) != 0 && error && !untouched.len);
    free(error); error = NULL;
    CHECK(d->type == 36 && !d->version && !strcmp(d->name, "GitHubApp") && !*d->custom_name);
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "github") && d->max_credential_span == 1024 && d->max_secret_size == -1 && d->start_offset == -1);
    CHECK(!strcmp(d->description, "GitHub Apps allow you to automate and improve your workflow. GitHub App keys can be used to authenticate and interact with the GitHub API on behalf of the app."));
    const char *invalid = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----";
    char *invalid_input = join("GITHUB 012345", invalid);
    br_results r = test_scan(d, NULL, false, invalid_input, strlen(invalid_input)); CHECK(r.len == 1); metadata(&r.items[0], invalid); br_results_clear(&r);
    frozen = true; clocks = 0;
    r = test_scan(d, NULL, true, invalid_input, strlen(invalid_input)); CHECK(!r.len && !clocks); br_results_clear(&r);
    char *one = NULL, *eight = NULL, *small = NULL; frozen = false;
    EVP_PKEY *key = generate(false, 1024, &one), *key8 = generate(true, 2048, &eight), *key_small = generate(false, 512, &small); frozen = true;
    char *prefixed = join("github", one), *input = join(prefixed, "github 012345"); free(prefixed);
    script s = {.key=key, .issuer="012345", .status=200};
    br_transport transport = {&s, send_request, release_request}; br_scan_ctx ctx = {.transport=&transport, .user_agent="offline"};
    for (int which = 0; which < 2; ++which) {
        char *p = join("github", which ? eight : one), *doc = join(p, "github 012345"); free(p);
        s.key = which ? key8 : key;
        clocks = 0; r = test_scan(d, &ctx, false, doc, strlen(doc)); CHECK(r.len == 1 && !clocks && !s.calls); metadata(&r.items[0], which ? eight : one); br_results_clear(&r);
        clocks = 0; r = test_scan(d, &ctx, true, doc, strlen(doc)); CHECK(r.len == 1 && r.items[0].verified && clocks == 2); metadata(&r.items[0], which ? eight : one); br_results_clear(&r);
        s.calls = s.releases = 0; free(doc);
    }
    s.key = key;
    /* Go getLine removes one final CR before trimming SP/HT, not arbitrary CR. */
    const char *const begin_endings[] = {"\r\r\n", "\r \n", "\r\n"};
    size_t header_len = strcspn(one, "\n"), key_len = strlen(one);
    for (size_t i = 0; i < 3; ++i) {
        size_t ending_len = strlen(begin_endings[i]), pem_len = key_len - 1 + ending_len;
        char *pem = malloc(pem_len + 1); CHECK(pem);
        memcpy(pem, one, header_len); memcpy(pem + header_len, begin_endings[i], ending_len);
        memcpy(pem + header_len + ending_len, one + header_len + 1, key_len - header_len);
        char *p = join("github", pem), *doc = join(p, "github 012345");
        OPENSSL_cleanse(p, strlen(p)); free(p);
        clocks = 0; r = test_scan(d, &ctx, false, doc, strlen(doc));
        CHECK(r.len == 1 && !clocks && !s.calls && !s.releases); metadata(&r.items[0], pem); br_results_clear(&r);
        clocks = 0; r = test_scan(d, &ctx, true, doc, strlen(doc));
        if (i < 2) CHECK(!r.len && !clocks && !s.calls && !s.releases);
        else CHECK(r.len == 1 && r.items[0].verified && clocks == 2 && s.calls == 1 && s.releases == 1);
        br_results_clear(&r); s.calls = s.releases = 0;
        OPENSSL_cleanse(pem, pem_len); free(pem); OPENSSL_cleanse(doc, strlen(doc)); free(doc);
    }
    char *small_prefix = join("github", small), *small_input = join(small_prefix, "github 012345"); free(small_prefix);
    clocks = 0; r = test_scan(d, &ctx, false, small_input, strlen(small_input)); CHECK(r.len == 1 && !clocks && !s.calls); br_results_clear(&r);
    clocks = 0; r = test_scan(d, &ctx, true, small_input, strlen(small_input)); CHECK(!r.len && clocks == 2 && !s.calls); br_results_clear(&r);
    free(small_input); OPENSSL_cleanse(small, strlen(small)); free(small); EVP_PKEY_free(key_small);
    const int statuses[] = {199,200,201,204,299,300,401,403,500};
    for (size_t i = 0; i < sizeof(statuses)/sizeof(*statuses); ++i) {
        s.status = statuses[i]; clocks = 0; r = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(r.len == 1 && r.items[0].verified == (s.status >= 200 && s.status < 300) && !r.items[0].verification_error);
        CHECK(s.calls == i+1 && s.releases == s.calls); br_results_clear(&r);
    }
    s.send_rc = 7; clocks = 0; r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && !r.items[0].verified && !r.items[0].verification_error); br_results_clear(&r); s.send_rc = 0;
    clocks = 0; r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len && clocks == 2); br_results_clear(&r);
    for (size_t i = 1; i <= 2; ++i) {
        bad_clock = i; clocks = 0; CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0 && error && clocks == i && !r.len); free(error); error = NULL;
    }
    bad_clock = 0;
    /* Exact occurrences, key-major independent IDs (including an ID in a key). */
    char *p = join("github", invalid), *twice = join(p, p), *product = join(twice, "github 012345 github 012345"); free(p); free(twice);
    r = test_scan(d, NULL, false, product, strlen(product)); CHECK(r.len == 4); for (size_t i = 0; i < r.len; ++i) metadata(&r.items[i], invalid); br_results_clear(&r); free(product);
    const char *hidden = "github -----BEGIN RSA PRIVATE KEY-----\ngithub 012345\n-----END RSA PRIVATE KEY-----";
    r = test_scan(d, NULL, false, hidden, strlen(hidden)); CHECK(r.len == 1); br_results_clear(&r);
    const char *no_matches[] = {
        "github 012345 -----BEGIN RSA PRIVATE KEY-----\nAAAA=\n-----END RSA PRIVATE KEY-----",
        "github 012345 -----begin RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
        "github 012345 -----BEGIN RSA PRIVATE KEY-----\vAAAA\n-----END RSA PRIVATE KEY-----",
        "github x012345 -----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
    };
    for (size_t i = 0; i < 4; ++i) { r = test_scan(d, NULL, false, no_matches[i], strlen(no_matches[i])); CHECK(!r.len); br_results_clear(&r); }
    for (size_t distance = 39; distance <= 40; ++distance) {
        char prefix[64] = "github"; memset(prefix+6, ' ', distance); prefix[6+distance] = 0;
        char *kp = join(prefix, invalid), *doc = join(kp, "github 012345"); free(kp);
        /* join contributes one newline to the prefix distance. */
        r = test_scan(d, NULL, false, doc, strlen(doc)); CHECK(r.len == (distance == 39 ? 1u : 0u)); br_results_clear(&r); free(doc);
    }
    /* Targeted owned resource failures occur before candidate skip/suppression,
     * and rollback preserves the caller's preexisting finding. */
    br_result sentinel = {.detector_type=999}; CHECK(!br_results_push(&r, &sentinel));
    fail_size = strlen(invalid); fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)invalid_input, strlen(invalid_input)}, &r, &error) != 0 && error && !fail_after && r.len == 1 && r.items[0].detector_type == 999);
    free(error); error = NULL;
    fail_part = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)invalid_input, strlen(invalid_input)}, &r, &error) != 0 && error && !fail_part && r.len == 1); free(error); error = NULL;
    /* Shared allocation, cancellation and invalid-UA failures are false-kept,
     * release an empty response once, and preserve the caller's existing item. */
    for (int mode = 0; mode < 3; ++mode) {
        size_t calls = s.calls, releases = s.releases;
        clocks = 0;
        if (mode == 0) ctx.cancelled = fail_shared_headers;
        if (mode == 1) ctx.cancelled = cancelled;
        if (mode == 2) ctx.user_agent = "offline\r\n";
        int rc = d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        CHECK(rc == 0 && !error && !fail_after);
        CHECK(r.len == 2 && r.items[0].detector_type == 999 && !r.items[1].verified && !r.items[1].verification_error);
        CHECK(clocks == 2 && s.calls == calls && s.releases == releases + 1 && !s.borrowed_auth && !s.copy);
        metadata(&r.items[1], one);
        br_result_clear(&r.items[--r.len]);
        ctx.cancelled = NULL; ctx.user_agent = "offline";
    }
    char *twice_invalid = join(invalid_input, invalid_input);
    fail_size = strlen(invalid); fail_after = 2;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)twice_invalid, strlen(twice_invalid)}, &r, &error) != 0 && error && !fail_after && r.len == 1 && r.items[0].detector_type == 999);
    free(error); error = NULL; free(twice_invalid);
    clocks = 0; fail_size = strlen(one); fail_after = 2;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0 && error && !fail_after && r.len == 1 && !clocks);
    free(error); error = NULL;
    clocks = 0; fail_size = 512 + ((size_t)EVP_PKEY_get_size(key) + 2) / 3 * 4; fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0 && error && !fail_after && r.len == 1 && clocks == 2);
    free(error); error = NULL;
    br_results_clear(&r);
    OPENSSL_cleanse(one, strlen(one)); OPENSSL_cleanse(eight, strlen(eight)); free(one); free(eight); free(input); free(invalid_input); EVP_PKEY_free(key); EVP_PKEY_free(key8);
    return test_finish("githubapp");
}
