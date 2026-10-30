/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/go_time.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "../../src/detectors/json.h"
#include "../../src/go_url.h"

#include <stdarg.h>
#include <stdint.h>

static int strdup_fail;
static char *jwt_strdup_wrap(const char *text)
{
    if (strdup_fail) return NULL;
    return strdup(text);
}
#define jwt_strdup jwt_strdup_wrap

static int each_force;
static int (*real_each)(br_slice, br_json_member_fn, void *) = br_json_each_member;
static int jwt_each(br_slice object, br_json_member_fn fn, void *user)
{
    if (each_force) {
        int rc = each_force;
        each_force = 0;
        return rc;
    }
    return real_each(object, fn, user);
}
#define br_json_each_member jwt_each

static int url_fail;
static int (*real_url_parse)(br_slice, br_go_url_parts *, br_go_url_error *, char **) = br_go_url_parse;
static int url_parse_wrap(br_slice url, br_go_url_parts *parts, br_go_url_error *rejection, char **error)
{
    if (url_fail) return -1;
    return real_url_parse(url, parts, rejection, error);
}
#define br_go_url_parse url_parse_wrap

static int fromdata_force;
static int (*real_fromdata)(EVP_PKEY_CTX *, EVP_PKEY **, int, OSSL_PARAM *) = EVP_PKEY_fromdata;
static int fromdata_wrap(EVP_PKEY_CTX *ctx, EVP_PKEY **key, int selection, OSSL_PARAM *params)
{
    if (fromdata_force) return fromdata_force;
    return real_fromdata(ctx, key, selection, params);
}
#define EVP_PKEY_fromdata fromdata_wrap

static int vsn_calls, vsn_fail_second;
static int vsn_wrap(char *buf, size_t n, const char *fmt, va_list args)
{
    ++vsn_calls;
    if (vsn_fail_second && (vsn_calls % 2) == 0) return -1;
    return vsnprintf(buf, n, fmt, args);
}
#define vsnprintf vsn_wrap

static int time_calls;
static int64_t time_seen[8];
static int time_force_fail;
static size_t releases_at_setter;
static int setter_calls;
static int setter_force;
static const char *setter_cause;
static br_slice setter_secret;

typedef struct {
    const char *body;
    int status;
    const char *send_error;
    int send_rc;
    bool null_cause;
} script_step;

typedef struct {
    script_step *steps;
    size_t nsteps, calls, releases;
    char *urls[6];
    int profiles[6], timeouts[6], types[6];
    bool had_headers[6], had_body[6];
} script_http;

static script_http *active_http;
static const char *step_body_error[6];

static int jwt_time_wrap(int64_t seconds, br_bytes *out, char **fatal)
{
    if (time_calls < 8) time_seen[time_calls] = seconds;
    ++time_calls;
    if (time_force_fail) {
        if (fatal) *fatal = strdup("injected time failure");
        return -1;
    }
    return br_go_time_unix_string(seconds, out, fatal);
}

static int jwt_set_error(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    setter_cause = cause;
    setter_secret = secrets && nsecrets ? secrets[0] : (br_slice){0};
    if (active_http) releases_at_setter = active_http->releases;
    if (setter_force) return setter_force;
    return br_result_set_verification_error(result, cause, secrets, nsecrets);
}

static int jwt_http_send(const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    (void)ctx;
    script_http *http = active_http;
    memset(response, 0, sizeof(*response));
    if (error) *error = NULL;
    if (!http || http->calls >= http->nsteps || http->calls >= 6) return 1;
    size_t i = http->calls++;
    http->urls[i] = request && request->url ? strdup(request->url) : NULL;
    http->profiles[i] = request ? (int)request->profile : -1;
    http->timeouts[i] = request ? (int)request->timeout_ms : -1;
    http->types[i] = request ? request->detector_type : -1;
    http->had_headers[i] = request && request->headers;
    http->had_body[i] = request && request->body.len;
    const script_step *step = &http->steps[i];
    response->status = step->status;
    if (step->body) response->body = (br_slice){(const unsigned char *)step->body, strlen(step->body)};
    if (i < 6 && step_body_error[i]) response->body_error = step_body_error[i];
    if (step->send_rc) {
        if (error && step->send_error && !step->null_cause) *error = strdup(step->send_error);
        return step->send_rc;
    }
    return 0;
}

static void jwt_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    (void)ctx;
    if (active_http) ++active_http->releases;
    if (response) memset(response, 0, sizeof(*response));
}

#define br_go_time_unix_string jwt_time_wrap
#define br_result_set_verification_error jwt_set_error
#define br_http_send jwt_http_send
#define br_http_release jwt_http_release
#define br_jwt_init br_jwt_init_under_test
#include "../../src/detectors/jwt.c"
#undef br_jwt_init
#undef br_http_release
#undef br_http_send
#undef br_result_set_verification_error
#undef br_go_time_unix_string

int br_jwt_init_under_test(const br_detector **out, char **error);

static void reset_hooks(void)
{
    time_calls = 0;
    time_force_fail = 0;
    setter_calls = 0;
    setter_force = 0;
    setter_cause = NULL;
    setter_secret = (br_slice){0};
    releases_at_setter = 0;
    memset(time_seen, 0, sizeof(time_seen));
    memset(step_body_error, 0, sizeof(step_body_error));
    strdup_fail = 0;
    each_force = 0;
    url_fail = 0;
    fromdata_force = 0;
    vsn_calls = 0;
    vsn_fail_second = 0;
}

static void script_clear(script_http *http)
{
    for (size_t i = 0; i < 6; ++i) free(http->urls[i]);
    *http = (script_http){0};
    active_http = NULL;
}

static char *b64url(const unsigned char *in, size_t len)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char *out = malloc(4 * ((len + 2) / 3) + 1);
    CHECK(out);
    size_t n = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned value = (unsigned)in[i] << 16;
        if (i + 1 < len) value |= (unsigned)in[i + 1] << 8;
        if (i + 2 < len) value |= in[i + 2];
        out[n++] = table[(value >> 18) & 63];
        out[n++] = table[(value >> 12) & 63];
        if (i + 1 < len) out[n++] = table[(value >> 6) & 63];
        if (i + 2 < len) out[n++] = table[value & 63];
    }
    out[n] = '\0';
    return out;
}

static char *join_token(const char *header, const char *claims, const unsigned char *sig, size_t sig_len)
{
    char *h = b64url((const unsigned char *)header, strlen(header));
    char *c = b64url((const unsigned char *)claims, strlen(claims));
    char *s = b64url(sig, sig_len);
    size_t n = strlen(h) + strlen(c) + strlen(s) + 3;
    char *token = malloc(n);
    CHECK(token);
    snprintf(token, n, "%s.%s.%s", h, c, s);
    free(h);
    free(c);
    free(s);
    return token;
}

static char *dummy_token(const char *header, const char *claims)
{
    static const unsigned char sig[] = "abcdefghijkl";
    return join_token(header, claims, sig, sizeof(sig) - 1);
}

static EVP_PKEY *generate_rsa(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *key = NULL;
    CHECK(ctx && EVP_PKEY_keygen_init(ctx) == 1);
    CHECK(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1);
    CHECK(EVP_PKEY_generate(ctx, &key) == 1 && key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static EVP_PKEY *generate_ec(const char *group)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[] = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group, 0), OSSL_PARAM_END};
    CHECK(ctx && EVP_PKEY_keygen_init(ctx) == 1);
    CHECK(EVP_PKEY_CTX_set_params(ctx, params) == 1);
    CHECK(EVP_PKEY_generate(ctx, &key) == 1 && key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static EVP_PKEY *generate_ed(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    EVP_PKEY *key = NULL;
    CHECK(ctx && EVP_PKEY_keygen_init(ctx) == 1);
    CHECK(EVP_PKEY_generate(ctx, &key) == 1 && key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static br_bytes sign_digest(EVP_PKEY *key, const char *md_name, const char *signing, bool pss)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *hash = md_name ? EVP_get_digestbyname(md_name) : NULL;
    CHECK(md);
    CHECK(EVP_DigestSignInit(md, pss || !md_name ? &pctx : NULL, hash, NULL, key) == 1);
    if (pss) {
        CHECK(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1);
        CHECK(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1);
    }
    size_t len = 0;
    CHECK(EVP_DigestSign(md, NULL, &len, (const unsigned char *)signing, strlen(signing)) == 1);
    unsigned char *sig = malloc(len);
    CHECK(sig && EVP_DigestSign(md, sig, &len, (const unsigned char *)signing, strlen(signing)) == 1);
    EVP_MD_CTX_free(md);
    return (br_bytes){sig, len};
}

static br_bytes ec_raw_signature(EVP_PKEY *key, const char *md_name, const char *signing, size_t coord)
{
    br_bytes der = sign_digest(key, md_name, signing, false);
    const unsigned char *p = der.data;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)der.len);
    CHECK(sig);
    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);
    unsigned char *raw = calloc(coord * 2, 1);
    CHECK(raw && BN_bn2binpad(r, raw, (int)coord) == (int)coord);
    CHECK(BN_bn2binpad(s, raw + coord, (int)coord) == (int)coord);
    ECDSA_SIG_free(sig);
    free(der.data);
    return (br_bytes){raw, coord * 2};
}

static char *bn_b64(const BIGNUM *value)
{
    int n = BN_num_bytes(value);
    unsigned char *buf = malloc((size_t)n);
    CHECK(buf && BN_bn2bin(value, buf) == n);
    char *encoded = b64url(buf, (size_t)n);
    free(buf);
    return encoded;
}

static char *rsa_jwk(EVP_PKEY *key, const char *kid, bool include_n, bool private_marker)
{
    BIGNUM *n = NULL, *e = NULL;
    CHECK(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) == 1);
    CHECK(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) == 1);
    char *nb = include_n ? bn_b64(n) : NULL;
    char *eb = bn_b64(e);
    char *json = NULL;
    size_t cap = 256 + (nb ? strlen(nb) : 0) + strlen(eb);
    json = malloc(cap);
    CHECK(json);
    if (private_marker && include_n)
        snprintf(json, cap, "{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\",\"d\":\"AA\"}", kid, nb, eb);
    else if (include_n)
        snprintf(json, cap, "{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\"}", kid, nb, eb);
    else
        snprintf(json, cap, "{\"kty\":\"RSA\",\"kid\":\"%s\",\"e\":\"%s\",\"d\":\"AA\"}", kid, eb);
    free(nb);
    free(eb);
    BN_free(n);
    BN_free(e);
    return json;
}

static char *ec_jwk(EVP_PKEY *key, const char *kid, const char *crv, size_t coord)
{
    BIGNUM *x = NULL, *y = NULL;
    CHECK(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1);
    CHECK(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1);
    unsigned char *xb = calloc(coord, 1), *yb = calloc(coord, 1);
    CHECK(xb && yb);
    CHECK(BN_bn2binpad(x, xb, (int)coord) == (int)coord);
    CHECK(BN_bn2binpad(y, yb, (int)coord) == (int)coord);
    char *xs = b64url(xb, coord), *ys = b64url(yb, coord);
    char *json = malloc(strlen(xs) + strlen(ys) + 128);
    CHECK(json);
    snprintf(json, strlen(xs) + strlen(ys) + 128,
             "{\"kty\":\"EC\",\"kid\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\",\"y\":\"%s\"}", kid, crv, xs, ys);
    free(xb);
    free(yb);
    free(xs);
    free(ys);
    BN_free(x);
    BN_free(y);
    return json;
}

static char *ed_jwk(EVP_PKEY *key, const char *kid)
{
    unsigned char pub[32];
    size_t len = sizeof(pub);
    CHECK(EVP_PKEY_get_raw_public_key(key, pub, &len) == 1 && len == 32);
    char *x = b64url(pub, len);
    char *json = malloc(strlen(x) + 64);
    CHECK(json);
    snprintf(json, strlen(x) + 64, "{\"kty\":\"OKP\",\"kid\":\"%s\",\"crv\":\"Ed25519\",\"x\":\"%s\"}", kid, x);
    free(x);
    return json;
}

static char *signed_token(const char *alg, const char *header_fmt, const char *claims, EVP_PKEY *key,
                          br_bytes (*signer)(EVP_PKEY *, const char *))
{
    char header[256];
    snprintf(header, sizeof(header), header_fmt, alg);
    char *h = b64url((const unsigned char *)header, strlen(header));
    char *c = b64url((const unsigned char *)claims, strlen(claims));
    size_t signing_len = strlen(h) + 1 + strlen(c);
    char *signing = malloc(signing_len + 1);
    CHECK(signing);
    snprintf(signing, signing_len + 1, "%s.%s", h, c);
    br_bytes sig = signer(key, signing);
    char *s = b64url(sig.data, sig.len);
    char *token = malloc(strlen(signing) + 1 + strlen(s) + 1);
    CHECK(token);
    snprintf(token, strlen(signing) + 1 + strlen(s) + 1, "%s.%s", signing, s);
    free(h);
    free(c);
    free(signing);
    free(sig.data);
    free(s);
    return token;
}

static br_bytes sign_rs(EVP_PKEY *key, const char *signing) { return sign_digest(key, "SHA256", signing, false); }
static br_bytes sign_ps(EVP_PKEY *key, const char *signing) { return sign_digest(key, "SHA256", signing, true); }
static br_bytes sign_es(EVP_PKEY *key, const char *signing) { return ec_raw_signature(key, "SHA256", signing, 32); }
static br_bytes sign_ed(EVP_PKEY *key, const char *signing) { return sign_digest(key, NULL, signing, false); }

static const char *extra(const br_result *result, const char *key)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, key, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}

static br_scan_ctx ctx_with(script_http *http, br_json *options)
{
    active_http = http;
    return (br_scan_ctx){.options = options};
}

static int scan_raw(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    const char *data, br_results *out, char **error)
{
    br_slice input = {0};
    if (data) input = (br_slice){(const unsigned char *)data, strlen(data)};
    return detector->scan(detector, ctx, verify, input, out, error);
}

static void expect_error(const br_result *result, const char *cause)
{
    CHECK(result->verification_error && !strcmp(result->verification_error, cause));
}

static void expect_jwks(const br_detector *detector, const char *token, const char *jwk,
                        bool verified, const char *cause)
{
    char *set = malloc(strlen(jwk) + 16);
    CHECK(set);
    snprintf(set, strlen(jwk) + 16, "{\"keys\":[%s]}", jwk);
    reset_hooks();
    script_step steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false},
                           {set, 200, NULL, 0, false}};
    script_http http = {.steps = steps, .nsteps = 2};
    br_scan_ctx ctx = ctx_with(&http, NULL);
    br_results results = {0};
    char *error = NULL;
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    CHECK(results.items[0].verified == verified && http.releases == 2);
    if (cause) expect_error(&results.items[0], cause);
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    free(error);
    free(set);
}

static void test_identity(const br_detector *detector)
{
    CHECK(detector->type == 1039 && detector->version == 0);
    CHECK(!strcmp(detector->name, "JWT"));
    CHECK(!strcmp(detector->description, "A JSON Web Token (JWT) is an approach to authentication or authorization that does not depend on server-side data. It may allow access to protected resources."));
    CHECK(detector->nkeywords == 3);
    CHECK(!strcmp(detector->keywords[0], "ewogIC") && !strcmp(detector->keywords[1], "ewoid"));
    CHECK(!strcmp(detector->keywords[2], "eyJ"));
    CHECK(detector->max_secret_size == 4096);
    CHECK(detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->custom_name && !detector->custom_name[0]);
    char *error = NULL;
    CHECK(br_jwt_init_under_test(NULL, &error) == -1 && error);
    free(error);
    const br_detector *again = NULL;
    CHECK(br_jwt_init_under_test(&again, &error) == 0 && !error && again == detector);
    br_results empty = {0};
    br_scan_ctx ctx = {0};
    CHECK(scan_raw(detector, &ctx, false, "", &empty, &error) == 0 && !error && !empty.len);
    CHECK(scan_raw(detector, &ctx, true, NULL, &empty, &error) == 0 && !error);
}

static void test_extraction(const br_detector *detector)
{
    reset_hooks();
    char *none = dummy_token("{\"alg\":\"none\"}", "{\"iss\":\"https://issuer.example\"}");
    char *hmac = dummy_token("{\"alg\":\"HS256\"}", "{\"iss\":\"https://issuer.example\"}");
    char *unknown = dummy_token("{\"alg\":\"none2\"}", "{\"iss\":\"https://issuer.example\"}");
    char *missing = dummy_token("{\"typ\":\"JWT\"}", "{\"iss\":\"https://issuer.example\"}");
    char *bad_header = dummy_token("not-json-at-all!!", "{\"iss\":\"https://issuer.example\"}");
    char *input = NULL;
    size_t cap = strlen(none) * 2 + strlen(hmac) + strlen(unknown) + strlen(missing) + strlen(bad_header) + 64;
    input = malloc(cap);
    CHECK(input);
    snprintf(input, cap, " %s %s %s %s %s x%s ", none, none, hmac, unknown, missing, bad_header);
    br_results results = {0};
    char *error = NULL;
    br_scan_ctx ctx = {0};
    CHECK(scan_raw(detector, &ctx, false, input, &results, &error) == 0 && !error);
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(none) && !memcmp(results.items[0].raw.data, none, strlen(none)));
    CHECK(!strcmp(extra(&results.items[0], "alg"), "none"));
    CHECK(!strcmp(extra(&results.items[0], "iss"), "https://issuer.example"));
    CHECK(!extra(&results.items[0], "iat")[0] && !extra(&results.items[0], "exp")[0]);
    CHECK(time_calls == 0 && setter_calls == 0 && !results.items[0].verified);
    CHECK(json_object_object_length(results.items[0].extra_data) == 4);
    br_results_clear(&results);
    free(input);
    free(none);
    free(hmac);
    free(unknown);
    free(missing);
    free(bad_header);
}

static void test_dates(const br_detector *detector)
{
    reset_hooks();
    char *zero = dummy_token("{\"alg\":\"none\"}", "{\"iat\":0,\"exp\":0}");
    char *fraction = dummy_token("{\"alg\":\"none\"}", "{\"iat\":0.0000000001}");
    char *present = dummy_token("{\"alg\":\"none\"}", "{\"iat\":1700000000,\"exp\":4102444800}");
    char *bad = dummy_token("{\"alg\":\"none\"}", "{\"iat\":\"later\",\"iss\":1}");
    br_scan_ctx ctx = {0};
    char *error = NULL;
    br_results results = {0};
    CHECK(scan_raw(detector, &ctx, false, zero, &results, &error) == 0 && !error && results.len == 1);
    CHECK(time_calls == 0 && !extra(&results.items[0], "iat")[0] && !extra(&results.items[0], "exp")[0]);
    br_results_clear(&results);
    reset_hooks();
    CHECK(scan_raw(detector, &ctx, false, fraction, &results, &error) == 0 && !error && results.len == 1);
    CHECK(time_calls == 1 && time_seen[0] == 0);
    br_bytes formatted = {0};
    CHECK(br_go_time_unix_string(0, &formatted, &error) == 0 && !error);
    CHECK(!strcmp(extra(&results.items[0], "iat"), (char *)formatted.data));
    CHECK(!extra(&results.items[0], "exp")[0]);
    free(formatted.data);
    br_results_clear(&results);
    reset_hooks();
    CHECK(scan_raw(detector, &ctx, false, present, &results, &error) == 0 && !error && results.len == 1);
    CHECK(time_calls == 2 && time_seen[0] == 1700000000 && time_seen[1] == 4102444800);
    formatted = (br_bytes){0};
    CHECK(br_go_time_unix_string(1700000000, &formatted, &error) == 0);
    CHECK(!strcmp(extra(&results.items[0], "iat"), (char *)formatted.data));
    free(formatted.data);
    formatted = (br_bytes){0};
    CHECK(br_go_time_unix_string(4102444800, &formatted, &error) == 0);
    CHECK(!strcmp(extra(&results.items[0], "exp"), (char *)formatted.data));
    free(formatted.data);
    br_results_clear(&results);
    reset_hooks();
    CHECK(scan_raw(detector, &ctx, false, bad, &results, &error) == 0 && !error && results.len == 1);
    CHECK(time_calls == 0 && !extra(&results.items[0], "iss")[0] && !extra(&results.items[0], "iat")[0]);
    br_results_clear(&results);
    reset_hooks();
    time_force_fail = 1;
    CHECK(scan_raw(detector, &ctx, false, present, &results, &error) == -1);
    CHECK(error && !strcmp(error, "injected time failure") && !results.len);
    free(error);
    free(zero);
    free(fraction);
    free(present);
    free(bad);
}

static void add_prior(br_results *results)
{
    br_result prior = {0};
    CHECK(br_finding_key_bytes(&prior, 1, (br_slice){(const unsigned char *)"prior", 5}, "key") == 0);
    CHECK(br_results_push(results, &prior) == 0);
}

static void test_verify_gates(const br_detector *detector)
{
    reset_hooks();
    char *token = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                              "{\"iss\":\"https://issuer.example\",\"exp\":4102444800}");
    char *expired = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                                "{\"iss\":\"https://issuer.example\",\"exp\":1}");
    char *future = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                               "{\"iss\":\"https://issuer.example\",\"iat\":4102444800,\"exp\":4102444801}");
    char *http_iss = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                                 "{\"iss\":\"http://issuer.example\",\"exp\":4102444800}");
    char *no_kid = dummy_token("{\"alg\":\"RS256\"}",
                               "{\"iss\":\"https://issuer.example\",\"exp\":4102444800}");
    char *path = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                             "{\"iss\":\"https://issuer.example/tenant\",\"exp\":4102444800}");
    script_http http = {0};
    script_step steps[] = {{"{}", 200, NULL, 0, false}};
    http.steps = steps;
    http.nsteps = 1;
    br_scan_ctx ctx = ctx_with(&http, NULL);
    br_results results = {0};
    char *error = NULL;
    CHECK(scan_raw(detector, &ctx, true, expired, &results, &error) == 0 && !error && results.len == 1);
    CHECK(!results.items[0].verified && !results.items[0].verification_error && !http.calls && setter_calls == 1 && !setter_cause);
    br_results_clear(&results);
    reset_hooks();
    http.calls = 0;
    CHECK(scan_raw(detector, &ctx, true, future, &results, &error) == 0 && !error && !http.calls && results.len == 1);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    reset_hooks();
    CHECK(scan_raw(detector, &ctx, true, http_iss, &results, &error) == 0 && !error && !http.calls);
    br_results_clear(&results);
    reset_hooks();
    CHECK(scan_raw(detector, &ctx, true, no_kid, &results, &error) == 0 && !error && !http.calls);
    br_results_clear(&results);
    reset_hooks();
    CHECK(scan_raw(detector, &ctx, true, path, &results, &error) == 0 && !error && results.len == 1 && !http.calls);
    expect_error(&results.items[0], "unsupported: JWT issuer URL JoinPath");
    CHECK(setter_calls == 1 && setter_secret.len == strlen(path) && !memcmp(setter_secret.data, path, setter_secret.len));
    br_results_clear(&results);
    reset_hooks();
    active_http = &http;
    CHECK(scan_raw(detector, NULL, true, token, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to perform OIDC discovery: failed to create request: net/http: nil Context");
    CHECK(!http.calls && !http.releases && setter_secret.len == strlen(token));
    br_results_clear(&results);
    reset_hooks();
    setter_force = 1;
    add_prior(&results);
    CHECK(scan_raw(detector, NULL, true, token, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set JWT verification error") && results.len == 1);
    CHECK(results.items[0].detector_type == 1 && !http.releases);
    free(error);
    br_results_clear(&results);
    script_clear(&http);
    free(token);
    free(expired);
    free(future);
    free(http_iss);
    free(no_kid);
    free(path);
}

static void test_http_policy(const br_detector *detector)
{
    reset_hooks();
    char *token = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                              "{\"iss\":\"https://issuer.example/\",\"exp\":4102444800}");
    char *query = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                              "{\"iss\":\"https://user:pass@issuer.example?x=1#frag\",\"exp\":4102444800}");
    script_step status[] = {{"nope", 404, NULL, 0, false}};
    script_http http = {.steps = status, .nsteps = 1};
    br_scan_ctx ctx = ctx_with(&http, NULL);
    br_results results = {0};
    char *error = NULL;
    add_prior(&results);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported: JWT HTTP status text"));
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1 && results.items[0].detector_type == 1);
    CHECK(http.profiles[0] == BR_HTTP_DETECTOR_PUBLIC && http.timeouts[0] == 0 && http.types[0] == 1039);
    CHECK(!http.had_headers[0] && !http.had_body[0]);
    CHECK(http.urls[0] && !strcmp(http.urls[0], "https://issuer.example/.well-known/openid-configuration"));
    free(error);
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    script_step denied[] = {{NULL, 0, "dial failed", 1, false}};
    http = (script_http){.steps = denied, .nsteps = 1};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to perform OIDC discovery: failed to perform request: dial failed");
    CHECK(!results.items[0].verified && http.releases == 1 && releases_at_setter == 1);
    CHECK(setter_secret.len == strlen(token));
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    script_step absent[] = {{NULL, 0, NULL, 1, true}};
    http = (script_http){.steps = absent, .nsteps = 1};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    CHECK(!results.items[0].verified && !results.items[0].verification_error && !setter_cause);
    CHECK(http.releases == 1 && setter_calls == 1);
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    setter_force = 1;
    http = (script_http){.steps = denied, .nsteps = 1};
    ctx = ctx_with(&http, NULL);
    add_prior(&results);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set JWT verification error") && results.len == 1 && http.releases == 1);
    free(error);
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    script_step discovery[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks?x=1\"} trailing", 200, NULL, 0, false},
                               {NULL, 0, "jwks down", 1, false}};
    http = (script_http){.steps = discovery, .nsteps = 2};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, query, &results, &error) == 0 && !error && results.len == 1);
    CHECK(http.calls == 2 && http.releases == 2);
    CHECK(!strcmp(http.urls[0], "https://user:pass@issuer.example/.well-known/openid-configuration?x=1#frag"));
    CHECK(!strcmp(http.urls[1], "https://issuer.example/jwks?x=1"));
    expect_error(&results.items[0], "failed to fetch JWKS: failed to perform request: jwks down");
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    script_step continued[] = {
        {"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false},
        {"{\"keys\":[{\"kty\":\"oct\",\"kid\":\"other\"}]}", 200, NULL, 0, false},
    };
    step_body_error[0] = "read failed";
    http = (script_http){.steps = continued, .nsteps = 2};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    CHECK(http.calls == 2 && http.releases == 2);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    script_step cut[] = {{"{\"jwks_uri\":", 200, NULL, 0, false}};
    step_body_error[0] = "read failed";
    http = (script_http){.steps = cut, .nsteps = 1};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to decode OIDC discovery document: read failed");
    CHECK(http.calls == 1 && http.releases == 1 && !results.items[0].verified);
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    script_step jwks_read[] = {
        {"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false},
        {"{\"keys\":[]}", 200, NULL, 0, false},
    };
    step_body_error[1] = "read failed";
    http = (script_http){.steps = jwks_read, .nsteps = 2};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to parse JWKS: jwk.ParseReader: failed to read from io.Reader: read failed");
    CHECK(http.calls == 2 && http.releases == 2 && !results.items[0].verified);
    br_results_clear(&results);
    script_clear(&http);
    free(token);
    free(query);
}

static void test_jwks_errors(const br_detector *detector)
{
    reset_hooks();
    char *token = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}",
                              "{\"iss\":\"https://issuer.example\",\"exp\":4102444800}");
    const char *cases[] = {
        "{\"jwks_uri\":\"\"}",
        "invalid JWKS URL: parse \"\": empty url",
        "{\"jwks_uri\":\"http://issuer.example/jwks\"}",
        "invalid JWKS URL: only https scheme is supported",
        "{\"jwks_uri\":\"https://issuer.example:abc/jwks\"}",
        "invalid JWKS URL: parse \"https://issuer.example:abc/jwks\": invalid port \":abc\" after host",
        "{\"jwks_uri\":\"https://evil.example/jwks\"}",
        "JWKS host does not match issuer host: \"https://evil.example/jwks\"",
        "{\"jwks_uri\":1}",
        "failed to decode OIDC discovery document: json: cannot unmarshal number into Go struct field .jwks_uri of type string",
        "s",
        "failed to decode OIDC discovery document: invalid character 's' looking for beginning of value",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i += 2) {
        reset_hooks();
        script_step steps[] = {{cases[i], 200, NULL, 0, false}};
        script_http http = {.steps = steps, .nsteps = 1};
        br_scan_ctx ctx = ctx_with(&http, NULL);
        br_results results = {0};
        char *error = NULL;
        CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
        expect_error(&results.items[0], cases[i + 1]);
        CHECK(http.calls == 1 && http.releases == 1 && !results.items[0].verified);
        br_results_clear(&results);
        script_clear(&http);
    }
    script_step bad_json[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false}, {"s", 200, NULL, 0, false}};
    script_http http = {.steps = bad_json, .nsteps = 2};
    br_scan_ctx ctx = ctx_with(&http, NULL);
    br_results results = {0};
    char *error = NULL;
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: error reading token: invalid character 's' looking for beginning of value");
    br_results_clear(&results);
    script_clear(&http);
    reset_hooks();
    script_step bad_key[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false},
                             {"{\"keys\":[{\"kty\":\"NOPE\",\"kid\":\"k\"}]}", 200, NULL, 0, false}};
    http = (script_http){.steps = bad_key, .nsteps = 2};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to decode key #0 in \"keys\": invalid key type from JSON (NOPE)");
    br_results_clear(&results);
    script_clear(&http);
    free(token);
}

static void test_drop_flag(const br_detector *detector)
{
    reset_hooks();
    char *token = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}", "{\"iss\":\"http://issuer.example\",\"exp\":4102444800}");
    char *errored = dummy_token("{\"alg\":\"RS256\",\"kid\":\"k\"}", "{\"iss\":\"https://issuer.example/tenant\",\"exp\":4102444800}");
    br_json *options = json_object_new_object();
    CHECK(json_object_object_add(options, "DropUnverifiedJWTResults", json_object_new_boolean(1)) == 0);
    br_scan_ctx ctx = {.options = options};
    br_results results = {0};
    char *error = NULL;
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && !results.len);
    CHECK(scan_raw(detector, &ctx, false, token, &results, &error) == 0 && !error && results.len == 1);
    br_results_clear(&results);
    CHECK(scan_raw(detector, &ctx, true, errored, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "unsupported: JWT issuer URL JoinPath");
    br_results_clear(&results);
    json_object_object_del(options, "DropUnverifiedJWTResults");
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    br_results_clear(&results);
    json_object_put(options);
    free(token);
    free(errored);
}

static void expect_verified(const br_detector *detector, const char *token, const char *discovery, const char *jwks)
{
    reset_hooks();
    script_step steps[] = {{discovery, 200, NULL, 0, false}, {jwks, 200, NULL, 0, false}};
    script_http http = {.steps = steps, .nsteps = 2};
    br_scan_ctx ctx = ctx_with(&http, NULL);
    br_results results = {0};
    char *error = NULL;
    CHECK(scan_raw(detector, &ctx, true, token, &results, &error) == 0 && !error && results.len == 1);
    if (!results.items[0].verified) {
        fprintf(stderr, "unverified cause: %s\n",
                results.items[0].verification_error ? results.items[0].verification_error : "(nil)");
    }
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 2 && http.releases == 2 && releases_at_setter == 2 && setter_calls == 1 && !setter_cause);
    br_json *options = json_object_new_object();
    json_object_object_add(options, "DropUnverifiedJWTResults", json_object_new_boolean(1));
    br_results dropped = {0};
    br_scan_ctx flagged = {.transport = ctx.transport, .options = options};
    active_http = &http;
    http.calls = http.releases = 0;
    CHECK(scan_raw(detector, &flagged, true, token, &dropped, &error) == 0 && !error && dropped.len == 1 && dropped.items[0].verified);
    br_results_clear(&results);
    br_results_clear(&dropped);
    json_object_put(options);
    script_clear(&http);
}

static void test_signatures(const br_detector *detector)
{
    const char *claims = "{\"iss\":\"https://issuer.example\",\"exp\":4102444800}";
    const char *header = "{\"alg\":\"%s\",\"kid\":\"k\"}";
    EVP_PKEY *rsa = generate_rsa();
    char *rs = signed_token("RS256", header, claims, rsa, sign_rs);
    char *ps = signed_token("PS256", header, claims, rsa, sign_ps);
    char *jwk = rsa_jwk(rsa, "k", true, false);
    char *set = malloc(strlen(jwk) + 32);
    CHECK(set);
    snprintf(set, strlen(jwk) + 32, "{\"keys\":[%s]}", jwk);
    expect_verified(detector, rs, "{\"jwks_uri\":\"https://issuer.example/jwks\"}", set);
    expect_verified(detector, ps, "{\"jwks_uri\":\"https://issuer.example/jwks\"}", set);
    unsigned char *sig = (unsigned char *)strrchr(rs, '.') + 1;
    if (sig[0] == 'A') sig[0] = 'B'; else sig[0] = 'A';
    reset_hooks();
    script_step steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false}, {set, 200, NULL, 0, false}};
    script_http http = {.steps = steps, .nsteps = 2};
    br_scan_ctx ctx = ctx_with(&http, NULL);
    br_results results = {0};
    char *error = NULL;
    CHECK(scan_raw(detector, &ctx, true, rs, &results, &error) == 0 && !error && results.len == 1);
    CHECK(!results.items[0].verified && !results.items[0].verification_error && http.releases == 2);
    br_results_clear(&results);
    script_clear(&http);
    char *private_jwk = rsa_jwk(rsa, "k", true, true);
    char *private_set = malloc(strlen(private_jwk) + 32);
    snprintf(private_set, strlen(private_jwk) + 32, "{\"keys\":[%s]}", private_jwk);
    char *fresh = signed_token("RS256", header, claims, rsa, sign_rs);
    script_step private_steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false}, {private_set, 200, NULL, 0, false}};
    http = (script_http){.steps = private_steps, .nsteps = 2};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, fresh, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to export matching key: jwk.Export: failed to export jwk.Key to raw format: missing \"q\" value");
    br_results_clear(&results);
    script_clear(&http);
    char *missing = rsa_jwk(rsa, "k", false, true);
    char *missing_set = malloc(strlen(missing) + 32);
    snprintf(missing_set, strlen(missing) + 32, "{\"keys\":[%s]}", missing);
    script_step missing_steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false}, {missing_set, 200, NULL, 0, false}};
    http = (script_http){.steps = missing_steps, .nsteps = 2};
    ctx = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &ctx, true, fresh, &results, &error) == 0 && !error && results.len == 1);
    expect_error(&results.items[0], "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to decode key #0 in \"keys\": failed to unmarshal JSON into key (*jwk.rsaPrivateKey): failed to unmarshal JSON into key (*jwk.rsaPrivateKey): required field n is missing");
    br_results_clear(&results);
    script_clear(&http);
    EVP_PKEY *ec = generate_ec("P-256");
    char *es = signed_token("ES256", header, claims, ec, sign_es);
    char *ec_key = ec_jwk(ec, "k", "P-256", 32);
    char *ec_set = malloc(strlen(ec_key) + 32);
    snprintf(ec_set, strlen(ec_key) + 32, "{\"keys\":[%s]}", ec_key);
    expect_verified(detector, es, "{\"jwks_uri\":\"https://issuer.example/jwks\"}", ec_set);
    EVP_PKEY *ed = generate_ed();
    char *eddsa = signed_token("EdDSA", header, claims, ed, sign_ed);
    char *ed_key = ed_jwk(ed, "k");
    char *ed_set = malloc(strlen(ed_key) + 32);
    snprintf(ed_set, strlen(ed_key) + 32, "{\"keys\":[%s]}", ed_key);
    expect_verified(detector, eddsa, "{\"jwks_uri\":\"https://issuer.example/jwks\"}", ed_set);
    EVP_PKEY_free(rsa);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(ed);
    free(rs);
    free(ps);
    free(jwk);
    free(set);
    free(private_jwk);
    free(private_set);
    free(fresh);
    free(missing);
    free(missing_set);
    free(es);
    free(ec_key);
    free(ec_set);
    free(eddsa);
    free(ed_key);
    free(ed_set);
}

static void test_source_policy(const br_detector *detector)
{
    reset_hooks();
    char number[519];
    number[0] = '1';
    memset(number + 1, '0', 512);
    memcpy(number + 513, "e-512", 5);
    number[518] = '\0';
    char claims[560];
    snprintf(claims, sizeof(claims), "{\"iat\":%s}", number);
    char *wide = dummy_token("{\"alg\":\"none\"}", claims);
    br_results results = {0};
    char *error = NULL;
    br_scan_ctx ctx = {0};
    CHECK(scan_raw(detector, &ctx, false, wide, &results, &error) == 0 && !error && results.len == 1);
    br_bytes formatted = {0};
    CHECK(br_go_time_unix_string(1, &formatted, &error) == 0 && !error);
    CHECK(time_calls == 1 && time_seen[0] == 1);
    CHECK(!strcmp(extra(&results.items[0], "iat"), (char *)formatted.data));
    free(formatted.data);
    br_results_clear(&results);
    free(wide);

    reset_hooks();
    char *absent = dummy_token("{\"alg\":\"none\"}", "{\"iat\":null}");
    CHECK(scan_raw(detector, &ctx, false, absent, &results, &error) == 0 && !error && results.len == 1);
    CHECK(!extra(&results.items[0], "iat")[0] && time_calls == 0);
    br_results_clear(&results);
    script_http http = {0};
    br_scan_ctx live = ctx_with(&http, NULL);
    CHECK(scan_raw(detector, &live, true, absent, &results, &error) == 0 && !error && results.len == 1);
    CHECK(!results.items[0].verified && http.calls == 0 && time_calls == 0);
    br_results_clear(&results);
    free(absent);

    reset_hooks();
    char *boundary = dummy_token("{\"alg\":\"none\"}", "{\"iat\":9223372036854775808}");
    CHECK(scan_raw(detector, &ctx, false, boundary, &results, &error) == 0 && !error && results.len == 1);
    CHECK(time_calls == 1 && time_seen[0] == INT64_MIN);
    br_results_clear(&results);
    free(boundary);

    br_bytes copied = {0};
    CHECK(copy_limited((br_slice){NULL, 4}, &copied, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(copy_limited((br_slice){NULL, 4}, &copied, NULL) == -1);

    reset_hooks();
    char *kid = dummy_token("{\"alg\":\"none\",\"kid\":\"k\"}", "{\"iss\":\"https://issuer.example\"}");
    script_step steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false}};
    http = (script_http){.steps = steps, .nsteps = 1};
    live = ctx_with(&http, NULL);
    strdup_fail = 1;
    step_body_error[0] = "";
    CHECK(scan_raw(detector, &live, true, kid, &results, NULL) == -1);
    CHECK(http.releases == 1 && !results.len);
    strdup_fail = 0;
    br_results_clear(&results);

    reset_hooks();
    http.calls = http.releases = 0;
    url_fail = 1;
    CHECK(scan_raw(detector, &live, true, kid, &results, NULL) == -1 && !results.len && !http.calls);
    url_fail = 0;

    reset_hooks();
    br_json *options = json_object_new_object();
    json_object_object_add(options, "DropUnverifiedJWTResults", json_object_new_boolean(1));
    script_step failed[] = {{NULL, 0, NULL, 1, true}};
    http = (script_http){.steps = failed, .nsteps = 1};
    live = ctx_with(&http, options);
    CHECK(scan_raw(detector, &live, true, kid, &results, &error) == 0 && !error && results.len == 1);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    CHECK(setter_calls == 1 && !setter_cause && http.releases == 1);
    br_results_clear(&results);
    json_object_put(options);
    script_clear(&http);

    br_bytes uri = {0};
    char *cause = NULL;
    const char *folded = "{\"JWKS_URI\":\"https://issuer.example/jwks\"}";
    CHECK(decode_discovery((br_slice){(const unsigned char *)folded, strlen(folded)}, NULL, &uri, &cause) == 0 && !cause);
    CHECK(uri.len == strlen("https://issuer.example/jwks") && !memcmp(uri.data, "https://issuer.example/jwks", uri.len));
    free(uri.data);
    const char *kept = "{\"jwks_uri\":\"https://issuer.example/jwks\",\"jwks_uri\":null}";
    CHECK(decode_discovery((br_slice){(const unsigned char *)kept, strlen(kept)}, NULL, &uri, &cause) == 0 && !cause);
    CHECK(uri.len == strlen("https://issuer.example/jwks"));
    free(uri.data);
    const char *last = "{\"jwks_uri\":\"https://a.example/jwks\",\"jwks_uri\":\"https://b.example/jwks\"}";
    CHECK(decode_discovery((br_slice){(const unsigned char *)last, strlen(last)}, NULL, &uri, &cause) == 0 && !cause);
    CHECK(uri.len == strlen("https://b.example/jwks") && !memcmp(uri.data, "https://b.example/jwks", uri.len));
    free(uri.data);
    const char *sticky = "{\"jwks_uri\":1,\"jwks_uri\":\"https://issuer.example/jwks\"}";
    CHECK(decode_discovery((br_slice){(const unsigned char *)sticky, strlen(sticky)}, NULL, &uri, &cause) == 1);
    CHECK(cause && strstr(cause, ".jwks_uri") && !uri.data);
    free(cause);
    cause = NULL;
    CHECK(decode_discovery((br_slice){(const unsigned char *)"null", 4}, NULL, &uri, &cause) == 0 && !cause && !uri.len);
    each_force = 1;
    CHECK(decode_discovery((br_slice){(const unsigned char *)folded, strlen(folded)}, NULL, &uri, &cause) == -1);
    CHECK(cause && !strcmp(cause, "cannot decode JWT discovery document"));
    free(cause);
    cause = NULL;

    jwt_jwk *keys = NULL;
    size_t nkeys = 0;
    const char *both = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"a\"}],\"keys\":[{\"kty\":\"oct\",\"kid\":\"b\"}]}";
    CHECK(parse_jwks((br_slice){(const unsigned char *)both, strlen(both)}, &keys, &nkeys, &cause) == 0 && !cause && nkeys == 2);
    CHECK(keys[0].has_kid && keys[1].has_kid && keys[0].kid.len == 1 && keys[1].kid.data[0] == 'b');
    for (size_t i = 0; i < nkeys; ++i) jwk_clear(&keys[i]);
    free(keys);
    const char *empty_keys = "{\"keys\":null}{\"extra\":1}";
    CHECK(parse_jwks((br_slice){(const unsigned char *)empty_keys, strlen(empty_keys)}, &keys, &nkeys, &cause) == 0 && !cause && !nkeys);
    const char *folded_keys = "{\"Keys\":[{\"kty\":\"oct\",\"kid\":\"a\"}]}";
    CHECK(parse_jwks((br_slice){(const unsigned char *)folded_keys, strlen(folded_keys)}, &keys, &nkeys, &cause) == 1);
    CHECK(cause && strstr(cause, "sole key"));
    free(cause);
    cause = NULL;
    const char *padded = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"YQ==QQ\",\"e\":\"AQ\"}]}";
    CHECK(parse_jwks((br_slice){(const unsigned char *)padded, strlen(padded)}, &keys, &nkeys, &cause) == 1);
    CHECK(cause && strstr(cause, "expected base64 encoded []byte"));
    free(cause);
    cause = NULL;
    const char *numeric_kid = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":1,\"n\":\"AQ\",\"e\":\"AQ\"}]}";
    CHECK(parse_jwks((br_slice){(const unsigned char *)numeric_kid, strlen(numeric_kid)}, &keys, &nkeys, &cause) == 1);
    CHECK(cause && strstr(cause, "kid") && !strstr(cause, "cannot parse JWKS"));
    free(cause);
    cause = NULL;
    const char *later = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k\"},{\"kty\":\"RSA\"}]}";
    CHECK(parse_jwks((br_slice){(const unsigned char *)later, strlen(later)}, &keys, &nkeys, &cause) == 1);
    CHECK(cause && strstr(cause, "required field n is missing"));
    free(cause);
    cause = NULL;
    free(kid);

    reset_hooks();
    vsn_fail_second = 1;
    const char *bad_type = "{\"jwks_uri\":1}";
    CHECK(decode_discovery((br_slice){(const unsigned char *)bad_type, strlen(bad_type)}, NULL, &uri, NULL) == -1);
    vsn_fail_second = 0;

    unsigned char quoted_uri[] = {'h', 't', 't', 'p', 's', ':', '/', '/', 'a', 0, '.', 'e'};
    CHECK(invalid_jwks_url((br_slice){quoted_uri, sizeof(quoted_uri)}, &cause) == 1);
    CHECK(cause && !strcmp(cause, "unsupported: JWT URL quote"));
    free(cause);
    cause = NULL;

    EVP_PKEY *rsa = generate_rsa();
    const char *signed_claims = "{\"iss\":\"https://issuer.example\",\"exp\":4102444800}";
    char *forced = signed_token("RS256", "{\"alg\":\"%s\",\"kid\":\"k\"}", signed_claims, rsa, sign_rs);
    char *public_jwk = rsa_jwk(rsa, "k", true, false);
    char *public_set = malloc(strlen(public_jwk) + 32);
    CHECK(public_set);
    snprintf(public_set, strlen(public_jwk) + 32, "{\"keys\":[%s]}", public_jwk);
    reset_hooks();
    script_step force_steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false},
                                 {public_set, 200, NULL, 0, false}};
    script_http force_http = {.steps = force_steps, .nsteps = 2};
    br_scan_ctx force_ctx = ctx_with(&force_http, NULL);
    fromdata_force = 2;
    CHECK(scan_raw(detector, &force_ctx, true, forced, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot export JWT key") && !results.len && force_http.releases == 2);
    free(error);
    error = NULL;
    fromdata_force = 0;
    EVP_PKEY_free(rsa);
    free(forced);
    free(public_jwk);
    free(public_set);

    EVP_PKEY *p384 = generate_ec("P-384");
    char *wide_key = ec_jwk(p384, "k", "P-384", 48);
    char *wide_set = malloc(strlen(wide_key) + 32);
    CHECK(wide_set);
    snprintf(wide_set, strlen(wide_key) + 32, "{\"keys\":[%s]}", wide_key);
    EVP_PKEY *p256 = generate_ec("P-256");
    char *narrow = signed_token("ES256", "{\"alg\":\"%s\",\"kid\":\"k\"}", signed_claims, p256, sign_es);
    reset_hooks();
    script_step curve_steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false},
                                 {wide_set, 200, NULL, 0, false}};
    script_http curve_http = {.steps = curve_steps, .nsteps = 2};
    br_scan_ctx curve_ctx = ctx_with(&curve_http, NULL);
    CHECK(scan_raw(detector, &curve_ctx, true, narrow, &results, &error) == 0 && !error && results.len == 1);
    CHECK(!results.items[0].verified && !results.items[0].verification_error && curve_http.releases == 2);
    br_results_clear(&results);
    EVP_PKEY_free(p384);
    EVP_PKEY_free(p256);
    free(wide_key);
    free(wide_set);
    free(narrow);

    unsigned char long_x[33], short_y[32];
    memset(long_x, 1, sizeof(long_x));
    memset(short_y, 2, sizeof(short_y));
    char *xs = b64url(long_x, sizeof(long_x));
    char *ys = b64url(short_y, sizeof(short_y));
    size_t over_len = strlen(xs) + strlen(ys) + 80;
    char *over = malloc(over_len);
    CHECK(over);
    snprintf(over, over_len,
             "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"}]}",
             xs, ys);
    char *over_token = dummy_token("{\"alg\":\"ES256\",\"kid\":\"k\"}", signed_claims);
    reset_hooks();
    script_step over_steps[] = {{"{\"jwks_uri\":\"https://issuer.example/jwks\"}", 200, NULL, 0, false},
                                {over, 200, NULL, 0, false}};
    script_http over_http = {.steps = over_steps, .nsteps = 2};
    br_scan_ctx over_ctx = ctx_with(&over_http, NULL);
    error = NULL;
    CHECK(scan_raw(detector, &over_ctx, true, over_token, &results, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported: JWT JWK key material") && !results.len);
    CHECK(over_http.releases == 2 && setter_calls == 0);
    free(error);
    error = NULL;
    free(xs);
    free(ys);
    free(over);
    free(over_token);

    EVP_PKEY *policy_rsa = generate_rsa();
    BIGNUM *policy_e = NULL;
    CHECK(EVP_PKEY_get_bn_param(policy_rsa, OSSL_PKEY_PARAM_RSA_E, &policy_e) == 1);
    CHECK(BN_get_word(policy_e) == 65537);
    BN_free(policy_e);
    char *policy_token = signed_token("RS256", "{\"alg\":\"%s\",\"kid\":\"k\"}", signed_claims, policy_rsa, sign_rs);
    char *policy_jwk = rsa_jwk(policy_rsa, "k", true, false);
    size_t policy_len = strlen(policy_jwk);
    char *bogus_alg = malloc(policy_len + 24);
    char *bogus_ops = malloc(policy_len + 32);
    CHECK(bogus_alg && bogus_ops);
    snprintf(bogus_alg, policy_len + 24, "%.*s,\"alg\":\"BOGUS\"}", (int)(policy_len - 1), policy_jwk);
    snprintf(bogus_ops, policy_len + 32, "%.*s,\"key_ops\":[\"bogus\"]}", (int)(policy_len - 1), policy_jwk);
    expect_jwks(detector, policy_token, bogus_alg, false,
                "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to decode key #0 in \"keys\": failed to unmarshal JSON into key (*jwk.rsaPublicKey): failed to decode value for key alg: invalid key value: \"BOGUS\": invalid key algorithm");
    expect_jwks(detector, policy_token, bogus_ops, false,
                "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to decode key #0 in \"keys\": failed to unmarshal JSON into key (*jwk.rsaPublicKey): failed to decode value for key key_ops: invalid keyoperation bogus");

    unsigned char pad_e[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01};
    BIGNUM *policy_n = NULL;
    CHECK(EVP_PKEY_get_bn_param(policy_rsa, OSSL_PKEY_PARAM_RSA_N, &policy_n) == 1);
    char *pad_n = bn_b64(policy_n);
    char *pad_eb = b64url(pad_e, sizeof(pad_e));
    BN_free(policy_n);
    char *padded_jwk = malloc(strlen(pad_n) + strlen(pad_eb) + 64);
    CHECK(padded_jwk);
    snprintf(padded_jwk, strlen(pad_n) + strlen(pad_eb) + 64,
             "{\"kty\":\"RSA\",\"kid\":\"k\",\"n\":\"%s\",\"e\":\"%s\"}", pad_n, pad_eb);
    expect_jwks(detector, policy_token, padded_jwk, true, NULL);
    EVP_PKEY_free(policy_rsa);
    free(policy_token);
    free(policy_jwk);
    free(bogus_alg);
    free(bogus_ops);
    free(pad_n);
    free(pad_eb);
    free(padded_jwk);

    EVP_PKEY *policy_ed = generate_ed();
    char *eddsa = signed_token("EdDSA", "{\"alg\":\"%s\",\"kid\":\"k\"}", signed_claims, policy_ed, sign_ed);
    unsigned char short_x[31];
    memset(short_x, 7, sizeof(short_x));
    char *short_b64 = b64url(short_x, sizeof(short_x));
    char *short_jwk = malloc(strlen(short_b64) + 80);
    CHECK(short_jwk);
    snprintf(short_jwk, strlen(short_b64) + 80,
             "{\"kty\":\"OKP\",\"kid\":\"k\",\"crv\":\"Ed25519\",\"x\":\"%s\"}", short_b64);
    expect_jwks(detector, eddsa, "{\"kty\":\"OKP\",\"kid\":\"k\",\"crv\":\"Ed25519\",\"x\":\"\"}", false, NULL);
    CHECK(setter_calls == 0);
    expect_jwks(detector, eddsa, short_jwk, false, NULL);
    CHECK(setter_calls == 0);
    EVP_PKEY_free(policy_ed);
    free(eddsa);
    free(short_b64);
    free(short_jwk);
}

int main(void)
{
    char *error = NULL;
    const br_detector *detector = NULL;
    CHECK(br_jwt_init_under_test(&detector, &error) == 0 && !error && detector);
    test_identity(detector);
    test_extraction(detector);
    test_dates(detector);
    test_verify_gates(detector);
    test_http_policy(detector);
    test_jwks_errors(detector);
    test_drop_flag(detector);
    test_signatures(detector);
    test_source_policy(detector);
    return test_finish("JWT");
}
