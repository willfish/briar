/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>

/* PUBLIC SYNTHETIC test material only: scalar ONE, never an account key.
 * No services, credential files, Go runtime or external key commands. */
static const char name1[] = "organizations/ORG__123-AB_C-de_F-GHI_-abcdefgh1234/apiKeys/KEY__123-ZZ__-aaaa-bbbb-GHIJklmn5678";
static const char name2[] = "organizations/OTHER123-AB_C-de_F-GHI_-abcdefgh1234/apiKeys/KEY__123-ZZ__-aaaa-bbbb-GHIJklmn5678";
static size_t nonce_calls, fail_nonce_at, crypto_faults, fail_part_after;
static bool fail_crypto_next, fail_strdup_next;
static const char *fault_file; static int fault_line;

/* OpenSSL's supported memory callbacks reach internal DSO allocations too;
 * symbol interposition alone does not. Only the selected allocation fails. */
static void *crypto_allocate(size_t size, const char *file, int line)
{
    (void)file; (void)line;
    if (fail_crypto_next) { fail_crypto_next = false; ++crypto_faults; fault_file = file; fault_line = line; return NULL; }
    return malloc(size);
}

static void *crypto_reallocate(void *pointer, size_t size, const char *file, int line)
{
    (void)file; (void)line; return realloc(pointer, size);
}

static void crypto_deallocate(void *pointer, const char *file, int line)
{
    (void)file; (void)line; free(pointer);
}

int RAND_bytes(unsigned char *bytes, int count)
{
    ++nonce_calls;
    if (fail_nonce_at && nonce_calls == fail_nonce_at) return 0;
    return RAND_bytes_ex(NULL, bytes, (size_t)count, 0); /* Actual cryptographic RNG. */
}

char *strdup(const char *text)
{
    if (fail_strdup_next && !strcmp(text, "unexpected status code 503")) { fail_strdup_next = false; return NULL; }
    size_t n = strlen(text) + 1; char *copy = malloc(n);
    if (copy) memcpy(copy, text, n);
    return copy;
}

/* Fail the actual metadata insertion with a positive nonzero return. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

typedef struct { unsigned char bytes[8192]; size_t len; } fixture_der;

/* Tiny fixture writer for the four source SEC1 fields, not a parser/framework. */
static void tlv(fixture_der *out, unsigned char tag, const unsigned char *bytes, size_t len)
{
    CHECK(out->len + len + 4 < sizeof(out->bytes) && len <= 65535);
    out->bytes[out->len++] = tag;
    if (len < 128) out->bytes[out->len++] = (unsigned char)len;
    else if (len < 256) { out->bytes[out->len++] = 0x81; out->bytes[out->len++] = (unsigned char)len; }
    else { out->bytes[out->len++] = 0x82; out->bytes[out->len++] = (unsigned char)(len >> 8); out->bytes[out->len++] = (unsigned char)len; }
    if (len) memcpy(out->bytes + out->len, bytes, len);
    out->len += len;
}

static fixture_der sec1(int nid, const unsigned char *scalar, size_t len, unsigned char version, bool bogus_point)
{
    fixture_der fields = {0}, oid = {0}, result = {0};
    static const unsigned char p256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7};
    unsigned char other[] = {0x2b, 0x81, 4, 0, 0};
    tlv(&fields, 2, &version, 1); tlv(&fields, 4, scalar, len);
    if (nid) {
        if (nid == NID_X9_62_prime256v1) tlv(&oid, 6, p256, sizeof(p256));
        else {
            other[4] = nid == NID_secp224r1 ? 0x21 : nid == NID_secp384r1 ? 0x22 : nid == NID_secp521r1 ? 0x23 : 0x0a;
            tlv(&oid, 6, other, sizeof(other));
        }
        tlv(&fields, 0xa0, oid.bytes, oid.len);
    }
    if (bogus_point) {
        /* ASN.1-valid BIT STRING containing an invalid EC point. Go ignores it. */
        static const unsigned char bits[] = {3, 2, 0, 0};
        tlv(&fields, 0xa1, bits, sizeof(bits));
    }
    tlv(&result, 0x30, fields.bytes, fields.len); return result;
}

static char *pem_text(const fixture_der *der, const char *label, const char *separator, bool final_newline)
{
    size_t n = (der->len + 2) / 3 * 4; unsigned char *base64 = malloc(n + 1); CHECK(base64);
    CHECK(EVP_EncodeBlock(base64, der->bytes, (int)der->len) == (int)n);
    size_t cap = n + 2 * strlen(label) + 3 * strlen(separator) + 80;
    char *text = malloc(cap); CHECK(text);
    int written = snprintf(text, cap, "-----BEGIN %s PRIVATE KEY-----%s%s%s-----END %s PRIVATE KEY-----%s",
        label, separator, base64, separator, label, final_newline ? separator : "");
    CHECK(written > 0 && (size_t)written < cap); free(base64); return text;
}

static char *join(const char *const *items, size_t count)
{
    size_t n = 1;
    for (size_t i = 0; i < count; ++i) n += strlen(items[i]) + 3;
    char *text = malloc(n); CHECK(text); size_t at = 0;
    for (size_t i = 0; i < count; ++i) { size_t len = strlen(items[i]); memcpy(text + at, items[i], len); at += len; memcpy(text + at, " | ", 3); at += 3; }
    text[at] = '\0'; return text;
}

static char *escaped_name(const char *name, size_t backslashes)
{
    char *text = malloc(strlen(name) + 3 * backslashes + 1); CHECK(text); size_t at = 0;
    for (size_t i = 0; name[i]; ++i) {
        if (name[i] == '/') for (size_t j = 0; j < backslashes; ++j) text[at++] = '\\';
        text[at++] = name[i];
    }
    text[at] = '\0'; return text;
}

static br_results scan_pair(const br_detector *detector, const br_scan_ctx *ctx, bool verify, const char *name, const char *pem)
{
    const char *items[] = {name, pem}; char *text = join(items, 2);
    br_results results = test_scan(detector, ctx, verify, text, strlen(text)); free(text); return results;
}

static void finding(const br_result *result, const char *name, const char *pem)
{
    CHECK(result->detector_type == 5 && !result->detector_name && !result->verification_from_cache);
    CHECK(result->raw.len == strlen(pem) && !memcmp(result->raw.data, pem, strlen(pem)));
    CHECK(result->raw_v2.len == strlen(name) + 1 + strlen(pem));
    CHECK(!memcmp(result->raw_v2.data, name, strlen(name)) && result->raw_v2.data[strlen(name)] == ':');
    CHECK(!memcmp(result->raw_v2.data + strlen(name) + 1, pem, strlen(pem)));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key_name", &value) && !strcmp(json_object_get_string(value), name));
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &value) && (size_t)json_object_get_string_len(value) == strlen(pem) && !strcmp(json_object_get_string(value), pem));
    CHECK(!result->extra_data && !result->redacted && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(name1) == 95 && strlen(name2) == 95);
    CHECK(br_coinbase_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 5 && detector->version == 0 && !strcmp(detector->name, "Coinbase") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Coinbase is a digital currency exchange that allows users to buy, sell, and store various cryptocurrencies. A Coinbase API key name and private key can be used to access and manage a user's account and transactions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "begin ec"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->false_positive && !detector->clean_always && !detector->cloud_endpoint && !detector->validate_endpoints);
    CHECK(br_coinbase_init(&again, &error) == 0 && !error && again == detector && again->state == detector->state);
    CHECK(br_coinbase_init(&again, NULL) == 0 && again == detector);
    CHECK(br_coinbase_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Coinbase detector output")); free(error);
    CHECK(br_coinbase_init(NULL, NULL) == -1); return detector;
}

static void normalization_and_uniqueness(const br_detector *detector, const fixture_der *der, const char *normal)
{
    const char *separators[] = {"\n", "\\n", "\\r", "\r", "\r\n", "\\r\\n", "\\\\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) for (int final = 0; final < 2; ++final) {
        char *pem = pem_text(der, "EC", separators[i], final != 0);
        br_results results = scan_pair(detector, NULL, false, name1, pem); CHECK(results.len == (i < 3 ? 1u : 0u));
        if (results.len) {
            size_t n = strlen(normal); char *expected = malloc(n + 2); CHECK(expected); memcpy(expected, normal, n + 1);
            if (i != 0 && final) { expected[n++] = '\n'; expected[n] = '\0'; }
            finding(&results.items[0], name1, expected); CHECK(!results.items[0].verified && !results.items[0].verification_error); free(expected);
        }
        br_results_clear(&results); free(pem);
    }
    /* CRLF/repeated delimiters fail the exact extraction grammar; bare CR is
     * extracted but fails PEM line parsing. Do not "repair" either behavior. */
    char *a = pem_text(der, "EC", "\n", true), *b = pem_text(der, "EC", "\\n", false), *c = pem_text(der, "EC", "\\r", false);
    char *escaped = escaped_name(name1, 3), *unbounded = escaped_name(name1, 4096);
    const char *items[] = {name1, escaped, unbounded, name1, normal, a, b, c, normal};
    char *text = join(items, sizeof(items) / sizeof(items[0]));
    br_results results = test_scan(detector, NULL, false, text, strlen(text)); CHECK(results.len == 12);
    for (size_t i = 0; i < results.len; ++i) { finding(&results.items[i], name1, normal); CHECK(!results.items[i].verified && !results.items[i].verification_error); }
    br_results_clear(&results); free(a); free(b); free(c); free(escaped); free(unbounded); free(text);

    results = test_scan(detector, NULL, false, normal, strlen(normal)); CHECK(!results.len); br_results_clear(&results);
    const char *bad_names[] = {"organizations/no-UUID/apiKeys/no-UUID", "Organizations/ORG__123-AB_C-de_F-GHI_-abcdefgh1234/apiKeys/KEY__123-ZZ__-aaaa-bbbb-GHIJklmn5678"};
    for (size_t i = 0; i < 2; ++i) { results = scan_pair(detector, NULL, false, bad_names[i], normal); CHECK(!results.len); br_results_clear(&results); }
    results = test_scan(detector, NULL, false, NULL, 0); CHECK(!results.len); br_results_clear(&results);
}

static void validation(const br_detector *detector)
{
    unsigned char one = 1, zero = 0, padded[4096] = {0}; padded[sizeof(padded) - 1] = 1;
    unsigned char order[] = {0xff,0xff,0xff,0xff,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
    const int curves[] = {NID_secp224r1, NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1};
    for (size_t i = 0; i < 4; ++i) {
        fixture_der der = sec1(curves[i], &one, 1, 1, false); char *pem = pem_text(&der, "EC", "\n", false);
        br_results results = scan_pair(detector, NULL, false, name1, pem); CHECK(results.len == 1); finding(&results.items[0], name1, pem);
        CHECK(!results.items[0].verification_error && !results.items[0].verified); br_results_clear(&results); free(pem);
    }
    fixture_der large = sec1(NID_X9_62_prime256v1, padded, sizeof(padded), 1, true);
    large.bytes[large.len++] = 0xff; large.bytes[large.len++] = 0; /* Ignored OUTER ASN.1 remainder. */
    char *long_pem = pem_text(&large, "EC", "\n", false);
    CHECK(strlen(long_pem) > 5500);
    br_results results = scan_pair(detector, NULL, false, name1, long_pem); CHECK(results.len == 1); finding(&results.items[0], name1, long_pem); br_results_clear(&results); free(long_pem);

    fixture_der invalid[] = {
        sec1(NID_X9_62_prime256v1, &zero, 1, 1, false), sec1(NID_X9_62_prime256v1, order, sizeof(order), 1, false),
        sec1(NID_X9_62_prime256v1, &one, 1, 2, false), sec1(NID_secp256k1, &one, 1, 1, false), sec1(0, &one, 1, 1, false),
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        char *pem = pem_text(&invalid[i], "EC", "\n", false); results = scan_pair(detector, NULL, false, name1, pem); CHECK(!results.len); br_results_clear(&results); free(pem);
    }
    padded[0] = 1; fixture_der too_long = sec1(NID_X9_62_prime256v1, padded, 33, 1, false); /* Nonzero extra padding. */
    char *pem = pem_text(&too_long, "EC", "\n", false); results = scan_pair(detector, NULL, false, name1, pem); CHECK(!results.len); br_results_clear(&results); free(pem);
    fixture_der raw = sec1(NID_X9_62_prime256v1, &one, 1, 1, false), ber = {0};
    ber.bytes[0] = 0x30; ber.bytes[1] = 0x80; memcpy(ber.bytes + 2, raw.bytes + 2, raw.len - 2); ber.len = raw.len + 2; /* Indefinite BER + EOC. */
    pem = pem_text(&ber, "EC", "\n", false); results = scan_pair(detector, NULL, false, name1, pem); CHECK(!results.len); br_results_clear(&results); free(pem);
    fixture_der pkcs8_fields = {0}, pkcs8 = {0};
    static const unsigned char algorithm[] = {0x30,0x13,6,7,0x2a,0x86,0x48,0xce,0x3d,2,1,6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7};
    tlv(&pkcs8_fields, 2, &zero, 1); memcpy(pkcs8_fields.bytes + pkcs8_fields.len, algorithm, sizeof(algorithm)); pkcs8_fields.len += sizeof(algorithm);
    tlv(&pkcs8_fields, 4, raw.bytes, raw.len); tlv(&pkcs8, 0x30, pkcs8_fields.bytes, pkcs8_fields.len);
    pem = pem_text(&pkcs8, "EC", "\n", false); results = scan_pair(detector, NULL, false, name1, pem); CHECK(!results.len); br_results_clear(&results); free(pem);
    pem = pem_text(&raw, "ECDSA", "\n", false); char *end = strstr(pem, "-----END ECDSA PRIVATE KEY-----"); CHECK(end); strcpy(end, "-----END EC PRIVATE KEY-----");
    results = scan_pair(detector, NULL, false, name1, pem); CHECK(!results.len); br_results_clear(&results); free(pem);
    CHECK(!nonce_calls); /* All mandatory filtering above is NoV, not signing. */
}

static br_bytes decode_segment(const char *text, size_t len)
{
    size_t padded = (len + 3) / 4 * 4; unsigned char *copy = malloc(padded + 1); CHECK(copy);
    for (size_t i = 0; i < padded; ++i) copy[i] = i >= len ? '=' : text[i] == '-' ? '+' : text[i] == '_' ? '/' : (unsigned char)text[i];
    copy[padded] = 0; br_bytes out = {.data = malloc(padded + 1)}; CHECK(out.data);
    int n = EVP_DecodeBlock(out.data, copy, (int)padded); CHECK(n >= 0 && (size_t)n >= padded - len);
    out.len = (size_t)n - (padded - len); out.data[out.len] = 0; free(copy); return out;
}

static EVP_PKEY *public_one(void)
{
    /* Frozen standard P256 generator = ONE*G; independent of provider parsing,
     * ignored public bits and private-key import/derivation. */
    static unsigned char generator[] = {
        4,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,3,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
        0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
    };
    char group[] = "prime256v1"; EVP_PKEY *key = NULL;
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0), OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, generator, sizeof(generator)), OSSL_PARAM_construct_end()};
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL); CHECK(ctx);
    CHECK(EVP_PKEY_fromdata_init(ctx) == 1 && EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) == 1 && key); EVP_PKEY_CTX_free(ctx); return key;
}

typedef struct {
    const char *const *names; size_t len;
    bool crypto_after_first, setter_after_first, part_after_first;
    const char *sensitive;
    char *released_cause;
} wire_expect;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire_expect *expected = http->user; CHECK(http->calls <= expected->len && http->releases + 1 == http->calls);
    const char *name = expected->names[http->calls - 1];
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.coinbase.com/v2/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 5);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && !request->dedup_key.data && request->nheaders == 2);
    const char *auth = NULL; size_t ua = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Authorization")) { CHECK(!auth); auth = request->headers[i].value; }
        else if (!strcmp(request->headers[i].name, "User-Agent")) { ++ua; CHECK(!strcmp(request->headers[i].value, ctx->user_agent ? "TruffleHog coinbase-test" : "TruffleHog")); }
        else CHECK(!"invented Coinbase header");
    }
    CHECK(ua == 1 && auth && !strncmp(auth, "Bearer ", 7)); const char *token = auth + 7;
    CHECK(!strchr(token, '=') && !strchr(token, '+') && !strchr(token, '/'));
    const char *dot1 = strchr(token, '.'), *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
    CHECK(dot1 && dot2 && !strchr(dot2 + 1, '.'));
    br_bytes h = decode_segment(token, (size_t)(dot1 - token)), c = decode_segment(dot1 + 1, (size_t)(dot2 - dot1 - 1)), sig = decode_segment(dot2 + 1, strlen(dot2 + 1));
    CHECK(sig.len == 64 && strlen(dot2 + 1) == 86);
    br_json *header = json_tokener_parse((const char *)h.data), *claims = json_tokener_parse((const char *)c.data), *value = NULL;
    CHECK(header && claims && json_object_object_length(header) == 4 && json_object_object_length(claims) == 5);
    CHECK(json_object_object_get_ex(header, "nonce", &value) && json_object_is_type(value, json_type_string) && json_object_get_string_len(value) == 32);
    const char *nonce = json_object_get_string(value);
    for (size_t i = 0; i < 32; ++i) CHECK((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'));
    char exact_header[256], exact_claims[384];
    snprintf(exact_header, sizeof(exact_header), "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"typ\":\"JWT\"}", name, nonce);
    CHECK(h.len == strlen(exact_header) && !strcmp((const char *)h.data, exact_header) && !strstr((const char *)h.data, "\\/"));
    CHECK(json_object_object_get_ex(claims, "nbf", &value) && json_object_is_type(value, json_type_int)); int64_t now = json_object_get_int64(value);
    CHECK(json_object_object_get_ex(claims, "exp", &value) && json_object_is_type(value, json_type_int) && json_object_get_int64(value) == now + 120);
    CHECK(now >= (int64_t)time(NULL) - 30 && now <= (int64_t)time(NULL) + 1);
    snprintf(exact_claims, sizeof(exact_claims), "{\"exp\":%" PRId64 ",\"iss\":\"cdp\",\"nbf\":%" PRId64 ",\"sub\":\"%s\",\"uri\":\"GET api.coinbase.com/v2/user\"}", now + 120, now, name);
    CHECK(c.len == strlen(exact_claims) && !strcmp((const char *)c.data, exact_claims) && !strstr((const char *)c.data, "\\/"));
    ECDSA_SIG *rs = ECDSA_SIG_new(); CHECK(rs);
    BIGNUM *r = BN_bin2bn(sig.data, 32, NULL), *s = BN_bin2bn(sig.data + 32, 32, NULL); CHECK(r && s && ECDSA_SIG_set0(rs, r, s) == 1);
    unsigned char der_sig[72], *at = der_sig; int der_len = i2d_ECDSA_SIG(rs, NULL); CHECK(der_len > 0 && (size_t)der_len <= sizeof(der_sig));
    CHECK(i2d_ECDSA_SIG(rs, &at) == der_len); EVP_PKEY *public_key = public_one(); EVP_MD_CTX *md = EVP_MD_CTX_new(); CHECK(md);
    CHECK(EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, public_key) == 1);
    CHECK(EVP_DigestVerify(md, der_sig, (size_t)der_len, (const unsigned char *)token, (size_t)(dot2 - token)) == 1);
    char *tampered = strdup(token); CHECK(tampered); tampered[0] = tampered[0] == 'a' ? 'b' : 'a';
    CHECK(EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, public_key) == 1);
    CHECK(EVP_DigestVerify(md, der_sig, (size_t)der_len, (const unsigned char *)tampered, (size_t)(dot2 - token)) == 0);
    free(tampered); EVP_MD_CTX_free(md); EVP_PKEY_free(public_key); ECDSA_SIG_free(rs); json_object_put(header); json_object_put(claims); free(h.data); free(c.data); free(sig.data);
    if (expected->setter_after_first && http->calls == 2) http->response.status = 503;
}

static void release(void *user, br_http_response *response)
{
    test_http *http = user; wire_expect *expected = http->user; test_http_release(user, response);
    if (expected->released_cause) { memset(expected->released_cause, 'X', strlen(expected->released_cause)); expected->released_cause = NULL; }
    if (http->releases == 1 && expected->crypto_after_first) fail_crypto_next = true;
    if (http->releases == 1 && expected->setter_after_first) fail_strdup_next = true;
    if (http->releases == 1 && expected->part_after_first) fail_part_after = 1;
}

static int corrupting_send(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    wire_expect *expected = ((test_http *)user)->user;
    expected->released_cause = *error; /* Actual owned transport cause, invalidated by release. */
    return rc;
}

static void nil_context_and_curves(const br_detector *detector, const fixture_der *normal_der, const char *normal)
{
    size_t before = nonce_calls;
    br_results results = scan_pair(detector, NULL, true, name1, normal); CHECK(results.len == 1 && nonce_calls == before + 1);
    finding(&results.items[0], name1, normal); CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "net/http: nil Context")); br_results_clear(&results);
    char *ecdsa = pem_text(normal_der, "ECDSA", "\n", false);
    results = scan_pair(detector, NULL, false, name1, ecdsa); CHECK(results.len == 1); finding(&results.items[0], name1, ecdsa); CHECK(!results.items[0].verification_error); br_results_clear(&results);
    before = nonce_calls; results = scan_pair(detector, NULL, true, name1, ecdsa); CHECK(results.len == 1 && nonce_calls == before);
    CHECK(!strcmp(results.items[0].verification_error, "failed to decode PEM block containing EC private key")); br_results_clear(&results); free(ecdsa);
    const int curves[] = {NID_secp224r1, NID_secp384r1, NID_secp521r1}; unsigned char one = 1;
    for (size_t i = 0; i < 3; ++i) {
        fixture_der der = sec1(curves[i], &one, 1, 1, false); char *pem = pem_text(&der, "EC", "\n", false); before = nonce_calls;
        results = scan_pair(detector, NULL, true, name1, pem); CHECK(results.len == 1 && nonce_calls == before + 1);
        finding(&results.items[0], name1, pem); CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "failed to sign JWT: key is invalid")); br_results_clear(&results); free(pem);
    }
}

static void statuses_and_transport(const br_detector *detector, const char *normal)
{
    const char *names[] = {name1}; wire_expect expected = {.names = names, .len = 1};
    const int statuses[] = {199,200,201,204,299,300,400,401,403,429,500};
    static const unsigned char ignored[] = {0,0xff,'n','o','t',' ','J','S','O','N'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body = {ignored, sizeof(ignored)}, .body_error = "ignored read error"}, .inspect = inspect, .user = &expected};
        br_transport transport = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "coinbase-test"};
        br_results results = scan_pair(detector, &ctx, true, name1, normal); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&results.items[0], name1, normal); CHECK(results.items[0].verified == (statuses[i] == 200));
        if (statuses[i] == 200 || statuses[i] == 401) CHECK(!results.items[0].verification_error);
        else { char cause[80]; snprintf(cause, sizeof(cause), "unexpected status code %d", statuses[i]); CHECK(!strcmp(results.items[0].verification_error, cause)); }
        br_results_clear(&results);
    }
    size_t cap = 2 * strlen(normal) + strlen(name1) + 64; char *sensitive = malloc(cap); CHECK(sensitive);
    snprintf(sensitive, cap, "Do PEM=%s, current=%s, name=%s", normal, normal, name1);
    test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = sensitive, .inspect = inspect, .user = &expected};
    br_transport transport = {&http, corrupting_send, release}; br_scan_ctx ctx = {.transport = &transport};
    br_results results = scan_pair(detector, &ctx, true, name1, normal); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !results.items[0].verified);
    char expected_error[256]; snprintf(expected_error, sizeof(expected_error), "Do PEM=[REDACTED], current=[REDACTED], name=%s", name1);
    CHECK(!strcmp(results.items[0].verification_error, expected_error)); finding(&results.items[0], name1, normal); br_results_clear(&results); free(sensitive);
    http = (test_http){.send_rc = -1, .inspect = inspect, .user = &expected};
    results = scan_pair(detector, &ctx, true, name1, normal); CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "HTTP transport failed") && http.calls == 1 && http.releases == 1); br_results_clear(&results);
    ctx.transport = NULL; results = scan_pair(detector, &ctx, true, name1, normal); CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "HTTP transport not installed")); br_results_clear(&results);
}

static void original_name_break(const br_detector *detector, const fixture_der *der, const char *normal)
{
    char *escaped = escaped_name(name1, 7), *second = pem_text(der, "EC", "\\n", false);
    const char *items[] = {name1, escaped, name2, name1, normal, second}; char *input = join(items, 6);
    const char *names[] = {name1, name1, name2}; wire_expect expected = {.names = names, .len = 3};
    test_http http = {.response = {.status = 200}, .inspect = inspect, .user = &expected}; br_transport transport = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) { finding(&results.items[i], names[i], normal); CHECK(results.items[i].verified && !results.items[i].verification_error); }
    br_results_clear(&results);
    /* No success: retain all original PEM products, not canonical uniqueness. */
    const char *all_names[] = {name1,name1,name1,name1,name2,name2}; expected.names = all_names; expected.len = 6;
    http.calls = http.releases = 0; http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 6 && http.calls == 6 && http.releases == 6);
    for (size_t i = 0; i < 6; ++i) { finding(&results.items[i], all_names[i], normal); CHECK(!results.items[i].verified && !results.items[i].verification_error); }
    br_results_clear(&results); free(escaped); free(second); free(input);
}

static void rollback(const br_detector *detector, const fixture_der *der, const char *normal)
{
    char *other = pem_text(der, "EC", "\\n", false); const char *items[] = {name1, normal, other}; char *input = join(items, 3);
    const char *names[] = {name1, name1};
    for (int mode = 0; mode < 4; ++mode) {
        wire_expect expected = {.names = names, .len = 2, .crypto_after_first = mode == 0, .setter_after_first = mode == 2, .part_after_first = mode == 3};
        test_http http = {.response = {.status = 401}, .inspect = inspect, .user = &expected}; br_transport transport = {&http, test_http_send, release}; br_scan_ctx ctx = {.transport = &transport};
        br_result sentinel = {.detector_type = 12345, .verified = true, .raw = {(unsigned char *)strdup("keep"), 4}, .verification_error = strdup("caller-owned")}; CHECK(sentinel.raw.data && sentinel.verification_error);
        unsigned char *raw = sentinel.raw.data; char *cause = sentinel.verification_error; br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
        size_t before = nonce_calls, failures = crypto_faults;
        if (mode == 1) fail_nonce_at = before + 2;
        char *error = NULL; int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        if (rc != -1 || !error || results.len != 1) fprintf(stderr, "rollback mode=%d rc=%d findings=%zu calls=%zu releases=%zu crypto-faults=%zu site=%s:%d cause=%s\n", mode, rc, results.len, http.calls, http.releases, crypto_faults - failures, fault_file ? fault_file : "none", fault_line, error ? error : "none");
        CHECK(rc == -1 && error && results.len == 1);
        CHECK(results.items[0].raw.data == raw && results.items[0].verification_error == cause && results.items[0].verified && results.items[0].detector_type == 12345);
        CHECK(results.items[0].raw.len == 4 && !memcmp(raw, "keep", 4) && !strcmp(cause, "caller-owned"));
        if (mode == 0) CHECK(!fail_crypto_next && crypto_faults == failures + 1 && http.calls == 1 && http.releases == 1);
        if (mode == 1) CHECK(!strcmp(error, "Coinbase cryptographic RNG failed") && nonce_calls == before + 2 && http.calls == 1 && http.releases == 1);
        if (mode == 2) CHECK(!fail_strdup_next && !strcmp(error, "cannot store Coinbase verification error") && http.calls == 2 && http.releases == 2);
        if (mode == 3) CHECK(!fail_part_after && !strcmp(error, "cannot create Coinbase result") && http.calls == 1 && http.releases == 1);
        fail_nonce_at = 0; free(error); br_results_clear(&results);
    }
    /* No failure remains armed, and the invocation did not consume the key. */
    br_results results = scan_pair(detector, NULL, false, name1, normal); CHECK(results.len == 1); finding(&results.items[0], name1, normal); br_results_clear(&results);
    free(other); free(input);
}

int main(void)
{
    CHECK(CRYPTO_set_mem_functions(crypto_allocate, crypto_reallocate, crypto_deallocate) == 1);
    const br_detector *detector = descriptor(); unsigned char one = 1;
    fixture_der der = sec1(NID_X9_62_prime256v1, &one, 1, 1, true);
    der.bytes[der.len++] = 0; der.bytes[der.len++] = 0xff; /* Ignore public contents AND outer remainder on the actual JWT path. */
    char *normal = pem_text(&der, "EC", "\n", false);
    normalization_and_uniqueness(detector, &der, normal); validation(detector);
    nil_context_and_curves(detector, &der, normal); statuses_and_transport(detector, normal);
    original_name_break(detector, &der, normal); rollback(detector, &der, normal);
    free(normal);
    return test_finish("Coinbase mandatory SEC1 + original uniqueness/single-pass normalization + native ES256 wire/signature + fatal rollback");
}
