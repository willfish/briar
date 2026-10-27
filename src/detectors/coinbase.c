/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/coinbase/coinbase.go and
 * golang-jwt/jwt v5.2.3 (existing MIT notice). Selected SEC1/padding and PEM
 * mechanics follow Go1.26.7: Copyright 2012/2009 The Go Authors, respectively;
 * see LICENSES/BSD-3-Clause-Go.txt. This is not a general Go PKI implementation. */
#include "detectors.h"
#include "captures.h"

#include <json-c/json.h>
#include <openssl/asn1t.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *name, *pem; } coinbase_patterns;
typedef struct {
    ASN1_INTEGER *version;
    ASN1_OCTET_STRING *scalar;
    ASN1_OBJECT *curve;
    ASN1_BIT_STRING *public_bits;
} coinbase_sec1;

ASN1_SEQUENCE(coinbase_sec1) = {
    ASN1_SIMPLE(coinbase_sec1, version, ASN1_INTEGER),
    ASN1_SIMPLE(coinbase_sec1, scalar, ASN1_OCTET_STRING),
    ASN1_EXP_OPT(coinbase_sec1, curve, ASN1_OBJECT, 0),
    ASN1_EXP_OPT(coinbase_sec1, public_bits, ASN1_BIT_STRING, 1)
} static_ASN1_SEQUENCE_END(coinbase_sec1)

typedef struct { EVP_PKEY *pkey; int bits; bool ec_label; } coinbase_key;

enum {
    COINBASE_HEADER_CAP = sizeof("{\"alg\":\"ES256\",\"kid\":\"\",\"nonce\":\"\",\"typ\":\"JWT\"}") + 95 + 32,
    COINBASE_CLAIMS_CAP = sizeof("{\"exp\":,\"iss\":\"cdp\",\"nbf\":,\"sub\":\"\",\"uri\":\"GET api.coinbase.com/v2/user\"}") + 40 + 95,
    /* Complete maximum encoded fields (including temporary Base64 padding),
     * Bearer prefix, two dots and NUL. No unbounded PEM is stored here. */
    COINBASE_AUTH_CAP = 7 + ((COINBASE_HEADER_CAP - 1 + 2) / 3) * 4 + 1 +
        ((COINBASE_CLAIMS_CAP - 1 + 2) / 3) * 4 + 1 + ((64 + 2) / 3) * 4 + 1
};

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void clear_free(void *data, size_t len)
{
    if (data) { OPENSSL_cleanse(data, len); free(data); }
}

static bool crypto_oom(void)
{
    bool found = false; unsigned long code;
    while ((code = ERR_get_error()) != 0)
        if (ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE) found = true;
    return found;
}

static int normalize_name(br_slice raw, char out[96], char **error)
{
    size_t at = 0;
    /* Capture edges cannot contain whitespace. Only backslash runs are
     * unbounded; removing ALL of them leaves the source's fixed 95 ASCII bytes. */
    for (size_t i = 0; i < raw.len; ++i) if (raw.data[i] != '\\') {
        if (at >= 95) return fail(error, "invalid native Coinbase name capture");
        out[at++] = (char)raw.data[i];
    }
    if (at != 95) return fail(error, "invalid native Coinbase name capture");
    out[at] = '\0'; return 0;
}

static int normalize_pem(br_slice raw, char **out, size_t *len, char **error)
{
    /* The regex permits only CR/LF whitespace at the edges. Trim BEFORE the
     * single-pass replacer: a final escaped newline survives as a final LF. */
    while (raw.len && (raw.data[raw.len - 1] == '\r' || raw.data[raw.len - 1] == '\n')) --raw.len;
    if (raw.len == SIZE_MAX) return fail(error, "Coinbase PEM length overflow");
    char *text = malloc(raw.len + 1); if (!text) return fail(error, "cannot normalize Coinbase PEM");
    size_t at = 0;
    for (size_t i = 0; i < raw.len;) {
        if (raw.data[i] == '\r' && i + 1 < raw.len && raw.data[i + 1] == '\n') { text[at++] = '\n'; i += 2; }
        else if (raw.len - i >= 4 && !memcmp(raw.data + i, "\\r\\n", 4)) { text[at++] = '\n'; i += 4; }
        else if (raw.len - i >= 2 && raw.data[i] == '\\' && (raw.data[i + 1] == 'n' || raw.data[i + 1] == 'r')) { text[at++] = '\n'; i += 2; }
        else text[at++] = (char)raw.data[i++];
    }
    text[at] = '\0'; *out = text; *len = at; return 0;
}

/* Decode only the envelope reachable through privateKeyPat, not arbitrary PEM
 * headers/encryption. Bare CR is not a line separator; labels must match. */
static int decode_pem(br_slice text, br_bytes *der, bool *ec_label, char **error)
{
    static const char ec[] = "-----BEGIN EC PRIVATE KEY-----\n", ecdsa[] = "-----BEGIN ECDSA PRIVATE KEY-----\n";
    const char *footer; size_t start;
    if (text.len >= sizeof(ec) - 1 && !memcmp(text.data, ec, sizeof(ec) - 1)) { start = sizeof(ec) - 1; footer = "\n-----END EC PRIVATE KEY-----"; *ec_label = true; }
    else if (text.len >= sizeof(ecdsa) - 1 && !memcmp(text.data, ecdsa, sizeof(ecdsa) - 1)) { start = sizeof(ecdsa) - 1; footer = "\n-----END ECDSA PRIVATE KEY-----"; *ec_label = false; }
    else return 0;
    size_t flen = strlen(footer), end = br_slice_find(text, (br_slice){(const unsigned char *)footer, flen}, start);
    if (end == SIZE_MAX) return 0;
    size_t after = end + flen;
    if (after != text.len && !(after + 1 == text.len && text.data[after] == '\n')) return 0;
    size_t cap = end - start;
    if (cap > INT_MAX) return fail(error, "Coinbase PEM exceeds native Base64 interface");
    unsigned char *b64 = malloc(cap + 1); if (!b64) return fail(error, "cannot decode Coinbase PEM");
    size_t n = 0;
    for (size_t i = start; i < end; ++i) if (text.data[i] != '\n' && text.data[i] != '\r') b64[n++] = text.data[i];
    bool valid = n && n % 4 == 0; size_t padding = 0;
    while (padding < n && b64[n - padding - 1] == '=') ++padding;
    if (padding > 2) valid = false;
    for (size_t i = 0; valid && i < n - padding; ++i) {
        unsigned char c = b64[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/')) valid = false;
    }
    if (!valid) { clear_free(b64, cap + 1); return 0; }
    size_t size = n / 4 * 3;
    der->data = malloc(size + 1);
    if (!der->data) { clear_free(b64, cap + 1); return fail(error, "cannot allocate Coinbase DER"); }
    int decoded = EVP_DecodeBlock(der->data, b64, (int)n);
    clear_free(b64, cap + 1);
    if (decoded < 0 || (size_t)decoded < padding) { clear_free(der->data, size + 1); *der = (br_bytes){0}; return 0; }
    der->len = (size_t)decoded - padding;
    return 0;
}

/* Success with pkey=NULL means invalid candidate, NOT resource failure. Keep
 * PKCS8 rejected; import only our validated SEC1 scalar and DER-parsed curve.
 * OpenSSL/Go ASN.1 acceptance outside this canonical subset remains partial. */
static int parse_key(br_slice pem, coinbase_key *out, char **error)
{
    br_bytes der = {0}; coinbase_sec1 *sec = NULL; unsigned char *canonical = NULL;
    EC_GROUP *group = NULL; EC_POINT *public_point = NULL; BN_CTX *bnctx = NULL;
    BIGNUM *scalar = NULL, *order = NULL; OSSL_PARAM_BLD *builder = NULL; OSSL_PARAM *params = NULL; EVP_PKEY_CTX *ctx = NULL;
    int rc = decode_pem(pem, &der, &out->ec_label, error);
    if (rc || !der.data) return rc;
    if (der.len > LONG_MAX) { rc = fail(error, "Coinbase DER exceeds native ASN.1 interface"); goto done; }
    const unsigned char *cursor = der.data;
    ERR_clear_error();
    sec = (coinbase_sec1 *)ASN1_item_d2i(NULL, &cursor, (long)der.len, coinbase_sec1_it());
    if (!sec) { if (crypto_oom()) rc = fail(error, "cannot allocate Coinbase SEC1 structure"); goto done; }
    /* Reject BER/noncanonical widening, but deliberately ignore OUTER remainder
     * like Go's discarded asn1.Unmarshal rest. Preserve OCTET STRING padding. */
    int encoded = ASN1_item_i2d((const ASN1_VALUE *)sec, NULL, coinbase_sec1_it());
    if (encoded <= 0) { rc = fail(error, "Coinbase native SEC1 encoding failed"); goto done; }
    canonical = malloc((size_t)encoded);
    if (!canonical) { rc = fail(error, "cannot allocate Coinbase canonical DER"); goto done; }
    unsigned char *write_at = canonical;
    if (ASN1_item_i2d((const ASN1_VALUE *)sec, &write_at, coinbase_sec1_it()) != encoded) { rc = fail(error, "Coinbase native SEC1 encoding failed"); goto done; }
    if ((size_t)(cursor - der.data) != (size_t)encoded || memcmp(canonical, der.data, (size_t)encoded)) goto done;
    if (ASN1_INTEGER_get(sec->version) != 1 || !sec->curve) goto done;
    int nid = OBJ_obj2nid(sec->curve);
    if (nid != NID_secp224r1 && nid != NID_X9_62_prime256v1 && nid != NID_secp384r1 && nid != NID_secp521r1) goto done;
    group = EC_GROUP_new_by_curve_name(nid); bnctx = BN_CTX_new(); order = BN_new();
    if (!group || !bnctx || !order) { rc = fail(error, "cannot allocate Coinbase curve state"); goto done; }
    if (EC_GROUP_get_order(group, order, bnctx) != 1) { rc = fail(error, "Coinbase native curve order failed"); goto done; }
    size_t width = (size_t)(BN_num_bits(order) + 7) / 8;
    int count = ASN1_STRING_length(sec->scalar); const unsigned char *bytes = ASN1_STRING_get0_data(sec->scalar);
    if (count < 0) goto done;
    size_t n = (size_t)count;
    while (n > width) { if (*bytes != 0) goto done; ++bytes; --n; }
    scalar = BN_bin2bn(bytes, (int)n, NULL);
    if (!scalar) { rc = fail(error, "cannot allocate Coinbase scalar"); goto done; }
    if (BN_is_zero(scalar) || BN_is_negative(scalar) || BN_cmp(scalar, order) >= 0) goto done;
    BN_set_flags(scalar, BN_FLG_CONSTTIME);
    public_point = EC_POINT_new(group);
    if (!public_point) { rc = fail(error, "cannot allocate Coinbase public point"); goto done; }
    /* public_bits is ASN.1 parsed, but its EC point contents are ignored by Go.
     * Derive the point from the scalar instead of importing supplied contents. */
    if (EC_POINT_mul(group, public_point, scalar, NULL, NULL, bnctx) != 1) { rc = fail(error, "Coinbase native public derivation failed"); goto done; }
    unsigned char public_bytes[133]; /* Complete uncompressed P521 point. */
    size_t public_len = EC_POINT_point2oct(group, public_point, POINT_CONVERSION_UNCOMPRESSED, public_bytes, sizeof(public_bytes), bnctx);
    if (!public_len) { rc = fail(error, "Coinbase native public encoding failed"); goto done; }
    builder = OSSL_PARAM_BLD_new();
    if (!builder || OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(nid), 0) != 1 ||
        OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, scalar) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, public_bytes, public_len) != 1) {
        rc = fail(error, "cannot construct Coinbase key parameters"); goto done;
    }
    params = OSSL_PARAM_BLD_to_param(builder); ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!params || !ctx) { rc = fail(error, "cannot allocate Coinbase key import"); goto done; }
    if (EVP_PKEY_fromdata_init(ctx) != 1 || EVP_PKEY_fromdata(ctx, &out->pkey, EVP_PKEY_KEYPAIR, params) != 1) {
        rc = fail(error, "Coinbase native EC key import failed"); goto done;
    }
    out->bits = EC_GROUP_get_degree(group);
 done:
    EVP_PKEY_CTX_free(ctx); OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(builder);
    BN_clear_free(scalar); BN_free(order); BN_CTX_free(bnctx); EC_POINT_free(public_point); EC_GROUP_free(group);
    if (sec && sec->scalar) OPENSSL_cleanse((void *)ASN1_STRING_get0_data(sec->scalar), (size_t)ASN1_STRING_length(sec->scalar));
    ASN1_item_free((ASN1_VALUE *)sec, coinbase_sec1_it());
    if (canonical) clear_free(canonical, (size_t)encoded);
    clear_free(der.data, der.len);
    if (rc) { EVP_PKEY_free(out->pkey); out->pkey = NULL; }
    return rc;
}

static int encode_segment(br_slice bytes, char *text, size_t cap, size_t *written, char **error)
{
    if (bytes.len > INT_MAX || bytes.len > (SIZE_MAX - 2) / 4 * 3) return fail(error, "Coinbase JWT segment length overflow");
    size_t size = (bytes.len + 2) / 3 * 4;
    if (size > INT_MAX || size >= cap) return fail(error, "Coinbase JWT segment capacity overflow");
    int n = EVP_EncodeBlock((unsigned char *)text, bytes.data, (int)bytes.len);
    if (n < 0 || (size_t)n != size) return fail(error, "Coinbase native Base64 encoding failed");
    while (n && text[n - 1] == '=') --n;
    for (int i = 0; i < n; ++i) { if (text[i] == '+') text[i] = '-'; else if (text[i] == '/') text[i] = '_'; }
    text[n] = '\0'; *written = (size_t)n; return 0;
}

/* Builds the actual signed JWT before context construction. Return -1 for
 * resources/checked RNG or unknown native crypto failures; source-known build
 * errors use a separate literal cause, never an integer sentinel collision. */
static int make_authorization(const char name[96], const coinbase_key *key, char authorization[COINBASE_AUTH_CAP],
                                const char **cause, char **error)
{
    *cause = NULL;
    if (!key->ec_label) { *cause = "failed to decode PEM block containing EC private key"; return 0; }
    struct timespec clock;
    if (clock_gettime(CLOCK_REALTIME, &clock) != 0) return fail(error, "Coinbase realtime clock failed");
    intmax_t epoch = clock.tv_sec;
    if (epoch < INT64_MIN || epoch > INT64_MAX - 120) return fail(error, "Coinbase JWT clock overflow");
    int64_t now = (int64_t)epoch;
    unsigned char nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return fail(error, "Coinbase cryptographic RNG failed");
    char nonce_hex[33]; static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(nonce); ++i) { nonce_hex[i * 2] = hex[nonce[i] >> 4]; nonce_hex[i * 2 + 1] = hex[nonce[i] & 15]; }
    nonce_hex[32] = '\0';
    /* Canonical names are exactly 95 ASCII word/hyphen/slash bytes, requiring
     * no JSON string escaping. Explicit order matches Go's sorted map keys;
     * slashes remain unescaped. Capacities derive from those fixed fields. */
    char header[COINBASE_HEADER_CAP], claims[COINBASE_CLAIMS_CAP];
    int hn = snprintf(header, sizeof(header), "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"typ\":\"JWT\"}", name, nonce_hex);
    int cn = snprintf(claims, sizeof(claims), "{\"exp\":%" PRId64 ",\"iss\":\"cdp\",\"nbf\":%" PRId64 ",\"sub\":\"%s\",\"uri\":\"GET api.coinbase.com/v2/user\"}", now + 120, now, name);
    if (hn < 0 || (size_t)hn >= sizeof(header) || cn < 0 || (size_t)cn >= sizeof(claims)) return fail(error, "Coinbase JWT framing overflow");
    size_t at = 7, written = 0;
    memcpy(authorization, "Bearer ", at);
    int rc = encode_segment((br_slice){(const unsigned char *)header, (size_t)hn}, authorization + at, COINBASE_AUTH_CAP - at, &written, error);
    if (rc) return -1;
    at += written; authorization[at++] = '.';
    rc = encode_segment((br_slice){(const unsigned char *)claims, (size_t)cn}, authorization + at, COINBASE_AUTH_CAP - at, &written, error);
    if (rc) return -1;
    at += written;
    EVP_MD_CTX *md = EVP_MD_CTX_new(); ECDSA_SIG *signature = NULL;
    if (!md) return fail(error, "cannot allocate Coinbase signing context");
    unsigned char der_sig[148]; size_t sig_len = sizeof(der_sig); /* Max four supported NIST curves, including P521. */
    if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key->pkey) != 1 ||
        EVP_DigestSign(md, der_sig, &sig_len, (const unsigned char *)authorization + 7, at - 7) != 1) {
        rc = fail(error, "Coinbase native ECDSA signing failed"); goto done;
    }
    /* jwt/v5.2.3 signs FIRST, then rejects non-256 curve bits. */
    if (key->bits != 256) { *cause = "failed to sign JWT: key is invalid"; goto done; }
    const unsigned char *der_at = der_sig;
    signature = d2i_ECDSA_SIG(NULL, &der_at, (long)sig_len);
    if (!signature || der_at != der_sig + sig_len) { rc = fail(error, "Coinbase native signature decoding failed"); goto done; }
    const BIGNUM *r, *s; ECDSA_SIG_get0(signature, &r, &s);
    unsigned char wire[64];
    if (BN_bn2binpad(r, wire, 32) != 32 || BN_bn2binpad(s, wire + 32, 32) != 32) { rc = fail(error, "Coinbase native signature width failed"); goto done; }
    authorization[at++] = '.';
    rc = encode_segment((br_slice){wire, sizeof(wire)}, authorization + at, COINBASE_AUTH_CAP - at, &written, error);
 done:
    ECDSA_SIG_free(signature); EVP_MD_CTX_free(md);
    return rc;
}

static int verify_coinbase(const br_scan_ctx *ctx, const char name[96], const coinbase_key *key,
                            br_result *result, char **error)
{
    /* Derived-capacity stack storage stays alive through send AND release. */
    char authorization[COINBASE_AUTH_CAP]; const char *cause = NULL;
    int rc = make_authorization(name, key, authorization, &cause, error);
    if (rc) return -1;
    const br_slice secret = {result->raw.data, result->raw.len};
    if (cause || !ctx) {
        rc = br_result_set_verification_error(result, cause ? cause : "net/http: nil Context", &secret, 1);
        return rc ? fail(error, "cannot store Coinbase verification error") : 0;
    }
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {.method = "GET", .url = "https://api.coinbase.com/v2/user", .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 5};
    br_http_response response = {0}; char *transport_error = NULL; char status_error[80];
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) cause = transport_error ? transport_error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) { snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status); cause = status_error; }
    rc = br_result_set_verification_error(result, cause, &secret, 1); /* Copy normalized-PEM-only cause before release/free. */
    br_http_release(ctx, &response); free(transport_error);
    return rc ? fail(error, "cannot store Coinbase verification error") : 0;
}

/* Coinbase publishes the normalized PEM as Raw, not the name. Transfer it
 * once and allocate only the required NAME:PEM projection and metadata. */
static int finding_coinbase(br_result *result, const char name[96], char **pem,
                            size_t len, char **error)
{
    if (len > INT_MAX || len > SIZE_MAX - 96) return fail(error, "Coinbase result length overflow");
    result->detector_type = 5;
    result->raw = (br_bytes){(unsigned char *)*pem, len}; *pem = NULL;
    result->raw_v2.len = 96 + len;
    result->raw_v2.data = malloc(result->raw_v2.len);
    if (!result->raw_v2.data) return fail(error, "cannot create Coinbase result");
    memcpy(result->raw_v2.data, name, 95); result->raw_v2.data[95] = ':';
    memcpy(result->raw_v2.data + 96, result->raw.data, len);
    result->secret_parts = json_object_new_object();
    if (!result->secret_parts) return fail(error, "cannot create Coinbase result");
    br_json *part = json_object_new_string_len(name, 95);
    if (!part) return fail(error, "cannot create Coinbase result");
    if (json_object_object_add(result->secret_parts, "key_name", part) != 0) {
        json_object_put(part); return fail(error, "cannot create Coinbase result");
    }
    part = json_object_new_string_len((const char *)result->raw.data, (int)len);
    if (!part) return fail(error, "cannot create Coinbase result");
    if (json_object_object_add(result->secret_parts, "key", part) != 0) {
        json_object_put(part); return fail(error, "cannot create Coinbase result");
    }
    return 0;
}

static int scan_coinbase(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid or uninitialized Coinbase scan");
    const coinbase_patterns *patterns = detector->state;
    if (!patterns->name || !patterns->pem) return fail(error, "uninitialized Coinbase patterns");
    br_captures names = {0}, pems = {0}; size_t original_len = out->len;
    int rc = br_captures_find(patterns->name, input, &names, true, error);
    if (!rc) rc = br_captures_find(patterns->pem, input, &pems, true, error);
    /* Uniqueness is on ORIGINAL matches only. Canonical collisions must remain
     * distinct products; first-seen order is one permitted upstream map order. */
    for (size_t n = 0; !rc && n < names.len; ++n) {
        char name[96]; rc = normalize_name(br_captures_at(&names, n), name, error);
        for (size_t p = 0; !rc && p < pems.len; ++p) {
            char *pem = NULL; size_t pem_len = 0; coinbase_key key = {0}; br_result result = {0}; bool verified = false;
            rc = normalize_pem(br_captures_at(&pems, p), &pem, &pem_len, error);
            if (!rc) rc = parse_key((br_slice){(const unsigned char *)pem, pem_len}, &key, error); /* Mandatory even in NoV. */
            if (!rc && key.pkey) {
                rc = finding_coinbase(&result, name, &pem, pem_len, error);
                if (!rc) {
                    if (verify) rc = verify_coinbase(ctx, name, &key, &result, error);
                    verified = result.verified;
                    if (!rc && br_results_push(out, &result) != 0) rc = fail(error, "cannot append Coinbase result");
                }
            }
            EVP_PKEY_free(key.pkey); clear_free(pem, pem_len); br_result_clear(&result);
            if (!rc && verified) break; /* Only this ORIGINAL name's private-key loop. */
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&names); br_captures_clear(&pems);
    return rc ? -1 : 0;
}

static coinbase_patterns patterns;
static const char *const keywords[] = {"begin ec"};
static const br_detector coinbase = {
    .type = 5, .version = 0, .name = "Coinbase", .custom_name = "",
    .description = "Coinbase is a digital currency exchange that allows users to buy, sell, and store various cryptocurrencies. A Coinbase API key name and private key can be used to access and manage a user's account and transactions.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_coinbase,
};

int br_coinbase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Coinbase detector output");
    *out = NULL;
    if (!patterns.name && br_regex_compile("\\b(organizations\\\\*/\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}\\\\*/apiKeys\\\\*/\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12})\\b", &patterns.name, error)) return -1;
    if (!patterns.pem && br_regex_compile("(-----BEGIN EC(?:DSA)? PRIVATE KEY-----(?:\\r|\\n|\\\\+r|\\\\+n)(?:[a-zA-Z0-9+/]+={0,2}(?:\\r|\\n|\\\\+r|\\\\+n))+-----END EC(?:DSA)? PRIVATE KEY-----(?:\\r|\\n|\\\\+r|\\\\+n)?)", &patterns.pem, error)) return -1;
    *out = &coinbase; return 0;
}
