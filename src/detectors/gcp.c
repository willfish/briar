/* SPDX-License-Identifier: AGPL-3.0-only */
/* Direct selected port of TruffleHog v3.97.2 pkg/detectors/gcp/gcp.go,
 * golang.org/x/oauth2 v0.34.0 google/jwt/jws, and Go's selected string
 * literal/PEM/time behavior. BSD attribution: existing NOTICE and
 * LICENSES/BSD-3-Clause-Go.txt. No SDK, discovery or native OAuth HTTP. */
#include "detectors.h"
#include "captures.h"
#include "gcp_json.h"
#include "gcp_oauth.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define S(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
enum { G_TYPE, G_PROJECT, G_KID, G_KEY, G_EMAIL, G_CLIENT, G_AUTH, G_TOKEN, G_PROVIDER, G_CERT, G_FIELDS };
static const char *const tags[] = {"type", "project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri", "auth_provider_x509_cert_url", "client_x509_cert_url"};
typedef struct { br_json *ref; br_slice text; br_bytes repair; } gcp_string;
typedef struct { gcp_string fields[G_FIELDS]; char *cause; char **fatal; bool bad_type; } gcp_record;

static int gcp_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}
static bool equal(br_slice a, br_slice b) { return a.len == b.len && (!a.len || !memcmp(a.data, b.data, a.len)); }
static bool contains(br_slice a, br_slice b) { return br_slice_find(a, b, 0) != SIZE_MAX; }
static br_slice bytes(br_bytes b) { return (br_slice){b.data, b.len}; }
static void string_clear(gcp_string *s) { json_object_put(s->ref); free(s->repair.data); *s = (gcp_string){0}; }
static void record_clear(gcp_record *r) { for (size_t i = 0; i < G_FIELDS; ++i) string_clear(&r->fields[i]); free(r->cause); }
static int string_take(gcp_string *s, br_json *v, char **error)
{
    gcp_string next = {0};
    if (br_gcp_json_text(v, &next.text, &next.repair, error)) { free(next.repair.data); return -1; }
    next.ref = json_object_get(v); /* Callback values are ephemeral, NOT root children. */
    string_clear(s); *s = next; return 0;
}
static int record_member(void *user, br_slice name, br_json *v, br_slice raw)
{
    (void)raw; gcp_record *r = user;
    for (size_t i = 0; i < G_FIELDS; ++i) if (br_json_field_name(name, tags[i])) {
        if (!v) return 0; /* Go null merges with a previous string. */
        if (!json_object_is_type(v, json_type_string)) {
            r->bad_type = true; /* Ignored extraction error needs no formatter. */
            return 0; /* First type error is sticky; later members still decode. */
        }
        return string_take(&r->fields[i], v, r->fatal);
    }
    return 0; /* No generic-map float conversion of unknown numbers. */
}
static int record_decode(br_slice input, gcp_record *r, char **error)
{
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(input, NULL, &root, &end, &r->cause);
    if (rc < 0) { json_object_put(root); return gcp_fail(error, "cannot decode GCP credential JSON"); }
    if (rc) { json_object_put(root); return 1; }
    if (root && !json_object_is_type(root, json_type_object)) {
        rc = br_json_type_cause(root, NULL, "gcp.gcpKey", &r->cause);
        json_object_put(root); return rc ? gcp_fail(error, "cannot allocate GCP credential type cause") : 1;
    }
    r->fatal = error;
    rc = root ? br_json_each_member((br_slice){input.data, end}, record_member, r) : 0;
    json_object_put(root);
    if (rc) return gcp_fail(error && *error ? NULL : error, "cannot project GCP credential JSON");
    return r->cause || r->bad_type ? 1 : 0;
}

/* Ordered ReplaceAll, then ONLY the source's synthetic double-quoted Go
 * literal. A JSON-unquote would incorrectly accept surrogates and reject the
 * Go-only byte/octal/bell escapes. Failed unquote preserves its whole input. */
static int replace(br_slice in, br_slice old, br_slice replacement, br_bytes *owned, br_slice *out, char **error)
{
    if (!contains(in, old)) { *out = in; return 0; }
    unsigned char *p = malloc(in.len + 1); /* All three source replacements shrink. */
    if (!p) return gcp_fail(error, "cannot clean GCP input");
    size_t at = 0, from = 0, match;
    while ((match = br_slice_find(in, old, from)) != SIZE_MAX) {
        memcpy(p + at, in.data + from, match - from); at += match - from;
        memcpy(p + at, replacement.data, replacement.len); at += replacement.len;
        from = match + old.len;
    }
    memcpy(p + at, in.data + from, in.len - from); at += in.len - from; p[at] = 0;
    free(owned->data); *owned = (br_bytes){p, at}; *out = bytes(*owned); return 0;
}
static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t rune_write(unsigned char *p, uint32_t r)
{
    if (r < 128) { p[0] = (unsigned char)r; return 1; }
    if (r < 2048) { p[0] = (unsigned char)(0xc0 | (r >> 6)); p[1] = (unsigned char)(0x80 | (r & 63)); return 2; }
    if (r < 65536) { p[0] = (unsigned char)(0xe0 | (r >> 12)); p[1] = (unsigned char)(0x80 | ((r >> 6) & 63)); p[2] = (unsigned char)(0x80 | (r & 63)); return 3; }
    p[0] = (unsigned char)(0xf0 | (r >> 18)); p[1] = (unsigned char)(0x80 | ((r >> 12) & 63)); p[2] = (unsigned char)(0x80 | ((r >> 6) & 63)); p[3] = (unsigned char)(0x80 | (r & 63)); return 4;
}
static int literal_pass(br_slice in, unsigned char *out, size_t *written)
{
    size_t at = 0;
    for (size_t i = 0; i < in.len;) {
        unsigned char c = in.data[i++]; uint32_t r = c; bool multi = false;
        if (c == '"' || c == '\n') return 1;
        if (c >= 128) {
            size_t n = br_utf8_rune((br_slice){in.data + i - 1, in.len - i + 1}, &r);
            if (!n) { r = 0xfffd; n = 1; }
            i += n - 1; multi = true;
        } else if (c == '\\') {
            if (i == in.len) return 1;
            c = in.data[i++];
            switch (c) {
            case 'a': r = '\a'; break; case 'b': r = '\b'; break; case 'f': r = '\f'; break;
            case 'n': r = '\n'; break; case 'r': r = '\r'; break; case 't': r = '\t'; break; case 'v': r = '\v'; break;
            case '\\': r = '\\'; break; case '"': r = '"'; break;
            case 'x': case 'u': case 'U': {
                size_t n = c == 'x' ? 2 : c == 'u' ? 4 : 8; r = 0;
                if (in.len - i < n) return 1;
                for (size_t j = 0; j < n; ++j) { int h = hex_digit(in.data[i++]); if (h < 0) return 1; r = (r << 4) | (uint32_t)h; }
                multi = c != 'x';
                if (multi && (r > 0x10ffff || (r >= 0xd800 && r <= 0xdfff))) return 1;
                break;
            }
            default:
                if (c < '0' || c > '7' || in.len - i < 2) return 1;
                r = c - '0';
                for (size_t j = 0; j < 2; ++j) { c = in.data[i++]; if (c < '0' || c > '7') return 1; r = (r << 3) | (c - '0'); }
                if (r > 255) return 1;
            }
        }
        unsigned char encoded[4]; size_t n = multi ? rune_write(encoded, r) : (encoded[0] = (unsigned char)r, (size_t)1);
        if (at > SIZE_MAX - n - 1) return -1;
        if (out) memcpy(out + at, encoded, n);
        at += n;
    }
    *written = at; return 0;
}
static int clean_input(br_slice original, br_slice *out, br_bytes *owned, char **error)
{
    *out = original;
    if (replace(*out, S(",\\\\n"), S("\\n"), owned, out, error) ||
        replace(*out, S("\\\"\\\\n"), S("\\n"), owned, out, error) ||
        replace(*out, S("\\\\\""), S("\""), owned, out, error)) return -1;
    if (contains(*out, S("\\\"auth_provider_x509_cert_url\\\""))) {
        size_t n = 0; int rc = literal_pass(*out, NULL, &n);
        if (rc < 0) return gcp_fail(error, "GCP Go literal is too large");
        if (rc) return 0;
        unsigned char *p = malloc(n + 1);
        if (!p) return gcp_fail(error, "cannot unquote GCP Go literal");
        if (literal_pass(*out, p, &n)) { free(p); return gcp_fail(error, "GCP Go literal changed during decode"); }
        p[n] = 0; free(owned->data); *owned = (br_bytes){p, n}; *out = bytes(*owned);
    }
    return 0;
}
static br_slice trim_carets(br_slice s)
{
    if (s.len && s.data[0] == '<') { ++s.data; --s.len; }
    if (s.len && s.data[s.len - 1] == '>') --s.len;
    return s;
}
static void transform(gcp_record *r)
{
    br_slice *email = &r->fields[G_EMAIL].text;
    size_t i = br_slice_find(*email, S("<mailto:"), 0);
    if (i != SIZE_MAX) {
        email->data += i + 8; email->len -= i + 8;
        size_t end = br_slice_find(*email, S("<mailto:"), 0); if (end != SIZE_MAX) email->len = end;
        end = br_slice_find(*email, S("|"), 0); if (end != SIZE_MAX) email->len = end;
    }
    const size_t urls[] = {G_PROVIDER, G_AUTH, G_CERT, G_TOKEN};
    for (size_t j = 0; j < sizeof(urls)/sizeof(urls[0]); ++j) r->fields[urls[j]].text = trim_carets(r->fields[urls[j]].text);
}
static int add_string(br_json *object, const char *name, br_slice value, char **error)
{
    if (value.len > INT_MAX) return gcp_fail(error, "unsupported: GCP JSON string exceeds native length interface");
    br_json *v = json_object_new_string_len((const char *)(value.data ? value.data : (const unsigned char *)""), (int)value.len);
    if (!v) return gcp_fail(error, "cannot allocate GCP metadata string");
    if (json_object_object_add(object, name, v)) { json_object_put(v); return gcp_fail(error, "cannot add GCP metadata string"); }
    return 0;
}
static int finding(gcp_record *r, br_slice raw, br_result *out, char **error)
{
    out->detector_type = 6;
    out->raw.data = malloc(raw.len ? raw.len : 1);
    if (!out->raw.data) return gcp_fail(error, "cannot allocate GCP Raw");
    if (raw.len) memcpy(out->raw.data, raw.data, raw.len);
    out->raw.len = raw.len;
    br_slice values[G_FIELDS]; for (size_t i = 0; i < G_FIELDS; ++i) values[i] = r->fields[i].text;
    if (br_gcp_json_object(tags, values, G_FIELDS, &out->raw_v2, error)) return -1;
    out->extra_data = json_object_new_object(); out->secret_parts = json_object_new_object();
    if (!out->extra_data || !out->secret_parts) return gcp_fail(error, "cannot allocate GCP metadata");
    if (add_string(out->extra_data, "rotation_guide", S("https://howtorotate.com/docs/tutorials/gcp/"), error) ||
        add_string(out->extra_data, "project", values[G_PROJECT], error) ||
        add_string(out->secret_parts, "key", bytes(out->raw_v2), error)) return -1;
    return 0;
}
static bool crypto_oom(void)
{
    unsigned long code; bool oom = false;
    while ((code = ERR_get_error())) if (ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE) oom = true;
    return oom;
}

/* Generic envelope decoding deliberately ignores block.Type. PEM_read_bio's
 * generic form never asks for a password or interprets/decrypts a key label. */
static int pem_der(br_slice input, unsigned char **out, size_t *len, char **error)
{
    if (input.len > INT_MAX) return gcp_fail(error, "unsupported: GCP PEM exceeds native length interface");
    *out = NULL; *len = 0;
    if (!input.len) return 0;
    BIO *bio = BIO_new_mem_buf(input.data, (int)input.len);
    if (!bio) return gcp_fail(error, "cannot allocate GCP PEM reader");
    char *name = NULL, *headers = NULL; unsigned char *data = NULL; long n = 0;
    ERR_clear_error(); int ok = PEM_read_bio(bio, &name, &headers, &data, &n);
    bool oom = crypto_oom(); BIO_free(bio); OPENSSL_free(name); OPENSSL_free(headers);
    if (oom) { OPENSSL_free(data); return gcp_fail(error, "cannot allocate GCP PEM data"); }
    if (!ok) { OPENSSL_free(data); return 0; }
    if (n < 0) { OPENSSL_free(data); return gcp_fail(error, "invalid GCP PEM decoded length"); }
    *out = data; *len = (size_t)n; return 0;
}
/* 0 parsed (possibly non-RSA/nil prefetch), +1 ordinary bad DER. Diagnostic
 * handling for an SDK failure is deliberately separate from ignored prefetch. */
static int private_key(br_slice input, bool sdk, EVP_PKEY **key, br_slice *cause, char **error)
{
    unsigned char *pem = NULL; size_t n = 0; *key = NULL;
    if (pem_der(input, &pem, &n, error)) return -1;
    if (!pem && !sdk) return 0;
    br_slice der = pem ? (br_slice){pem, n} : input;
    if (der.len > LONG_MAX) { OPENSSL_free(pem); return gcp_fail(error, "unsupported: GCP DER exceeds native length interface"); }
    const unsigned char *p = der.data;
    ERR_clear_error(); PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)der.len);
    bool oom = crypto_oom();
    if (oom) { PKCS8_PRIV_KEY_INFO_free(p8); OPENSSL_free(pem); return gcp_fail(error, "cannot allocate GCP PKCS8 key"); }
    if (p8) {
        ERR_clear_error(); *key = EVP_PKCS82PKEY(p8); oom = crypto_oom(); PKCS8_PRIV_KEY_INFO_free(p8);
        if (oom) { EVP_PKEY_free(*key); *key = NULL; OPENSSL_free(pem); return gcp_fail(error, "cannot import GCP PKCS8 key"); }
    }
    if (!*key) {
        p = der.data; ERR_clear_error();
        *key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, (long)der.len); oom = crypto_oom();
        if (oom) { EVP_PKEY_free(*key); *key = NULL; OPENSSL_free(pem); return gcp_fail(error, "cannot allocate GCP PKCS1 key"); }
        /* Go PKCS1 rejects trailing bytes (PKCS8 ignores its outer remainder). */
        if (*key && p != der.data + der.len) { EVP_PKEY_free(*key); *key = NULL; }
    }
    bool empty = !der.len; OPENSSL_free(pem);
    if (!*key) {
        if (!sdk) return 1;
        if (empty) { *cause = S("private key should be a PEM or plain PKCS1 or PKCS8; parse error: asn1: syntax error: sequence truncated"); return 1; }
        return gcp_fail(error, "unsupported: GCP Go PKCS1/PKCS8 malformed-key diagnostic requires source ASN1 parity");
    }
    int kind = EVP_PKEY_base_id(*key);
    if (sdk && kind != EVP_PKEY_RSA) {
        EVP_PKEY_free(*key); *key = NULL;
        if (kind != EVP_PKEY_EC && kind != EVP_PKEY_ED25519 && kind != EVP_PKEY_X25519)
            return gcp_fail(error, "unsupported: GCP Go PKCS8 algorithm diagnostic");
        *cause = S("private key is invalid"); return 1;
    }
    ERR_clear_error(); EVP_PKEY_CTX *check = EVP_PKEY_CTX_new(*key, NULL);
    if (!check) { EVP_PKEY_free(*key); *key = NULL; return gcp_fail(error, "cannot allocate GCP private-key validation"); }
    int valid = EVP_PKEY_private_check(check); bool check_oom = crypto_oom(); EVP_PKEY_CTX_free(check);
    if (valid != 1) {
        EVP_PKEY_free(*key); *key = NULL;
        if (check_oom) return gcp_fail(error, "cannot validate GCP private key");
        if (!sdk) return 1;
        return gcp_fail(error, "unsupported: GCP Go invalid-private-key diagnostic");
    }
    return 0;
}

static bool go_space(uint32_t r)
{
    return (r >= 9 && r <= 13) || r == 32 || r == 0x85 || r == 0xa0 || r == 0x1680 ||
           (r >= 0x2000 && r <= 0x200a) || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000;
}
static br_slice trim_space(br_slice s)
{
    size_t start = 0, end = 0;
    for (size_t i = 0; i < s.len;) {
        uint32_t r; size_t n = br_utf8_rune((br_slice){s.data + i, s.len - i}, &r);
        if (!n) { r = 0xfffd; n = 1; }
        if (!go_space(r)) { if (end == 0) start = i; end = i + n; }
        i += n;
    }
    return (br_slice){s.data ? s.data + start : NULL, end ? end - start : 0};
}
static bool path_safe(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~' || c == '$' || c == '&' || c == '+' || c == ':' || c == '=' || c == '@';
}
static int cert_url(br_slice provided, br_slice email, br_bytes *out, char **error)
{
    provided = trim_space(provided);
    if (provided.len) {
        /* A URL control is a determinate ignored NewRequest error, not an ABI
         * string boundary. Never truncate one into a different PUBLIC URL. */
        for (size_t i = 0; i < provided.len; ++i) if (provided.data[i] < 32 || provided.data[i] == 127) return 1;
        if (provided.len == SIZE_MAX) return gcp_fail(error, "GCP certificate URL is too large");
        out->data = malloc(provided.len + 1);
        if (!out->data) return gcp_fail(error, "cannot allocate GCP certificate URL");
        memcpy(out->data, provided.data, provided.len); out->data[provided.len] = 0; out->len = provided.len; return 0;
    }
    if (!email.len) return 1;
    const br_slice prefix = S("https://www.googleapis.com/robot/v1/metadata/x509/"); size_t n = prefix.len;
    for (size_t i = 0; i < email.len; ++i) {
        size_t add = path_safe(email.data[i]) ? 1 : 3;
        if (n > SIZE_MAX - add - 1) return gcp_fail(error, "GCP certificate URL is too large");
        n += add;
    }
    out->data = malloc(n + 1);
    if (!out->data) return gcp_fail(error, "cannot allocate GCP certificate URL");
    memcpy(out->data, prefix.data, prefix.len); size_t at = prefix.len; static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < email.len; ++i) {
        unsigned char c = email.data[i];
        if (path_safe(c)) out->data[at++] = c;
        else { out->data[at++] = '%'; out->data[at++] = (unsigned char)hex[c >> 4]; out->data[at++] = (unsigned char)hex[c & 15]; }
    }
    out->data[at] = 0; out->len = at; return 0;
}
/* Typed map decoder: null values overwrite with "", duplicate keys overwrite;
 * unlike struct decoding an ordinary bad value invalidates the whole fetch. */
typedef struct { gcp_string name, pem; } cert_entry;
typedef struct { cert_entry *items; size_t len, capacity; char **fatal; bool bad_type; } cert_map;
static void cert_map_clear(cert_map *map)
{
    for (size_t i = 0; i < map->len; ++i) { string_clear(&map->items[i].name); string_clear(&map->items[i].pem); }
    free(map->items);
}
static int cert_member(void *user, br_slice name, br_json *v, br_slice raw)
{
    (void)raw; cert_map *m = user;
    if (v && !json_object_is_type(v, json_type_string)) {
        m->bad_type = true; return 0;
    }
    if (name.len > INT_MAX) return gcp_fail(m->fatal, "unsupported: GCP certificate KID exceeds native JSON length");
    br_json *key_json = json_object_new_string_len((const char *)name.data, (int)name.len);
    if (!key_json) return gcp_fail(m->fatal, "cannot allocate GCP certificate KID");
    gcp_string key = {0}; int rc = string_take(&key, key_json, m->fatal); json_object_put(key_json);
    if (rc) return -1;
    size_t i;
    for (i = 0; i < m->len; ++i) if (equal(key.text, m->items[i].name.text)) break;
    if (i == m->len) {
        if (m->len == m->capacity) {
            size_t next = m->capacity ? m->capacity * 2 : 4;
            if (next < m->capacity || next > SIZE_MAX / sizeof(*m->items)) { string_clear(&key); return gcp_fail(m->fatal, "GCP certificate map is too large"); }
            cert_entry *items = realloc(m->items, next * sizeof(*items));
            if (!items) { string_clear(&key); return gcp_fail(m->fatal, "cannot grow GCP certificate map"); }
            m->items = items; m->capacity = next;
        }
        m->items[m->len++] = (cert_entry){.name=key}; key = (gcp_string){0};
    }
    string_clear(&key);
    /* JSON null overwrites a map's value with "", unlike a struct string. */
    return string_take(&m->items[i].pem, v, m->fatal);
}
static int rsa_equal(EVP_PKEY *a, EVP_PKEY *b, bool *same, char **error)
{
    *same = false;
    if (!b || EVP_PKEY_base_id(b) != EVP_PKEY_RSA) return 0;
    BIGNUM *an = NULL, *ae = NULL, *bn = NULL, *be = NULL;
    ERR_clear_error();
    int ok = EVP_PKEY_get_bn_param(a, OSSL_PKEY_PARAM_RSA_N, &an) && EVP_PKEY_get_bn_param(a, OSSL_PKEY_PARAM_RSA_E, &ae) &&
             EVP_PKEY_get_bn_param(b, OSSL_PKEY_PARAM_RSA_N, &bn) && EVP_PKEY_get_bn_param(b, OSSL_PKEY_PARAM_RSA_E, &be);
    if (ok) *same = BN_cmp(an, bn) == 0 && BN_cmp(ae, be) == 0;
    BN_free(an); BN_free(ae); BN_free(bn); BN_free(be);
    if (!ok || crypto_oom()) return gcp_fail(error, "cannot compare GCP RSA public keys");
    return 0;
}
static int certificate_kid(const br_scan_ctx *ctx, gcp_record *r, br_result *result, char **error)
{
    if (!r->fields[G_KEY].text.len) return 0;
    br_bytes url = {0}; EVP_PKEY *key = NULL; br_slice unused = {0};
    br_http_response response = {0}; char *ordinary = NULL; br_json *root = NULL; cert_map map = {0}; bool sent = false;
    int rc = cert_url(r->fields[G_CERT].text, r->fields[G_EMAIL].text, &url, error);
    if (rc) { free(url.data); return rc < 0 ? -1 : 0; }
    rc = private_key(r->fields[G_KEY].text, false, &key, &unused, error);
    if (rc < 0) goto done;
    rc = 0;
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA) goto done;
    if (!ctx) goto done; /* NewRequestWithContext(nil) fails ordinarily. */
    const br_header accept = {"Accept", "application/json"};
    const br_http_request request = {.method="GET", .url=(const char *)url.data, .headers=&accept, .nheaders=1, .profile=BR_HTTP_DETECTOR_PUBLIC, .detector_type=6};
    sent = true; rc = br_http_send(ctx, &request, &response, &ordinary);
    if (rc) { if (rc < 0) rc = gcp_fail(error, ordinary ? ordinary : "GCP certificate transport failed fatally"); else rc = 0; goto done; }
    if (response.status < 200 || response.status >= 300) goto done;
    size_t end = 0;
    rc = br_json_first_document(response.body, response.body_error, &root, &end, &ordinary);
    if (rc < 0) { rc = gcp_fail(error, "cannot decode GCP certificate JSON"); goto done; }
    if (rc || (root && !json_object_is_type(root, json_type_object))) { rc = 0; goto done; }
    map.fatal = error;
    rc = root ? br_json_each_member((br_slice){response.body.data, end}, cert_member, &map) : 0;
    if (rc) { rc = -1; goto done; }
    if (map.bad_type) goto done;
    for (size_t i = 0; i < map.len; ++i) {
        br_slice kid = map.items[i].name.text;
        unsigned char *der = NULL; size_t n = 0;
        if (pem_der(map.items[i].pem.text, &der, &n, error)) { rc = -1; goto done; }
        if (!der) { rc = gcp_fail(error, "unsupported: GCP source dereferences nil certificate after missing PEM"); goto done; }
        if (n > LONG_MAX) { OPENSSL_free(der); rc = gcp_fail(error, "unsupported: GCP certificate DER exceeds native length interface"); goto done; }
        const unsigned char *at = der; ERR_clear_error(); X509 *cert = d2i_X509(NULL, &at, (long)n);
        bool oom = crypto_oom(); OPENSSL_free(der);
        if (oom) { X509_free(cert); rc = gcp_fail(error, "cannot allocate GCP certificate"); goto done; }
        if (!cert) continue;
        ERR_clear_error(); EVP_PKEY *pub = X509_get_pubkey(cert); oom = crypto_oom();
        if (oom) { EVP_PKEY_free(pub); X509_free(cert); rc = gcp_fail(error, "cannot allocate GCP certificate public key"); goto done; }
        bool same = false; rc = rsa_equal(key, pub, &same, error); EVP_PKEY_free(pub); X509_free(cert);
        if (rc) goto done;
        if (same) {
            if (kid.len) rc = add_string(result->extra_data, "private_key_id", kid, error);
            goto done; /* Empty matched KID still stops this map search. */
        }
    }
 done:
    if (sent) br_http_release(ctx, &response);
    free(ordinary); cert_map_clear(&map); json_object_put(root); EVP_PKEY_free(key); free(url.data);
    return rc;
}

static int join_cause(br_slice prefix, br_slice cause, br_gcp_oauth_error *out, char **error)
{
    if (prefix.len > SIZE_MAX - cause.len - 1) return gcp_fail(error, "GCP cause is too large");
    out->text.data = malloc(prefix.len + cause.len + 1);
    if (!out->text.data) return gcp_fail(error, "cannot allocate GCP cause");
    memcpy(out->text.data, prefix.data, prefix.len);
    if (cause.len) memcpy(out->text.data + prefix.len, cause.data, cause.len);
    out->text.len = prefix.len + cause.len; out->text.data[out->text.len] = 0; return 0;
}
static int quoted_cause(br_slice prefix, br_slice text, br_gcp_oauth_error *out, char **error)
{
    size_t n;
    if (br_gcp_oauth_quote(text, NULL, 0, &n, error)) return -1;
    if (prefix.len > SIZE_MAX - n - 1) return gcp_fail(error, "GCP quoted cause is too large");
    out->text.data = malloc(prefix.len + n + 1);
    if (!out->text.data) return gcp_fail(error, "cannot allocate GCP quoted cause");
    memcpy(out->text.data, prefix.data, prefix.len);
    if (br_gcp_oauth_quote(text, out->text.data + prefix.len, n, &n, error)) return -1;
    out->text.len = prefix.len + n; out->text.data[out->text.len] = 0; return 0;
}
static int segment(br_slice input, unsigned char *out, size_t *written, char **error)
{
    if (input.len > INT_MAX || input.len > (SIZE_MAX - 2) / 4 * 3) return gcp_fail(error, "GCP JWT segment exceeds native length interface");
    size_t padded = (input.len + 2) / 3 * 4;
    if (padded > INT_MAX) return gcp_fail(error, "GCP JWT Base64 exceeds native length interface");
    int n = EVP_EncodeBlock(out, input.data, (int)input.len);
    if (n < 0 || (size_t)n != padded) return gcp_fail(error, "GCP JWT Base64 encoding failed");
    while (n && out[n - 1] == '=') --n;
    for (int i = 0; i < n; ++i) { if (out[i] == '+') out[i] = '-'; else if (out[i] == '/') out[i] = '_'; }
    *written = (size_t)n; return 0;
}
static int claims_json(gcp_record *r, br_slice audience, br_bytes *out, char **error)
{
    struct timespec clock;
    if (clock_gettime(CLOCK_REALTIME, &clock)) return gcp_fail(error, "GCP realtime clock failed");
    intmax_t now = clock.tv_sec;
    if (now < INT64_MIN + 10 || now > INT64_MAX - 3590) return gcp_fail(error, "unsupported: GCP JWT clock range");
    char iat[32], exp[32];
    int a = snprintf(exp, sizeof(exp), "%" PRId64, (int64_t)now + 3590);
    int b = snprintf(iat, sizeof(iat), "%" PRId64, (int64_t)now - 10);
    if (a < 0 || b < 0 || (size_t)a >= sizeof(exp) || (size_t)b >= sizeof(iat)) return gcp_fail(error, "GCP JWT clock formatting failed");
    const br_slice p1 = S("{\"iss\":"), p2 = S(",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"aud\":"), p3 = S(",\"exp\":"), p4 = S(",\"iat\":");
    size_t email_n, aud_n;
    if (br_gcp_json_string(r->fields[G_EMAIL].text, NULL, 0, &email_n, error) || br_gcp_json_string(audience, NULL, 0, &aud_n, error)) return -1;
    size_t fixed = p1.len + p2.len + p3.len + p4.len + (size_t)a + (size_t)b + 1;
    if (email_n > SIZE_MAX - fixed - 1 || aud_n > SIZE_MAX - fixed - email_n - 1) return gcp_fail(error, "GCP JWT claims are too large");
    size_t n = fixed + email_n + aud_n;
    out->data = malloc(n + 1); if (!out->data) return gcp_fail(error, "cannot allocate GCP JWT claims");
    size_t at = 0, written;
#define PUT(v) do { memcpy(out->data + at, (v).data, (v).len); at += (v).len; } while (0)
    PUT(p1);
    if (br_gcp_json_string(r->fields[G_EMAIL].text, out->data + at, n - at, &written, error)) return -1;
    at += written;
    PUT(p2);
    if (br_gcp_json_string(audience, out->data + at, n - at, &written, error)) return -1;
    at += written;
    PUT(p3); memcpy(out->data + at, exp, (size_t)a); at += (size_t)a;
    PUT(p4); memcpy(out->data + at, iat, (size_t)b); at += (size_t)b;
#undef PUT
    out->data[at++] = '}'; out->data[at] = 0; out->len = at; return 0;
}
static int assertion(gcp_record *r, EVP_PKEY *key, br_slice audience, br_bytes *out, br_slice *cause, br_gcp_oauth_error *owned, char **error)
{
    const char *const names[] = {"alg", "typ", "kid"};
    const br_slice values[] = {S("RS256"), S("JWT"), r->fields[G_KID].text};
    br_bytes header = {0}, claims = {0}; EVP_MD_CTX *md = NULL; unsigned char *signature = NULL; int rc = -1;
    if (br_gcp_json_object(names, values, values[2].len ? 3 : 2, &header, error) || claims_json(r, audience, &claims, error)) goto done;
    int bits = EVP_PKEY_bits(key);
    if (bits < 1024) {
        /* Pinned default; no ambient GODEBUG/FIPS discovery. */
        char message[sizeof("crypto/rsa: -bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)") + 3 * sizeof(int)];
        int n = snprintf(message, sizeof(message), "crypto/rsa: %d-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)", bits);
        if (n < 0 || (size_t)n >= sizeof(message)) { rc = gcp_fail(error, "GCP RSA size diagnostic failed"); goto done; }
        rc = join_cause(S(""), (br_slice){(const unsigned char *)message, (size_t)n}, owned, error);
        if (!rc) { *cause = bytes(owned->text); rc = 1; }
        goto done;
    }
    int key_size = EVP_PKEY_get_size(key);
    if (key_size <= 0) { rc = gcp_fail(error, "GCP RSA signature size failed"); goto done; }
    size_t sig_size = (size_t)key_size;
    if (header.len > (SIZE_MAX - 2) / 4 * 3 || claims.len > (SIZE_MAX - 2) / 4 * 3 || sig_size > (SIZE_MAX - 2) / 4 * 3) { rc = gcp_fail(error, "GCP JWT size overflow"); goto done; }
    size_t h = (header.len + 2) / 3 * 4, c = (claims.len + 2) / 3 * 4, s = (sig_size + 2) / 3 * 4;
    if (h > SIZE_MAX - c - 3 || s > SIZE_MAX - h - c - 3) { rc = gcp_fail(error, "GCP JWT size overflow"); goto done; }
    out->data = malloc(h + c + s + 3); signature = malloc(sig_size);
    md = EVP_MD_CTX_new();
    if (!out->data || !signature || !md) { rc = gcp_fail(error, "cannot allocate GCP JWT signature"); goto done; }
    size_t at, n;
    if (segment(bytes(header), out->data, &at, error)) goto done;
    out->data[at++] = '.';
    if (segment(bytes(claims), out->data + at, &n, error)) goto done;
    at += n; EVP_PKEY_CTX *pkctx = NULL;
    if (EVP_DigestSignInit(md, &pkctx, EVP_sha256(), NULL, key) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_DigestSign(md, signature, &sig_size, out->data, at) != 1) {
        rc = gcp_fail(error, "GCP native RSA-SHA256 signing failed"); goto done;
    }
    out->data[at++] = '.';
    if (segment((br_slice){signature, sig_size}, out->data + at, &n, error)) goto done;
    at += n; out->data[at] = 0; out->len = at; rc = 0;
 done:
    EVP_MD_CTX_free(md); free(signature); free(header.data); free(claims.data); return rc;
}

/* Source time.Time.UnmarshalJSON uses the ORIGINAL quoted bytes, not a JSON
 * unescaped value. Parse(RFC3339) fallback currently permits a one-digit hour,
 * comma fractional seconds and zone 24/60; unused valid values need no clock. */
static int time_error(br_slice input, br_slice elem, br_slice remainder, const char *range, br_gcp_oauth_error *out, char **error)
{
    size_t qinput, qelem = 0, qrest = 0;
    if (br_gcp_oauth_quote(input, NULL, 0, &qinput, error)) return -1;
    if (!range && (br_gcp_oauth_quote(elem, NULL, 0, &qelem, error) || br_gcp_oauth_quote(remainder, NULL, 0, &qrest, error))) return -1;
    size_t n = sizeof("parsing time ") - 1 + qinput;
    if (range) n += strlen(range);
    else {
        size_t extra = sizeof(" as \"2006-01-02T15:04:05Z07:00\": cannot parse ") - 1 + sizeof(" as ") - 1;
        if (n > SIZE_MAX - extra - qelem - qrest - 1) return gcp_fail(error, "GCP time diagnostic is too large");
        n += extra + qelem + qrest;
    }
    out->text.data = malloc(n + 1); if (!out->text.data) return gcp_fail(error, "cannot allocate GCP time diagnostic");
    size_t at = 0, wrote;
#define TEXT(t) do { const char *p_ = (t); size_t n_ = strlen(p_); memcpy(out->text.data + at, p_, n_); at += n_; } while (0)
    TEXT("parsing time ");
    if (br_gcp_oauth_quote(input, out->text.data + at, n - at, &wrote, error)) return -1;
    at += wrote;
    if (range) TEXT(range);
    else {
        TEXT(" as \"2006-01-02T15:04:05Z07:00\": cannot parse ");
        if (br_gcp_oauth_quote(remainder, out->text.data + at, n - at, &wrote, error)) return -1;
        at += wrote;
        TEXT(" as ");
        if (br_gcp_oauth_quote(elem, out->text.data + at, n - at, &wrote, error)) return -1;
        at += wrote;
    }
#undef TEXT
    out->text.data[at] = 0; out->text.len = at; return 1;
}
static int time_extra(br_slice input, br_slice extra, br_gcp_oauth_error *out, char **error)
{
    size_t a, b;
    if (br_gcp_oauth_quote(input, NULL, 0, &a, error) || br_gcp_oauth_quote(extra, NULL, 0, &b, error)) return -1;
    const br_slice prefix = S("parsing time "), sep = S(": extra text: ");
    if (a > SIZE_MAX - prefix.len - sep.len - 1 || b > SIZE_MAX - prefix.len - sep.len - a - 1) return gcp_fail(error, "GCP time diagnostic is too large");
    size_t n = prefix.len + a + sep.len + b;
    out->text.data = malloc(n + 1);
    if (!out->text.data) return gcp_fail(error, "cannot allocate GCP time diagnostic");
    memcpy(out->text.data, prefix.data, prefix.len);
    if (br_gcp_oauth_quote(input, out->text.data + prefix.len, a, &a, error)) return -1;
    memcpy(out->text.data + prefix.len + a, sep.data, sep.len);
    if (br_gcp_oauth_quote(extra, out->text.data + prefix.len + a + sep.len, b, &b, error)) return -1;
    out->text.len = n; out->text.data[n] = 0; return 1;
}
static bool digits(br_slice s, size_t *at, size_t min, size_t max, unsigned *value)
{
    size_t start = *at; unsigned v = 0;
    while (*at < s.len && *at - start < max && s.data[*at] >= '0' && s.data[*at] <= '9') v = v * 10 + s.data[(*at)++] - '0';
    *value = v; return *at - start >= min;
}
static int time_validate(br_slice raw, br_gcp_oauth_error *out, char **error)
{
    if (equal(raw, S("null"))) return 0;
    if (raw.len < 2 || raw.data[0] != '"' || raw.data[raw.len - 1] != '"') return join_cause(S(""), S("Time.UnmarshalJSON: input is not a JSON string"), out, error) ? -1 : 1;
    br_slice s = {raw.data + 1, raw.len - 2}; size_t at = 0, start; unsigned v[6] = {0};
    const br_slice elem[] = {S("2006"), S("01"), S("02"), S("15"), S("04"), S("05")};
    const char separators[] = {'-', '-', 'T', ':', ':'};
    const br_slice sep[] = {S("-"), S("-"), S("T"), S(":"), S(":")};
    for (size_t i = 0; i < 6; ++i) {
        start = at;
        if (!digits(s, &at, i == 0 ? 4 : i == 3 ? 1 : 2, i == 0 ? 4 : 2, &v[i])) return time_error(s, elem[i], (br_slice){s.data + start, s.len - start}, NULL, out, error);
        const char *range = i == 1 && (v[i] < 1 || v[i] > 12) ? ": month out of range" :
                            i == 2 && (v[i] > 31) ? ": day out of range" :
                            i == 3 && v[i] > 23 ? ": hour out of range" :
                            i == 4 && v[i] > 59 ? ": minute out of range" :
                            i == 5 && v[i] > 59 ? ": second out of range" : NULL;
        if (range) return time_error(s, elem[i], (br_slice){s.data + at, s.len - at}, range, out, error);
        if (i < 5) {
            if (at == s.len || s.data[at] != (unsigned char)separators[i]) return time_error(s, sep[i], (br_slice){s.data + at, s.len - at}, NULL, out, error);
            ++at;
        }
    }
    if (at + 1 < s.len && (s.data[at] == '.' || s.data[at] == ',') && s.data[at + 1] >= '0' && s.data[at + 1] <= '9') {
        ++at; while (at < s.len && s.data[at] >= '0' && s.data[at] <= '9') ++at;
    }
    start = at;
    if (at < s.len && s.data[at] == 'Z') ++at;
    else {
        if (s.len - at < 6 || (s.data[at] != '-' && s.data[at] != '+') || s.data[at + 3] != ':') return time_error(s, S("Z07:00"), (br_slice){s.data + start, s.len - start}, NULL, out, error);
        ++at; unsigned hour, minute;
        if (!digits(s, &at, 2, 2, &hour) || at == s.len || s.data[at++] != ':' || !digits(s, &at, 2, 2, &minute)) return time_error(s, S("Z07:00"), (br_slice){s.data + start, s.len - start}, NULL, out, error);
        if (hour > 24 || minute > 60) return time_error(s, S("Z07:00"), (br_slice){s.data + start, s.len - start}, hour > 24 ? ": time zone offset hour out of range" : ": time zone offset minute out of range", out, error);
    }
    if (at != s.len) return time_extra(s, (br_slice){s.data + at, s.len - at}, out, error);
    static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    unsigned max = days[v[1] - 1] + (v[1] == 2 && (v[0] % 4 == 0 && (v[0] % 100 != 0 || v[0] % 400 == 0)));
    if (!v[2] || v[2] > max) return time_error(s, S(""), S(""), ": day out of range", out, error);
    return 0;
}
static bool int64_token(br_slice raw)
{
    size_t at = raw.len && raw.data[0] == '-' ? 1 : 0; bool negative = at != 0;
    uint64_t n = 0, limit = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    if (at == raw.len) return false;
    for (; at < raw.len; ++at) {
        unsigned char c = raw.data[at]; if (c < '0' || c > '9' || n > (limit - (c - '0')) / 10) return false;
        n = n * 10 + c - '0';
    }
    return true;
}
typedef struct { gcp_string id; char *cause; br_gcp_oauth_error custom; char **fatal; bool claims, suppressed; } token_fields;
static int numeric_cause(br_slice raw, const char *path, char **out, char **error)
{
    const br_slice prefix = S("json: cannot unmarshal number ");
    char suffix[96]; /* Complete fixed paths above and fixed int64 type. */
    int n = snprintf(suffix, sizeof(suffix), " into Go struct field %s of type int64", path);
    if (n < 0 || (size_t)n >= sizeof(suffix) || raw.len > SIZE_MAX - prefix.len - (size_t)n - 1) return gcp_fail(error, "GCP numeric type cause is too large");
    *out = malloc(prefix.len + raw.len + (size_t)n + 1);
    if (!*out) return gcp_fail(error, "cannot allocate GCP numeric type cause");
    memcpy(*out, prefix.data, prefix.len); memcpy(*out + prefix.len, raw.data, raw.len); memcpy(*out + prefix.len + raw.len, suffix, (size_t)n + 1); return 0;
}
static int typed_member(void *user, br_slice name, br_json *v, br_slice raw)
{
    token_fields *f = user; const char *path = NULL, *expected = "string"; bool integer = false, id = false;
    if (!f->claims && br_json_field_name(name, "expiry")) {
        /* No valid RFC3339 contains this literal. A failed string parse's Go
         * %q quotes its whole raw value, without creating/removing the literal. */
        if (v && json_object_is_type(v, json_type_string) && contains(raw, S("invalid_grant"))) { f->suppressed = true; return 1; }
        return time_validate(raw, &f->custom, f->fatal);
    }
    if (f->claims) {
        const char *const names[] = {"iss", "scope", "aud", "typ", "sub", "prn", "exp", "iat"};
        const char *const paths[] = {"ClaimSet.iss", "ClaimSet.scope", "ClaimSet.aud", "ClaimSet.typ", "ClaimSet.sub", "ClaimSet.prn", "ClaimSet.exp", "ClaimSet.iat"};
        for (size_t i = 0; i < 8; ++i) if (br_json_field_name(name, names[i])) { path = paths[i]; integer = i >= 6; break; }
    } else {
        if (br_json_field_name(name, "access_token")) path = ".access_token";
        else if (br_json_field_name(name, "token_type")) path = ".token_type";
        else if (br_json_field_name(name, "refresh_token")) path = ".refresh_token";
        else if (br_json_field_name(name, "id_token")) { path = ".id_token"; id = true; }
        else if (br_json_field_name(name, "expires_in")) { path = ".expires_in"; integer = true; }
    }
    if (!path || !v) return 0;
    if (integer) expected = "int64";
    bool valid = integer ? (json_object_is_type(v, json_type_int) && int64_token(raw)) : json_object_is_type(v, json_type_string);
    if (!valid) {
        if (!f->cause) {
            if (integer && (json_object_is_type(v, json_type_int) || json_object_is_type(v, json_type_double))) {
                if (numeric_cause(raw, path, &f->cause, f->fatal)) return -1;
            } else if (br_json_type_cause(v, path, expected, &f->cause)) return gcp_fail(f->fatal, "cannot allocate GCP token type cause");
        }
        return 0;
    }
    if (id) return string_take(&f->id, v, f->fatal);
    /* Go also repairs unused strings; no owned copy needed when valid UTF8. */
    if (!integer) { br_slice text; br_bytes repair = {0}; int rc = br_gcp_json_text(v, &text, &repair, f->fatal); free(repair.data); if (rc) return -1; }
    return 0;
}
static int decode_typed(br_slice body, bool claims, token_fields *f, char **error)
{
    br_json *root = NULL; size_t end = body.len;
    int rc = claims ? br_json_first_document(body, NULL, &root, &end, &f->cause) : br_json_document(body, &root, &f->cause);
    if (rc < 0) { json_object_put(root); return gcp_fail(error, "cannot decode GCP token JSON"); }
    if (rc) { json_object_put(root); return 1; }
    if (root && !json_object_is_type(root, json_type_object)) {
        rc = br_json_type_cause(root, NULL, claims ? "jws.ClaimSet" : "struct { oauth2.Token; IDToken string \"json:\\\"id_token\\\"\" }", &f->cause);
        json_object_put(root); return rc ? gcp_fail(error, "cannot allocate GCP token type cause") : 1;
    }
    f->fatal = error; f->claims = claims;
    rc = root ? br_json_each_member((br_slice){body.data, end}, typed_member, f) : 0;
    json_object_put(root);
    if (rc < 0) return gcp_fail(error && *error ? NULL : error, "cannot project GCP token JSON");
    return rc || f->cause ? 1 : 0;
}
/* Raw URL decoder ignores CR/LF like encoding/base64, but rejects '=', '+' and
 * '/'. Non-strict unused low bits are accepted. Error index is original input. */
static int id_payload(br_slice encoded, br_bytes *out, size_t *bad, char **error)
{
    if (encoded.len == SIZE_MAX) return gcp_fail(error, "GCP ID token is too large");
    out->data = malloc(encoded.len + 1);
    if (!out->data) return gcp_fail(error, "cannot allocate GCP ID token payload");
    unsigned group = 0, count = 0;
    for (size_t i = 0; i < encoded.len; ++i) {
        unsigned char c = encoded.data[i]; int v;
        if (c == '\r' || c == '\n') continue;
        if (c >= 'A' && c <= 'Z') v = c - 'A'; else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52; else if (c == '-') v = 62; else if (c == '_') v = 63;
        else { *bad = i; return 1; }
        group = (group << 6) | (unsigned)v; ++count;
        if (count == 4) {
            out->data[out->len++] = (unsigned char)(group >> 16); out->data[out->len++] = (unsigned char)(group >> 8); out->data[out->len++] = (unsigned char)group; group = count = 0;
        }
    }
    if (count == 1) { *bad = encoded.len - 1; return 1; }
    if (count >= 2) out->data[out->len++] = (unsigned char)(group >> (count == 2 ? 4 : 10));
    if (count == 3) out->data[out->len++] = (unsigned char)(group >> 2);
    out->data[out->len] = 0; return 0;
}
static void token_fields_clear(token_fields *f) { string_clear(&f->id); free(f->cause); br_gcp_oauth_error_clear(&f->custom); }
static int decode_id(br_slice token, br_gcp_oauth_error *cause, char **error)
{
    size_t a = br_slice_find(token, S("."), 0), b = a == SIZE_MAX ? SIZE_MAX : br_slice_find(token, S("."), a + 1);
    if (b == SIZE_MAX || br_slice_find(token, S("."), b + 1) != SIZE_MAX)
        return join_cause(S("oauth2: error decoding JWT token: "), S("jws: invalid token received"), cause, error) ? -1 : 1;
    br_bytes payload = {0}; size_t bad = 0;
    int rc = id_payload((br_slice){token.data + a + 1, b - a - 1}, &payload, &bad, error);
    token_fields f = {0};
    if (rc < 0) goto done;
    if (rc) {
        char message[sizeof("illegal base64 data at input byte ") + 3 * sizeof(size_t)];
        int n = snprintf(message, sizeof(message), "illegal base64 data at input byte %zu", bad);
        if (n < 0 || (size_t)n >= sizeof(message)) { rc = gcp_fail(error, "GCP Base64 error formatting failed"); goto done; }
        rc = join_cause(S("oauth2: error decoding JWT token: "), (br_slice){(const unsigned char *)message, (size_t)n}, cause, error) ? -1 : 1; goto done;
    }
    rc = decode_typed(bytes(payload), true, &f, error);
    if (rc > 0) rc = join_cause(S("oauth2: error decoding JWT token: "), (br_slice){(const unsigned char *)f.cause, f.cause ? strlen(f.cause) : 0}, cause, error) ? -1 : 1;
 done:
    free(payload.data); token_fields_clear(&f); return rc;
}
static int jwt_token(const br_gcp_state *state, const br_scan_ctx *ctx, gcp_record *r, bool *verified, br_slice *cause, br_gcp_oauth_error *owned, char **error)
{
    EVP_PKEY *key = NULL; br_bytes jwt = {0}, form = {0}, body = {0}; br_gcp_oauth_error io_error = {0};
    br_gcp_oauth_response response = {0}; token_fields fields = {0}; bool sent = false; int rc;
    rc = private_key(r->fields[G_KEY].text, true, &key, cause, error);
    if (rc) { rc = rc < 0 ? -1 : 0; goto done; }
    /* Source ContextClient dereferences ctx after ParseKey, before signing. */
    if (!ctx) { rc = gcp_fail(error, "unsupported: GCP source nil-context SDK client panic"); goto done; }
    br_slice url = r->fields[G_TOKEN].text; if (!url.len) url = S("https://oauth2.googleapis.com/token");
    rc = assertion(r, key, url, &jwt, cause, owned, error);
    if (rc) { if (rc > 0) rc = 0; goto done; }
    const br_gcp_oauth_pair pairs[] = {{"assertion", bytes(jwt)}, {"grant_type", S("urn:ietf:params:oauth:grant-type:jwt-bearer")}};
    if (br_gcp_oauth_form(pairs, 2, &form, error)) { rc = -1; goto done; }
    /* Do not turn unported arbitrary net/url constructor behavior into mock
     * success. Preserve custom URI bytes in NoV/RawV2; verification currently
     * supports the canonical SDK endpoint only, after required signing/form. */
    if (!equal(url, S("https://oauth2.googleapis.com/token"))) {
        rc = gcp_fail(error, "unsupported: GCP noncanonical SDK token URI constructor"); goto done;
    }
    if (!state->io) { rc = gcp_fail(error, "unsupported: GCP native SDK JWT HTTP byte I/O is not implemented"); goto done; }
    if (!state->io->send || !state->io->read || !state->io->release) { rc = gcp_fail(error, "invalid GCP SDK JWT HTTP byte I/O"); goto done; }
    const br_gcp_oauth_header header = {"Content-Type", S("application/x-www-form-urlencoded")};
    const br_gcp_oauth_request request = {.role=BR_GCP_JWT_POST, .method="POST", .url=url, .body=bytes(form), .headers=&header, .nheaders=1, .timeout_ns=0};
    sent = true; rc = state->io->send(state->user, ctx, &request, &response, &io_error);
    if (rc < 0) { rc = gcp_fail(error, "GCP JWT HTTP sender failed fatally"); goto done; }
    if (!rc) {
        br_gcp_oauth_error_clear(&io_error);
        rc = br_gcp_oauth_read(state->io, state->user, &response, &body, &io_error, error);
    }
    if (rc < 0) goto done;
    if (rc > 0) {
        /* fmt.Errorf(%v), NOT %w: keep FULL Do/read cause, never its leaf. */
        if (contains(bytes(io_error.text), S("invalid_grant"))) { rc = 0; goto done; }
        rc = join_cause(S("oauth2: cannot fetch token: "), bytes(io_error.text), owned, error); if (!rc) *cause = bytes(owned->text); goto done;
    }
    if (response.status < 200 || response.status > 299) {
        if (contains(response.status_text, S("invalid_grant")) || contains(bytes(body), S("invalid_grant"))) { rc = 0; goto done; }
        rc = br_gcp_oauth_retrieve_error(response.status_text, bytes(body), (br_slice){0}, (br_slice){0}, (br_slice){0}, owned, error);
        if (!rc) *cause = bytes(owned->text);
        goto done;
    }
    rc = decode_typed(bytes(body), false, &fields, error);
    if (rc < 0) goto done;
    if (rc > 0) {
        if (fields.suppressed) { rc = 0; goto done; }
        br_slice detail = fields.custom.text.data ? bytes(fields.custom.text) : (br_slice){(const unsigned char *)fields.cause, fields.cause ? strlen(fields.cause) : 0};
        if (contains(detail, S("invalid_grant"))) { rc = 0; goto done; }
        rc = join_cause(S("oauth2: cannot fetch token: "), detail, owned, error); if (!rc) *cause = bytes(owned->text); goto done;
    }
    if (fields.id.text.len) {
        rc = decode_id(fields.id.text, owned, error);
        if (rc < 0) goto done;
        if (rc > 0) {
            if (contains(bytes(owned->text), S("invalid_grant"))) { br_gcp_oauth_error_clear(owned); rc = 0; goto done; }
            *cause = bytes(owned->text); rc = 0; goto done;
        }
    }
    *verified = true; rc = 0;
 done:
    if (sent) state->io->release(state->user, &response); /* request values still live */
    EVP_PKEY_free(key); free(jwt.data); free(form.data); free(body.data); br_gcp_oauth_error_clear(&io_error); token_fields_clear(&fields); return rc;
}
static int verify(const br_gcp_state *state, const br_scan_ctx *ctx, gcp_record *r, br_result *result, br_slice *cause, br_gcp_oauth_error *owned, char **error)
{
    br_slice type = r->fields[G_TYPE].text;
    if (equal(type, S("service_account"))) return jwt_token(state, ctx, r, &result->verified, cause, owned, error);
    if (equal(type, S("authorized_user"))) *cause = S("oauth2: token expired and refresh token is not set");
    else if (equal(type, S("external_account"))) *cause = S("oauth2/google/externalaccount: Audience must be set");
    else if (equal(type, S("external_account_authorized_user"))) *cause = S("oauth2/google: Token should be created with fields to make it valid (`token` and `expiry`), or fields to allow it to refresh (`refresh_token`, `token_url`, `client_id`, `client_secret`).");
    else if (equal(type, S("impersonated_service_account"))) *cause = S("missing 'source_credentials' field or 'service_account_impersonation_url' in credentials");
    else if (!type.len) *cause = S("missing 'type' field in credentials");
    else {
        if (quoted_cause(S("unknown credential type: "), type, owned, error)) return -1;
        *cause = bytes(owned->text);
    }
    return 0; /* Constructor causes are never invalid_grant-suppressed. */
}
static int set_error(br_result *result, br_slice cause, br_slice original, char **error)
{
    if (!cause.data) return br_result_set_verification_error(result, NULL, &original, 1) ? gcp_fail(error, "cannot set GCP verification error") : 0;
    if (!memchr(cause.data, 0, cause.len))
        return br_result_set_verification_error(result, (const char *)cause.data, &original, 1) ? gcp_fail(error, "cannot set GCP verification error") : 0;
    /* ABI1 takes C strings. Decide representability AFTER bytewise source
     * redaction. A NUL wholly removed with the original match is allowed. */
    size_t from = 0, match, n = 0;
    while (original.len && (match = br_slice_find(cause, original, from)) != SIZE_MAX) {
        if (memchr(cause.data + from, 0, match - from)) return gcp_fail(error, "unsupported: GCP verification error contains NUL after redaction");
        if (n > SIZE_MAX - (match - from) - S("[REDACTED]").len - 1) return gcp_fail(error, "GCP redacted error is too large");
        n += match - from + S("[REDACTED]").len; from = match + original.len;
    }
    if (memchr(cause.data + from, 0, cause.len - from)) return gcp_fail(error, "unsupported: GCP verification error contains NUL after redaction");
    if (n > SIZE_MAX - (cause.len - from) - 1) return gcp_fail(error, "GCP redacted error is too large");
    n += cause.len - from; char *redacted = malloc(n + 1);
    if (!redacted) return gcp_fail(error, "cannot represent GCP redacted error");
    from = 0; size_t at = 0;
    while (original.len && (match = br_slice_find(cause, original, from)) != SIZE_MAX) {
        memcpy(redacted + at, cause.data + from, match - from); at += match - from;
        memcpy(redacted + at, "[REDACTED]", 10); at += 10; from = match + original.len;
    }
    memcpy(redacted + at, cause.data + from, cause.len - from); redacted[n] = 0;
    int rc = br_result_set_verification_error(result, redacted, NULL, 0); free(redacted);
    return rc ? gcp_fail(error, "cannot set GCP verification error") : 0;
}
static bool false_positive(const br_detector *d, const br_result *r, char **reason)
{
    (void)d; (void)r; if (reason) *reason = NULL; return false;
}
static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verification, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return gcp_fail(error, "invalid GCP scan arguments");
    const br_gcp_state *state = detector->state; size_t initial = out->len; br_captures captures = {0};
    if (br_captures_find(state->regex, input, &captures, true, error)) { br_captures_clear(&captures); return -1; }
    int rc = 0;
    for (size_t i = 0; i < captures.len; ++i) {
        br_slice original = br_captures_at(&captures, i), cleaned; br_bytes storage = {0}; gcp_record record = {0}; br_result result = {0}; br_gcp_oauth_error owned = {0};
        if (clean_input(original, &cleaned, &storage, error)) { rc = -1; goto candidate_done; }
        rc = record_decode(cleaned, &record, error); if (rc) { if (rc > 0) rc = 0; goto candidate_done; }
        transform(&record);
        br_slice email = record.fields[G_EMAIL].text, raw = email.len ? email : cleaned;
        if (equal(raw, S("image-pulling@authenticated-image-pulling.iam.gserviceaccount.com"))) goto candidate_done;
        if (finding(&record, raw, &result, error)) { rc = -1; goto candidate_done; }
        if (verification && certificate_kid(ctx, &record, &result, error)) { rc = -1; goto candidate_done; }
        br_json *kid;
        if (!json_object_object_get_ex(result.extra_data, "private_key_id", &kid) && record.fields[G_KID].text.len && add_string(result.extra_data, "private_key_id", record.fields[G_KID].text, error)) { rc = -1; goto candidate_done; }
        if (record.fields[G_TYPE].text.len && add_string(result.secret_parts, "type", record.fields[G_TYPE].text, error)) { rc = -1; goto candidate_done; }
        if (verification) {
            br_slice cause = {0};
            if (verify(state, ctx, &record, &result, &cause, &owned, error) || set_error(&result, cause, original, error)) { rc = -1; goto candidate_done; }
        }
        /* Output-only ABI boundary, after transformations/skips and required
         * owned work. Invalid UTF8 is representable; embedded NUL is not. */
        if (email.len && memchr(email.data, 0, email.len)) { rc = gcp_fail(error, "unsupported: GCP Redacted contains embedded NUL in ABI1"); goto candidate_done; }
        result.redacted = malloc(email.len + 1);
        if (!result.redacted) { rc = gcp_fail(error, "cannot allocate GCP Redacted"); goto candidate_done; }
        if (email.len) memcpy(result.redacted, email.data, email.len);
        result.redacted[email.len] = 0;
        if (br_results_push(out, &result)) { rc = gcp_fail(error, "cannot append GCP finding"); goto candidate_done; }
 candidate_done:
        br_result_clear(&result); record_clear(&record); free(storage.data); br_gcp_oauth_error_clear(&owned);
        if (rc < 0) break;
    }
    br_captures_clear(&captures);
    if (rc < 0) while (out->len > initial) br_result_clear(&out->items[--out->len]);
    return rc < 0 ? -1 : 0;
}
int br_gcp_init(const br_detector **out, char **error)
{
    static const char *const keywords[] = {"provider_x509"}; static br_gcp_state state;
    static br_detector detector = {.type=6, .version=0, .name="GCP", .custom_name="", .description="GCP (Google Cloud Platform) is a suite of cloud computing services that runs on the same infrastructure that Google uses internally for its end-user products. GCP keys can be used to access and manage these services.", .keywords=keywords, .nkeywords=1, .max_secret_size=2048, .start_offset=4096, .max_credential_span=-1, .state=&state, .scan=scan, .false_positive=false_positive};
    if (error) *error = NULL;
    if (!out) return gcp_fail(error, "invalid GCP factory output");
    if (!state.regex && br_regex_compile("(\\{[^{]+auth_provider_x509_cert_url[^}]+\\})", &state.regex, error)) return -1;
    *out = &detector; return 0;
}
