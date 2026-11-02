/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/jwt/jwt.go.
 * Verification is injected HTTP plus memory-only crypto. Live JWKS is unsupported. */
#include "detectors.h"
#include "findings.h"
#include "json.h"
#include "../go_time.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <json-c/json_util.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <stdarg.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char description[] =
    "A JSON Web Token (JWT) is an approach to authentication or authorization that does not depend on server-side data. It may allow access to protected resources.";
static const char *const keywords[] = {"ewogIC", "ewoid", "eyJ"};
static const char jwt_pattern[] =
    "\\b((?:eyJ|ewogIC|ewoid)[A-Za-z0-9_-]{12,}={0,2}\\.(?:eyJ|ewo)[A-Za-z0-9_-]{12,}={0,2}\\.[A-Za-z0-9_-]{12,})\\b";
enum { JWT_BODY_LIMIT = 1024 * 1024, JWT_LEEWAY = 60 };

typedef struct {
    br_regex *regex;
} jwt_state;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

#ifndef jwt_strdup
#define jwt_strdup strdup
#endif

static int format_owned(char **out, const char *fmt, ...)
{
    va_list args, copy;
    va_start(args, fmt);
    int n = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (n < 0) return -1;
    char *buf = malloc((size_t)n + 1);
    if (!buf) return -1;
    va_start(copy, fmt);
    int written = vsnprintf(buf, (size_t)n + 1, fmt, copy);
    va_end(copy);
    if (written < 0 || written != n) {
        free(buf);
        return -1;
    }
    *out = buf;
    return 0;
}

static int owned_copy(br_slice in, char **out)
{
    *out = NULL;
    if (in.len == SIZE_MAX) return -1;
    char *copy = malloc(in.len + 1);
    if (!copy) return -1;
    if (in.len) memcpy(copy, in.data, in.len);
    copy[in.len] = '\0';
    *out = copy;
    return 0;
}

static bool slice_eq(br_slice left, br_slice right)
{
    return left.len == right.len && (!left.len || !memcmp(left.data, right.data, left.len));
}

static bool known_alg(br_slice alg)
{
    static const char *const names[] = {
        "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (alg.len == strlen(names[i]) && !memcmp(alg.data, names[i], alg.len)) return true;
    return false;
}

static bool hmac_alg(br_slice alg)
{
    return (alg.len == 5 && !memcmp(alg.data, "HS256", 5)) ||
           (alg.len == 5 && !memcmp(alg.data, "HS384", 5)) ||
           (alg.len == 5 && !memcmp(alg.data, "HS512", 5));
}

static int b64_digit(unsigned char c, bool url)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (url) return c == '-' ? 62 : c == '_' ? 63 : -1;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}

/* Padding is allowed and decoding is not strict. JWT segments are URL-safe. */
static int b64_decode(br_slice in, bool url, bool add_padding, bool reject_after_pad, br_bytes *out)
{
    *out = (br_bytes){0};
    size_t n = 0;
    for (size_t i = 0; i < in.len; ++i) {
        unsigned char c = in.data[i];
        if (c == '\r' || c == '\n') continue;
        ++n;
    }
    if (!n) return 1;
    size_t pad = 0;
    if (add_padding && n % 4) {
        pad = 4 - (n % 4);
        if (pad == 3) return 1;
    } else if (n % 4 == 1) return 1;
    size_t cap = ((n + pad) / 4) * 3;
    unsigned char *decoded = malloc(cap ? cap : 1);
    if (!decoded) return -1;
    int val[4];
    size_t got = 0, produced = 0;
    int rc = 0;
    bool in_pad = false, finished_pad = false;
    for (size_t i = 0; i < in.len && !rc; ++i) {
        unsigned char c = in.data[i];
        if (c == '\r' || c == '\n') continue;
        if (reject_after_pad && finished_pad) rc = 1;
        if (c == '=') {
            if (!got) rc = 1;
            else {
                in_pad = true;
                val[got++] = -2;
            }
        } else {
            if (reject_after_pad && in_pad) rc = 1;
            int digit = b64_digit(c, url);
            if (digit < 0) rc = 1;
            else val[got++] = digit;
        }
        if (!rc && got == 4) {
            if (val[0] < 0 || val[1] < 0 || produced + 1 > cap) rc = 1;
            else {
                decoded[produced++] = (unsigned char)((val[0] << 2) | (val[1] >> 4));
                if (val[2] != -2) {
                    if (val[2] < 0 || produced >= cap) rc = 1;
                    else decoded[produced++] = (unsigned char)(((val[1] & 15) << 4) | (val[2] >> 2));
                }
                if (!rc && val[3] != -2) {
                    if (val[2] < 0 || val[3] < 0 || produced >= cap) rc = 1;
                    else decoded[produced++] = (unsigned char)(((val[2] & 3) << 6) | val[3]);
                }
            }
            if (in_pad) finished_pad = true;
            in_pad = false;
            got = 0;
        }
    }
    if (!rc && add_padding && pad) {
        int fill = pad == 2 ? -2 : 0;
        int extra[4] = {0, 0, fill, -2};
        size_t have = got;
        /* Remainder 2 needs two pads; remainder 3 needs one. Both are valid. */
        if (have + pad != 4) rc = 1;
        for (size_t i = 0; i < have; ++i) extra[i] = val[i];
        if (!rc && (extra[0] < 0 || extra[1] < 0)) rc = 1;
        if (!rc) decoded[produced++] = (unsigned char)((extra[0] << 2) | (extra[1] >> 4));
        if (!rc && pad == 1) {
            if (extra[2] < 0) rc = 1;
            else decoded[produced++] = (unsigned char)(((extra[1] & 15) << 4) | (extra[2] >> 2));
        }
        got = 0;
    }
    if (rc || got) {
        free(decoded);
        return rc ? rc : 1;
    }
    *out = (br_bytes){decoded, produced};
    return 0;
}

static int jwt_segment(br_slice in, br_bytes *out)
{
    return b64_decode(in, true, true, false, out);
}

typedef enum { DATE_ABSENT, DATE_ZERO, DATE_PRESENT, DATE_INVALID } date_kind;

typedef struct {
    br_slice alg, iss, kid;
    bool iss_set, kid_set;
    date_kind iat, exp, nbf;
    double iat_value, exp_value, nbf_value;
    br_json *header, *claims;
} jwt_claims;

static void claims_clear(jwt_claims *claims)
{
    json_object_put(claims->header);
    json_object_put(claims->claims);
    free((void *)claims->alg.data);
    free((void *)claims->iss.data);
    free((void *)claims->kid.data);
    *claims = (jwt_claims){0};
}

static int own_slice(br_slice in, br_slice *out)
{
    *out = (br_slice){0};
    if (!in.len) return 0;
    unsigned char *copy = malloc(in.len);
    if (!copy) return -1;
    memcpy(copy, in.data, in.len);
    *out = (br_slice){copy, in.len};
    return 0;
}

static int number_value(br_json *value, br_slice encoded, double *number)
{
    if (!value || (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double)))
        return 1;
    if (!encoded.data || !encoded.len || encoded.len == SIZE_MAX) return 1;
    char *token = malloc(encoded.len + 1);
    if (!token) return -1;
    memcpy(token, encoded.data, encoded.len);
    token[encoded.len] = '\0';
    int parsed = json_parse_double(token, number);
    free(token);
    if (parsed != 0 || !isfinite(*number)) return 1;
    return 0;
}

/* A present null is invalid. A missing key is absent. Allocation failure is fatal. */
static int classify_date(bool seen, br_json *value, br_slice encoded, double *number, date_kind *kind)
{
    if (!seen) {
        *kind = DATE_ABSENT;
        return 0;
    }
    if (!value || json_object_is_type(value, json_type_null)) {
        *kind = DATE_INVALID;
        return 0;
    }
    int rc = number_value(value, encoded, number);
    if (rc < 0) return -1;
    if (rc) {
        *kind = DATE_INVALID;
        return 0;
    }
    /* Presence is decided before truncation. Exact 0, including -0, is absent. */
    *kind = *number == 0.0 ? DATE_ZERO : DATE_PRESENT;
    return 0;
}

typedef struct {
    const char *name;
    br_json *value;
    br_slice encoded;
    bool seen;
} claim_field;

static int take_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    claim_field *fields = user;
    for (size_t i = 0; fields[i].name; ++i) {
        if (name.len == strlen(fields[i].name) && !memcmp(name.data, fields[i].name, name.len)) {
            /* The visitor frees its temporary after the callback. Last duplicate wins. */
            json_object_put(fields[i].value);
            fields[i].value = json_object_get(value);
            fields[i].encoded = encoded;
            fields[i].seen = true;
            if (value && !fields[i].value) return -1;
        }
    }
    return 0;
}

static void release_fields(claim_field *fields)
{
    for (size_t i = 0; fields[i].name; ++i) {
        json_object_put(fields[i].value);
        fields[i].value = NULL;
    }
}

static int read_claims(br_slice header_json, br_slice claims_json, jwt_claims *out, bool *drop, char **error)
{
    *out = (jwt_claims){0};
    *drop = false;
    char *cause = NULL;
    int rc = br_json_check_float64_numbers(header_json, &cause);
    if (rc) {
        free(cause);
        if (rc < 0) return fail(error, "cannot decode JWT header");
        *drop = true;
        return 0;
    }
    rc = br_json_check_float64_numbers(claims_json, &cause);
    if (rc) {
        free(cause);
        if (rc < 0) return fail(error, "cannot decode JWT claims");
        *drop = true;
        return 0;
    }
    size_t end = 0;
    rc = br_json_document(header_json, &out->header, &cause);
    if (rc) {
        free(cause);
        claims_clear(out);
        if (rc < 0) return fail(error, "cannot decode JWT header");
        *drop = true;
        return 0;
    }
    if (!json_object_is_type(out->header, json_type_object)) {
        claims_clear(out);
        *drop = true;
        return 0;
    }
    rc = br_json_document(claims_json, &out->claims, &cause);
    if (rc) {
        free(cause);
        claims_clear(out);
        if (rc < 0) return fail(error, "cannot decode JWT claims");
        *drop = true;
        return 0;
    }
    /* JSON null unmarshals to a nil map. Every other non-object is a decode failure. */
    if (out->claims && !json_object_is_type(out->claims, json_type_object) &&
        !json_object_is_type(out->claims, json_type_null)) {
        claims_clear(out);
        *drop = true;
        return 0;
    }
    claim_field header_fields[] = {{"alg", NULL, {0}, false}, {"kid", NULL, {0}, false}, {NULL, NULL, {0}, false}};
    if (br_json_each_member(header_json, take_member, header_fields) != 0) {
        release_fields(header_fields);
        claims_clear(out);
        return fail(error, "cannot decode JWT header");
    }
    if (!header_fields[0].seen || !header_fields[0].value ||
        !json_object_is_type(header_fields[0].value, json_type_string) ||
        own_slice(br_json_text(header_fields[0].value), &out->alg) != 0) {
        bool fatal = header_fields[0].seen && header_fields[0].value &&
                     json_object_is_type(header_fields[0].value, json_type_string);
        release_fields(header_fields);
        claims_clear(out);
        if (fatal) return fail(error, "cannot decode JWT header");
        *drop = true;
        return 0;
    }
    if (!known_alg(out->alg)) {
        release_fields(header_fields);
        claims_clear(out);
        *drop = true;
        return 0;
    }
    if (header_fields[1].seen && header_fields[1].value &&
        json_object_is_type(header_fields[1].value, json_type_string)) {
        if (own_slice(br_json_text(header_fields[1].value), &out->kid) != 0) {
            release_fields(header_fields);
            claims_clear(out);
            return fail(error, "cannot decode JWT header");
        }
        out->kid_set = true;
    }
    release_fields(header_fields);
    if (out->claims && json_object_is_type(out->claims, json_type_object)) {
        claim_field claim_fields[] = {
            {"iss", NULL, {0}, false}, {"iat", NULL, {0}, false},
            {"exp", NULL, {0}, false}, {"nbf", NULL, {0}, false}, {NULL, NULL, {0}, false},
        };
        if (br_json_each_member(claims_json, take_member, claim_fields) != 0) {
            release_fields(claim_fields);
            claims_clear(out);
            return fail(error, "cannot decode JWT claims");
        }
        if (claim_fields[0].seen && claim_fields[0].value &&
            json_object_is_type(claim_fields[0].value, json_type_string)) {
            if (own_slice(br_json_text(claim_fields[0].value), &out->iss) != 0) {
                release_fields(claim_fields);
                claims_clear(out);
                return fail(error, "cannot decode JWT claims");
            }
            out->iss_set = true;
        }
        if (classify_date(claim_fields[1].seen, claim_fields[1].value, claim_fields[1].encoded,
                          &out->iat_value, &out->iat) != 0 ||
            classify_date(claim_fields[2].seen, claim_fields[2].value, claim_fields[2].encoded,
                          &out->exp_value, &out->exp) != 0 ||
            classify_date(claim_fields[3].seen, claim_fields[3].value, claim_fields[3].encoded,
                          &out->nbf_value, &out->nbf) != 0) {
            release_fields(claim_fields);
            claims_clear(out);
            return fail(error, "cannot decode JWT claims");
        }
        release_fields(claim_fields);
    }
    (void)end;
    return 0;
}

/* Go truncates toward zero, normalizes time.Unix, then drops the fraction. */
static int truncated_unix(double value, int64_t *seconds)
{
    double whole = 0;
    double frac = modf(value, &whole);
    /* 2^63 is not an int64. Selected Go's out-of-range conversion is the indefinite minimum. */
    const double int64_limit = 9223372036854775808.0;
    if (!(whole < int64_limit) || whole < (double)INT64_MIN) {
        *seconds = INT64_MIN;
        return 0;
    }
    int64_t sec = (int64_t)whole;
    double nanos = frac * 1000000000.0;
    if (!(nanos < int64_limit) || nanos < (double)INT64_MIN) {
        *seconds = INT64_MIN;
        return 0;
    }
    int64_t nsec = (int64_t)nanos;
    if (nsec < 0 || nsec >= 1000000000) {
        int64_t carry = nsec / 1000000000;
        if ((carry > 0 && sec > INT64_MAX - carry) || (carry < 0 && sec < INT64_MIN - carry)) {
            *seconds = INT64_MIN;
            return 0;
        }
        sec += carry;
        nsec -= carry * 1000000000;
        if (nsec < 0) {
            nsec += 1000000000;
            if (sec == INT64_MIN) {
                *seconds = INT64_MIN;
                return 0;
            }
            --sec;
        }
    }
    *seconds = sec;
    return 0;
}

static int format_date(date_kind kind, double value, char **out, char **error)
{
    *out = NULL;
    if (kind != DATE_PRESENT) return 0;
    int64_t seconds = 0;
    if (truncated_unix(value, &seconds) != 0) return fail(error, "cannot format JWT time");
    br_bytes formatted = {0};
    if (br_go_time_unix_string(seconds, &formatted, error) != 0) return -1;
    *out = (char *)formatted.data;
    return 0;
}

static int put_text(br_json *object, const char *key, const char *value, size_t len)
{
    br_json *text = json_object_new_string_len(value ? value : "", (int)len);
    if (!text) return -1;
    if (json_object_object_add(object, key, text) != 0) {
        json_object_put(text);
        return -1;
    }
    return 0;
}

static bool https_url(br_slice url)
{
    if (url.len < 8 || !url.data) return false;
    const unsigned char *p = url.data;
    return (p[0] == 'h' || p[0] == 'H') && (p[1] == 't' || p[1] == 'T') &&
           (p[2] == 't' || p[2] == 'T') && (p[3] == 'p' || p[3] == 'P') &&
           (p[4] == 's' || p[4] == 'S') && p[5] == ':' && p[6] == '/' && p[7] == '/';
}

/* Nonzero helper status is fatal even when the error pointer is NULL. */
static int url_status(br_slice url, br_go_url_parts *parts, bool *ok, char **error)
{
    br_go_url_error rejection = {0};
    if (br_go_url_parse(url, parts, &rejection, error) != 0) return -1;
    *ok = rejection.kind == BR_GO_URL_OK;
    return 0;
}

/* Host-only https URLs concatenate. Every other form is unsupported before a send. */
static int discovery_url(br_slice issuer, char **url, char **cause, char **error)
{
    *url = NULL;
    *cause = NULL;
    const char path[] = "/.well-known/openid-configuration";
    size_t scheme = 0;
    for (; scheme + 2 < issuer.len; ++scheme)
        if (issuer.data[scheme] == ':' && issuer.data[scheme + 1] == '/' && issuer.data[scheme + 2] == '/')
            break;
    if (scheme + 2 >= issuer.len) {
        *cause = strdup("unsupported: JWT issuer URL JoinPath");
        return *cause ? 0 : fail(error, "cannot format JWT verification error");
    }
    size_t auth = scheme + 3;
    size_t path_at = auth;
    while (path_at < issuer.len && issuer.data[path_at] != '/' && issuer.data[path_at] != '?' &&
           issuer.data[path_at] != '#')
        ++path_at;
    size_t path_end = path_at;
    while (path_end < issuer.len && issuer.data[path_end] != '?' && issuer.data[path_end] != '#') ++path_end;
    size_t path_len = path_end - path_at;
    bool closed = path_len == 0 || (path_len == 1 && issuer.data[path_at] == '/');
    if (!closed) {
        *cause = strdup("unsupported: JWT issuer URL JoinPath");
        return *cause ? 0 : fail(error, "cannot format JWT verification error");
    }
    size_t auth_len = path_at - auth;
    size_t tail = issuer.len - path_end;
    if (auth_len > SIZE_MAX - (sizeof(path) + tail + 8)) return fail(error, "cannot format JWT discovery URL");
    char *built = malloc(8 + auth_len + sizeof(path) - 1 + tail + 1);
    if (!built) return fail(error, "cannot format JWT discovery URL");
    memcpy(built, "https://", 8);
    if (auth_len) memcpy(built + 8, issuer.data + auth, auth_len);
    memcpy(built + 8 + auth_len, path, sizeof(path) - 1);
    if (tail) memcpy(built + 8 + auth_len + sizeof(path) - 1, issuer.data + path_end, tail);
    built[8 + auth_len + sizeof(path) - 1 + tail] = '\0';
    *url = built;
    return 0;
}

/* 0 quoted, 1 unadmitted, -1 allocation failure. Unadmitted bytes are not fake Go escapes. */
static int go_quote(br_slice text, char **out)
{
    size_t cap = text.len * 2 + 3;
    char *buf = malloc(cap ? cap : 1);
    if (!buf) return -1;
    size_t n = 0;
    buf[n++] = '"';
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i];
        if (c == '\\' || c == '"') {
            if (n + 2 >= cap) {
                free(buf);
                return -1;
            }
            buf[n++] = '\\';
            buf[n++] = (char)c;
        } else if (c >= 0x20 && c < 0x7f) {
            buf[n++] = (char)c;
        } else {
            free(buf);
            return 1;
        }
    }
    buf[n++] = '"';
    buf[n] = '\0';
    *out = buf;
    return 0;
}

static int now_wall(int64_t *sec, int64_t *nsec, char **error)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return fail(error, "unsupported: JWT clock");
    *sec = (int64_t)ts.tv_sec;
    *nsec = (int64_t)ts.tv_nsec;
    return 0;
}

static bool before_second(int64_t now_sec, int64_t target)
{
    (void)0;
    return now_sec < target;
}

static bool date_allows(date_kind kind, double value, int64_t now_sec, int delta, char **error)
{
    if (kind == DATE_INVALID) return false;
    if (kind != DATE_PRESENT) return true;
    int64_t seconds = 0;
    if (truncated_unix(value, &seconds) != 0) {
        fail(error, "cannot format JWT time");
        return false;
    }
    int64_t target = seconds;
    if (delta > 0) {
        if (seconds > INT64_MAX - delta) return true;
        target = seconds + delta;
        return before_second(now_sec, target);
    }
    if (seconds < INT64_MIN - delta) return true;
    target = seconds + delta;
    return !before_second(now_sec, target);
}

static int claims_valid(const jwt_claims *claims, char **error)
{
    int64_t sec = 0, nsec = 0;
    if (now_wall(&sec, &nsec, error) != 0) return -1;
    (void)nsec;
    if (!date_allows(claims->exp, claims->exp_value, sec, JWT_LEEWAY, error) ||
        !date_allows(claims->nbf, claims->nbf_value, sec, -JWT_LEEWAY, error) ||
        !date_allows(claims->iat, claims->iat_value, sec, -JWT_LEEWAY, error)) {
        if (error && *error) return -1;
        return 1;
    }
    return 0;
}

typedef enum { KEY_NONE, KEY_RSA, KEY_EC, KEY_OKP } key_use;

typedef struct {
    br_bytes kid, crv, n, e, x, y;
    bool has_kid, crv_set, n_set, e_set, x_set, y_set, q_set, p_set;
    bool private_form, skip_verify;
    key_use use;
} jwt_jwk;

static void jwk_clear(jwt_jwk *key)
{
    free(key->kid.data);
    free(key->crv.data);
    free(key->n.data);
    free(key->e.data);
    free(key->x.data);
    free(key->y.data);
    *key = (jwt_jwk){0};
}

static bool bytes_eq(br_bytes value, const char *literal)
{
    size_t n = strlen(literal);
    return value.len == n && (!n || !memcmp(value.data, literal, n));
}

static bool name_is(br_slice name, const char *literal)
{
    size_t n = strlen(literal);
    return name.len == n && name.data && !memcmp(name.data, literal, n);
}

static int copy_bytes(br_slice in, br_bytes *out)
{
    *out = (br_bytes){0};
    if (!in.len) return 0;
    unsigned char *copy = malloc(in.len);
    if (!copy) return -1;
    memcpy(copy, in.data, in.len);
    *out = (br_bytes){copy, in.len};
    return 0;
}

static int decode_b64_field(br_slice text, br_bytes *out)
{
    bool url = true;
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i];
        if (c == '+' || c == '/') url = false;
    }
    bool padded = text.len && text.data[text.len - 1] == '=';
    return b64_decode(text, url, !padded, true, out);
}

typedef struct {
    jwt_jwk *key;
    char *cause;
    int rc;
    int phase;
    bool kty_set, kid_set;
} key_parse;

static int key_type_name(key_use use, const char **name)
{
    if (use == KEY_RSA) {
        *name = "*jwk.rsaPublicKey";
        return 0;
    }
    if (use == KEY_EC) {
        *name = "*jwk.ecdsaPublicKey";
        return 0;
    }
    if (use == KEY_OKP) {
        *name = "*jwk.okpPublicKey";
        return 0;
    }
    return 1;
}

static int key_ordinary(key_parse *parse, const char *message)
{
    char *owned = jwt_strdup(message);
    if (!owned) return -1;
    parse->cause = owned;
    parse->rc = 1;
    return 1;
}

static int store_bytes(br_slice text, br_bytes *dest, bool *set)
{
    /* A present empty string is an empty byte slice, not a decode failure. */
    if (!text.len) {
        free(dest->data);
        *dest = (br_bytes){0};
        *set = true;
        return 0;
    }
    br_bytes decoded = {0};
    int rc = decode_b64_field(text, &decoded);
    if (rc) return rc;
    free(dest->data);
    *dest = decoded;
    *set = true;
    return 0;
}

static bool known_jwk_algorithm(br_slice alg)
{
    static const char *const names[] = {
        "ES256", "ES256K", "ES384", "ES512", "EdDSA", "HS256", "HS384", "HS512",
        "none", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512",
        "A128GCMKW", "A128KW", "A192GCMKW", "A192KW", "A256GCMKW", "A256KW", "dir",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
        "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
        "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512",
        "A128CBC-HS256", "A128GCM", "A192CBC-HS384", "A192GCM", "A256CBC-HS512", "A256GCM",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (name_is(alg, names[i])) return true;
    return false;
}

static bool known_key_operation(br_slice op)
{
    return name_is(op, "sign") || name_is(op, "verify") || name_is(op, "encrypt") ||
           name_is(op, "decrypt") || name_is(op, "wrapKey") || name_is(op, "unwrapKey") ||
           name_is(op, "deriveKey") || name_is(op, "deriveBits");
}

static const char *key_decode_type(const jwt_jwk *key)
{
    if (key->skip_verify) return "*jwk.symmetricKey";
    if (key->private_form) {
        if (key->use == KEY_EC) return "*jwk.ecdsaPrivateKey";
        if (key->use == KEY_OKP) return "*jwk.okpPrivateKey";
        return "*jwk.rsaPrivateKey";
    }
    if (key->use == KEY_EC) return "*jwk.ecdsaPublicKey";
    if (key->use == KEY_OKP) return "*jwk.okpPublicKey";
    return "*jwk.rsaPublicKey";
}

static int key_decode_error(key_parse *parse, const char *field, const char *detail)
{
    char *message = NULL;
    if (format_owned(&message, "failed to unmarshal JSON into key (%s): failed to decode value for key %s: %s",
                     key_decode_type(parse->key), field, detail) < 0)
        return -1;
    free(parse->cause);
    parse->cause = message;
    parse->rc = 1;
    return 0;
}

static int decode_key_alg(key_parse *parse, br_json *value)
{
    if (!value) return key_decode_error(parse, "alg", "json: cannot unmarshal null into Go value of type string") < 0 ? -1 : 0;
    if (!json_object_is_type(value, json_type_string)) {
        char *inner = NULL;
        if (br_json_type_cause(value, NULL, "string", &inner) != 0) return -1;
        int rc = key_decode_error(parse, "alg", inner);
        free(inner);
        return rc < 0 ? -1 : 0;
    }
    br_slice alg = br_json_text(value);
    if (known_jwk_algorithm(alg)) return 0;
    char *quoted = NULL;
    int quoted_rc = go_quote(alg, &quoted);
    if (quoted_rc < 0) return -1;
    if (quoted_rc > 0) return -1;
    char *detail = NULL;
    if (format_owned(&detail, "invalid key value: %s: invalid key algorithm", quoted) < 0) {
        free(quoted);
        return -1;
    }
    free(quoted);
    int rc = key_decode_error(parse, "alg", detail);
    free(detail);
    return rc < 0 ? -1 : 0;
}

static int reject_key_operation(key_parse *parse, br_slice text)
{
    if (known_key_operation(text)) return 0;
    char *rendered = NULL;
    if (owned_copy(text, &rendered) != 0) return -1;
    char *detail = NULL;
    if (format_owned(&detail, "invalid keyoperation %s", rendered) < 0) {
        free(rendered);
        return -1;
    }
    free(rendered);
    int rc = key_decode_error(parse, "key_ops", detail);
    free(detail);
    return rc < 0 ? -1 : 0;
}

static int decode_key_ops(key_parse *parse, br_json *value)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (json_object_is_type(value, json_type_string))
        return reject_key_operation(parse, br_json_text(value));
    if (!json_object_is_type(value, json_type_array)) {
        char *inner = NULL;
        if (br_json_type_cause(value, NULL, "[]string", &inner) != 0) return -1;
        int rc = key_decode_error(parse, "key_ops", inner);
        free(inner);
        return rc < 0 ? -1 : 0;
    }
    for (size_t i = 0; i < json_object_array_length(value); ++i) {
        br_json *element = json_object_array_get_idx(value, i);
        if (!element) return key_decode_error(parse, "key_ops", "json: cannot unmarshal null into Go value of type string") < 0 ? -1 : 0;
        if (!json_object_is_type(element, json_type_string)) {
            char *inner = NULL;
            if (br_json_type_cause(element, NULL, "string", &inner) != 0) return -1;
            int rc = key_decode_error(parse, "key_ops", inner);
            free(inner);
            return rc < 0 ? -1 : 0;
        }
        int rejected = reject_key_operation(parse, br_json_text(element));
        if (rejected || parse->rc) return rejected;
    }
    return 0;
}

static int key_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    key_parse *parse = user;
    if (parse->rc) return 0;
    jwt_jwk *key = parse->key;
    if (name_is(name, "kty")) {
        if (!value || !json_object_is_type(value, json_type_string)) {
            return key_ordinary(parse, "invalid key type from JSON ()") < 0 ? -1 : 0;
        }
        br_slice kty = br_json_text(value);
        key_use use = KEY_NONE;
        bool skip = false;
        if (kty.len == 3 && !memcmp(kty.data, "RSA", 3)) use = KEY_RSA;
        else if (kty.len == 2 && !memcmp(kty.data, "EC", 2)) use = KEY_EC;
        else if (kty.len == 3 && !memcmp(kty.data, "OKP", 3)) use = KEY_OKP;
        else if (kty.len == 3 && !memcmp(kty.data, "oct", 3)) skip = true;
        else {
            char *rendered = NULL;
            if (owned_copy(kty, &rendered) != 0) return -1;
            char *message = NULL;
            if (format_owned(&message, "invalid key type from JSON (%s)", rendered ? rendered : "") < 0) {
                free(rendered);
                return -1;
            }
            free(rendered);
            parse->cause = message;
            parse->rc = 1;
            return 0;
        }
        if (parse->kty_set && (use != key->use || skip != key->skip_verify)) {
            return key_ordinary(parse, "invalid kty value for RSAPublicKey") < 0 ? -1 : 0;
        }
        key->use = use;
        key->skip_verify = skip;
        parse->kty_set = true;
        return 0;
    }
    if (name_is(name, "d")) {
        if (!parse->phase) key->private_form = true;
        return 0;
    }
    if (name_is(name, "q")) {
        if (!parse->phase) key->q_set = value && !json_object_is_type(value, json_type_null);
        return 0;
    }
    if (name_is(name, "p")) {
        if (!parse->phase) key->p_set = value && !json_object_is_type(value, json_type_null);
        return 0;
    }
    if (!parse->phase && name_is(name, "kty")) return 0;
    if (parse->phase && name_is(name, "kid")) return 0;
    if (name_is(name, "kid")) {
        if (parse->kid_set) return 0;
        parse->kid_set = true;
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string)) {
            return key_ordinary(parse, "failed to decode value for key kid: error reading next value: json: cannot unmarshal number into Go value of type string") < 0 ? -1 : 0;
        }
        if (copy_bytes(br_json_text(value), &key->kid) != 0) return -1;
        key->has_kid = true;
        return 0;
    }
    if (!parse->phase || !parse->kty_set) return 0;
    /* alg and key_ops are decoded for every key. They are not a selection filter. */
    if (name_is(name, "alg")) return decode_key_alg(parse, value);
    if (name_is(name, "key_ops")) return decode_key_ops(parse, value);
    if (key->skip_verify) return 0;
    const char *field = NULL;
    br_bytes *dest = NULL;
    bool *set = NULL;
    if (key->use == KEY_RSA && name_is(name, "n")) {
        field = "n";
        dest = &key->n;
        set = &key->n_set;
    } else if (key->use == KEY_RSA && name_is(name, "e")) {
        field = "e";
        dest = &key->e;
        set = &key->e_set;
    } else if ((key->use == KEY_EC || key->use == KEY_OKP) && name_is(name, "crv")) {
        if (!value || json_object_is_type(value, json_type_null)) return 0;
        if (!json_object_is_type(value, json_type_string)) {
            return key_ordinary(parse, "failed to decode value for key crv: json: cannot unmarshal number into Go value of type string") < 0 ? -1 : 0;
        }
        br_slice text = br_json_text(value);
        if (copy_bytes(text, &key->crv) != 0) return -1;
        key->crv_set = true;
        return 0;
    } else if (key->use == KEY_EC && name_is(name, "x")) {
        field = "x";
        dest = &key->x;
        set = &key->x_set;
    } else if (key->use == KEY_EC && name_is(name, "y")) {
        field = "y";
        dest = &key->y;
        set = &key->y_set;
    } else if (key->use == KEY_OKP && name_is(name, "x")) {
        field = "x";
        dest = &key->x;
        set = &key->x_set;
    }
    if (!field) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        char *message = NULL;
        if (format_owned(&message, "failed to decode value for key %s: error reading next value: json: cannot unmarshal number into Go value of type string", field) < 0)
            return -1;
        parse->cause = message;
        parse->rc = 1;
        return 0;
    }
    int decoded = store_bytes(br_json_text(value), dest, set);
    if (decoded < 0) return -1;
    if (decoded) {
        char *message = NULL;
        if (format_owned(&message, "failed to decode value for key %s: expected base64 encoded []byte", field) < 0)
            return -1;
        parse->cause = message;
        parse->rc = 1;
    }
    return 0;
}

static int require_field(key_parse *parse, bool present, const char *field, const char *type_name)
{
    if (parse->rc || present) return 0;
    char *inner = NULL;
    if (format_owned(&inner, "failed to unmarshal JSON into key (%s): required field %s is missing", type_name, field) < 0)
        return -1;
    char *message = NULL;
    if (format_owned(&message, "failed to unmarshal JSON into key (%s): %s", type_name, inner) < 0) {
        free(inner);
        return -1;
    }
    free(inner);
    parse->cause = message;
    parse->rc = 1;
    return 0;
}

static int parse_one_key(br_slice object, jwt_jwk *key, char **cause)
{
    *key = (jwt_jwk){0};
    key_parse parse = {.key = key};
    int visit = br_json_each_member(object, key_member, &parse);
    if (!visit && !parse.rc) {
        parse.phase = 1;
        visit = br_json_each_member(object, key_member, &parse);
    }
    if (visit) {
        free(parse.cause);
        jwk_clear(key);
        return fail(cause, "cannot parse JWT key");
    }
    if (!parse.rc && !parse.kty_set)
        if (key_ordinary(&parse, "jwk.Parse: failed to get \"kty\" hint") < 0) parse.rc = -1;
    if (!parse.rc && key->private_form) {
        const char *type_name = key->use == KEY_EC ? "*jwk.ecdsaPrivateKey" :
                                key->use == KEY_OKP ? "*jwk.okpPrivateKey" : "*jwk.rsaPrivateKey";
        if (key->use == KEY_RSA) {
            if (require_field(&parse, key->n_set, "n", type_name) < 0) parse.rc = -1;
            if (require_field(&parse, key->e_set, "e", type_name) < 0) parse.rc = -1;
        } else if (key->use == KEY_EC) {
            if (require_field(&parse, key->crv_set, "crv", type_name) < 0) parse.rc = -1;
            if (require_field(&parse, key->x_set, "x", type_name) < 0) parse.rc = -1;
            if (require_field(&parse, key->y_set, "y", type_name) < 0) parse.rc = -1;
        } else if (key->use == KEY_OKP) {
            if (require_field(&parse, key->crv_set, "crv", type_name) < 0) parse.rc = -1;
            if (require_field(&parse, key->x_set, "x", type_name) < 0) parse.rc = -1;
        }
    } else if (!parse.rc && !key->skip_verify) {
        const char *type_name = NULL;
        if (key_type_name(key->use, &type_name) == 0) {
            if (key->use == KEY_RSA) {
                if (require_field(&parse, key->n_set, "n", type_name) < 0) parse.rc = -1;
                if (require_field(&parse, key->e_set, "e", type_name) < 0) parse.rc = -1;
            } else if (key->use == KEY_EC) {
                if (require_field(&parse, key->crv_set, "crv", type_name) < 0) parse.rc = -1;
                if (require_field(&parse, key->x_set, "x", type_name) < 0) parse.rc = -1;
                if (require_field(&parse, key->y_set, "y", type_name) < 0) parse.rc = -1;
            } else if (key->use == KEY_OKP) {
                if (require_field(&parse, key->crv_set, "crv", type_name) < 0) parse.rc = -1;
                if (require_field(&parse, key->x_set, "x", type_name) < 0) parse.rc = -1;
            }
        }
    }
    if (parse.rc < 0) {
        free(parse.cause);
        jwk_clear(key);
        return fail(cause, "cannot parse JWT key");
    }
    if (parse.rc) {
        *cause = parse.cause;
        jwk_clear(key);
        return 1;
    }
    return 0;
}

typedef struct {
    jwt_jwk *keys;
    size_t n, cap;
    char *cause;
    int rc;
    size_t index;
} jwks_list;

static int jwks_append(jwks_list *list, br_slice encoded, size_t index)
{
    if (list->rc) return 0;
    if (list->n == list->cap) {
        if (list->cap > SIZE_MAX / 2) { list->rc = -1; return -1; }
        size_t cap = list->cap ? list->cap * 2 : 4;
        if (cap > SIZE_MAX / sizeof(*list->keys)) { list->rc = -1; return -1; }
        jwt_jwk *grown = realloc(list->keys, cap * sizeof(*grown));
        if (!grown) {
            list->rc = -1;
            return -1;
        }
        list->keys = grown;
        list->cap = cap;
    }
    char *key_cause = NULL;
    int key_rc = parse_one_key(encoded, &list->keys[list->n], &key_cause);
    if (key_rc < 0) {
        free(key_cause);
        list->rc = -1;
        return -1;
    }
    if (key_rc) {
        char *message = NULL;
        const char *inner = key_cause ? key_cause : "jwk.Parse: no parser was able to parse the key";
        if (format_owned(&message, "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to decode key #%zu in \"keys\": %s", index, inner) < 0) {
            free(key_cause);
            list->rc = -1;
            return -1;
        }
        free(key_cause);
        list->cause = message;
        list->rc = 1;
        return 0;
    }
    free(key_cause);
    ++list->n;
    return 0;
}

static int jwks_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    jwks_list *list = user;
    if (list->rc) return 0;
    if (!value || !json_object_is_type(value, json_type_object)) {
        char *message = NULL;
        if (format_owned(&message, "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to decode key #%zu in \"keys\": jwk.Parse: failed to probe data", index) < 0) {
            list->rc = -1;
            return -1;
        }
        list->cause = message;
        list->rc = 1;
        return 0;
    }
    (void)value;
    return jwks_append(list, encoded, index);
}

static int jwks_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    jwks_list *list = user;
    if (list->rc) return 0;
    if (!name_is(name, "keys")) return 0;
    list->index = 1;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_array)) {
        char *type_cause = NULL;
        if (br_json_type_cause(value, NULL, "[]json.RawMessage", &type_cause) != 0) {
            list->rc = -1;
            return -1;
        }
        char *message = NULL;
        if (format_owned(&message, "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to decode \"keys\": %s", type_cause) < 0) {
            free(type_cause);
            list->rc = -1;
            return -1;
        }
        free(type_cause);
        list->cause = message;
        list->rc = 1;
        return 0;
    }
    int visit = br_json_each_element(encoded, jwks_element, list);
    if (visit) {
        list->rc = -1;
        return -1;
    }
    return 0;
}

static int parse_jwks(br_slice body, jwt_jwk **keys, size_t *nkeys, char **cause)
{
    *keys = NULL;
    *nkeys = 0;
    *cause = NULL;
    if (!body.len || (body.len == 1 && (body.data[0] == ' ' || body.data[0] == '\n' || body.data[0] == '\t' || body.data[0] == '\r'))) {
        *cause = strdup("failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: error reading token: EOF");
        return *cause ? 1 : -1;
    }
    bool blank = true;
    for (size_t i = 0; i < body.len; ++i)
        if (body.data[i] != ' ' && body.data[i] != '\n' && body.data[i] != '\t' && body.data[i] != '\r') {
            blank = false;
            break;
        }
    if (blank) {
        *cause = strdup("failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: error reading token: EOF");
        return *cause ? 1 : -1;
    }
    br_json *root = NULL;
    size_t end = 0;
    char *decode = NULL;
    int rc = br_json_first_document(body, NULL, &root, &end, &decode);
    if (rc < 0) {
        free(decode);
        return fail(cause, "cannot parse JWKS");
    }
    if (rc) {
        char *message = NULL;
        const char *inner = decode ? decode : "unexpected end of JSON input";
        if (format_owned(&message, "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: error reading token: %s", inner) < 0) {
            free(decode);
            return fail(cause, "cannot parse JWKS");
        }
        free(decode);
        *cause = message;
        return 1;
    }
    if (!json_object_is_type(root, json_type_object)) {
        const char *inner = json_object_is_type(root, json_type_array) ?
            "expected '{' but got '['" : "error reading token: EOF";
        json_object_put(root);
        if (format_owned(cause, "failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: %s", inner) < 0)
            return fail(cause, "cannot parse JWKS");
        return 1;
    }
    json_object_put(root);
    jwks_list list = {0};
    br_slice document = {body.data, end};
    int visit = br_json_each_member(document, jwks_member, &list);
    if (visit || list.rc < 0) {
        for (size_t i = 0; i < list.n; ++i) jwk_clear(&list.keys[i]);
        free(list.keys);
        free(list.cause);
        return fail(cause, "cannot parse JWKS");
    }
    if (list.rc) {
        for (size_t i = 0; i < list.n; ++i) jwk_clear(&list.keys[i]);
        free(list.keys);
        *cause = list.cause;
        return 1;
    }
    if (!list.index) {
        jwt_jwk key = {0};
        char *key_cause = NULL;
        int key_rc = parse_one_key(document, &key, &key_cause);
        free(key_cause);
        if (key_rc < 0) {
            jwk_clear(&key);
            return fail(cause, "cannot parse JWKS");
        }
        if (key_rc) {
            jwk_clear(&key);
            *cause = jwt_strdup("failed to parse JWKS: jwk.ParseReader: failed to parse reader: jwk.Parse: failed to unmarshal JWK set: failed to parse sole key in key set");
            return *cause ? 1 : -1;
        }
        jwt_jwk *one = calloc(1, sizeof(*one));
        if (!one) {
            jwk_clear(&key);
            return fail(cause, "cannot parse JWKS");
        }
        one[0] = key;
        *keys = one;
        *nkeys = 1;
        return 0;
    }
    *keys = list.keys;
    *nkeys = list.n;
    return 0;
}

static const jwt_jwk *lookup_kid(const jwt_jwk *keys, size_t nkeys, br_slice kid)
{
    for (size_t i = 0; i < nkeys; ++i)
        if (keys[i].has_kid && slice_eq((br_slice){keys[i].kid.data, keys[i].kid.len}, kid)) return &keys[i];
    return NULL;
}

static int export_cause(char **cause, const char *inner)
{
    char *message = NULL;
    if (format_owned(&message, "failed to export matching key: jwk.Export: failed to export jwk.Key to raw format: %s", inner) < 0)
        return fail(cause, "cannot export JWT key");
    *cause = message;
    return 1;
}

static int pad_coord(br_slice in, size_t size, unsigned char *out)
{
    if (in.len > size) return 1;
    memset(out, 0, size);
    if (in.len) memcpy(out + size - in.len, in.data, in.len);
    return 0;
}

static int build_rsa(const jwt_jwk *key, EVP_PKEY **out, char **cause)
{
    *out = NULL;
    if (!key->n_set) return export_cause(cause, "missing \"n\" value");
    if (!key->e_set) return export_cause(cause, "missing \"e\" value");
    if (!key->n.len || !key->e.len || key->n.len > INT_MAX)
        return fail(cause, "unsupported: JWT RSA key material");
    /* Source SetBytes ignores leading zeros, then truncates to a 64-bit Go int. */
    size_t e_at = 0;
    while (e_at < key->e.len && !key->e.data[e_at]) ++e_at;
    size_t e_sig = key->e.len - e_at;
    if (e_sig > 8 || (e_sig == 8 && (key->e.data[e_at] & 0x80)))
        return fail(cause, "unsupported: JWT RSA key material");
    static const unsigned char zero_exponent = 0;
    const unsigned char *e_bytes = e_sig ? key->e.data + e_at : &zero_exponent;
    int e_len = e_sig ? (int)e_sig : 1;
    BIGNUM *n = BN_bin2bn(key->n.data, (int)key->n.len, NULL);
    BIGNUM *e = BN_bin2bn(e_bytes, e_len, NULL);
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int rc = -1;
    if (!n || !e || !builder) goto done;
    if (OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
        OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_E, e) != 1) goto done;
    params = OSSL_PARAM_BLD_to_param(builder);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, out, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_free(*out);
        *out = NULL;
        goto done;
    }
    rc = 0;
done:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    BN_free(n);
    BN_free(e);
    if (rc && !*cause) return fail(cause, "cannot export JWT key");
    return rc;
}

static int build_ec(const jwt_jwk *key, const char *group, size_t coord, EVP_PKEY **out, char **cause)
{
    *out = NULL;
    if (!key->crv_set) return export_cause(cause, "missing \"crv\" field");
    if (!bytes_eq(key->crv, group)) return fail(cause, "unsupported: JWT elliptic curve");
    if (!key->x_set) return export_cause(cause, "missing \"x\" field");
    if (!key->y_set) return export_cause(cause, "missing \"y\" field");
    if (!key->x.len || !key->y.len) return fail(cause, "unsupported: JWT elliptic curve");
    unsigned char *point = malloc(1 + coord * 2);
    if (!point) return fail(cause, "cannot export JWT key");
    point[0] = 0x04;
    if (pad_coord((br_slice){key->x.data, key->x.len}, coord, point + 1) ||
        pad_coord((br_slice){key->y.data, key->y.len}, coord, point + 1 + coord)) {
        free(point);
        return fail(cause, "unsupported: JWT JWK key material");
    }
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int rc = -1;
    if (!builder) goto done;
    if (OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, group, 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, point, 1 + coord * 2) != 1)
        goto done;
    params = OSSL_PARAM_BLD_to_param(builder);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, out, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_free(*out);
        *out = NULL;
        goto done;
    }
    rc = 0;
done:
    free(point);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    if (rc && !*cause) return fail(cause, "cannot export JWT key");
    return rc;
}

static int build_okp(const jwt_jwk *key, EVP_PKEY **out, char **cause)
{
    *out = NULL;
    if (!key->crv_set) return export_cause(cause, "missing \"crv\" field");
    if (!bytes_eq(key->crv, "Ed25519")) return fail(cause, "unsupported: JWT elliptic curve");
    if (!key->x_set) return export_cause(cause, "missing \"x\" field");
    /* Export accepts any length. Verify rejects a non-32-byte key without an error. */
    if (key->x.len != 32) return 2;
    *out = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key->x.data, key->x.len);
    if (!*out) return fail(cause, "cannot export JWT key");
    return 0;
}

static int ecdsa_der(br_slice raw, size_t coord, unsigned char **der, size_t *der_len)
{
    *der = NULL;
    *der_len = 0;
    if (raw.len != coord * 2) return 1;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(raw.data, (int)coord, NULL);
    BIGNUM *s = BN_bin2bn(raw.data + coord, (int)coord, NULL);
    if (!sig || !r || !s || ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return -1;
    }
    int len = i2d_ECDSA_SIG(sig, der);
    ECDSA_SIG_free(sig);
    if (len <= 0) return -1;
    *der_len = (size_t)len;
    return 0;
}

static int verify_signature(br_slice alg, br_slice signing, br_slice signature, const jwt_jwk *key,
                            bool *valid, bool *omit_setter, char **cause)
{
    *valid = false;
    if (key->private_form) {
        if (key->use == KEY_RSA && !key->q_set) return export_cause(cause, "missing \"q\" value");
        if (key->use == KEY_RSA && !key->p_set) return export_cause(cause, "missing \"p\" value");
        if (key->use == KEY_EC && !key->crv_set) return export_cause(cause, "missing \"crv\" field");
        if (key->use == KEY_OKP && !key->x_set) return export_cause(cause, "missing \"x\" field");
        return fail(cause, "unsupported: JWT private JWK export");
    }
    if (key->skip_verify) return 0;
    const EVP_MD *hash = NULL;
    bool pss = false, ecdsa = false, ed = false;
    size_t sig_width = 0;
    if (alg.len == 5 && !memcmp(alg.data, "RS256", 5)) hash = EVP_sha256();
    else if (alg.len == 5 && !memcmp(alg.data, "RS384", 5)) hash = EVP_sha384();
    else if (alg.len == 5 && !memcmp(alg.data, "RS512", 5)) hash = EVP_sha512();
    else if (alg.len == 5 && !memcmp(alg.data, "PS256", 5)) { hash = EVP_sha256(); pss = true; }
    else if (alg.len == 5 && !memcmp(alg.data, "PS384", 5)) { hash = EVP_sha384(); pss = true; }
    else if (alg.len == 5 && !memcmp(alg.data, "PS512", 5)) { hash = EVP_sha512(); pss = true; }
    else if (alg.len == 5 && !memcmp(alg.data, "ES256", 5)) { hash = EVP_sha256(); ecdsa = true; sig_width = 32; }
    else if (alg.len == 5 && !memcmp(alg.data, "ES384", 5)) { hash = EVP_sha384(); ecdsa = true; sig_width = 48; }
    else if (alg.len == 5 && !memcmp(alg.data, "ES512", 5)) { hash = EVP_sha512(); ecdsa = true; sig_width = 66; }
    else if (alg.len == 5 && !memcmp(alg.data, "EdDSA", 5)) ed = true;
    else return 0;
    /* The verification curve comes from the JWK, not from ES256/ES384/ES512. */
    size_t key_coord = 0;
    const char *group = NULL;
    if (key->use == KEY_EC) {
        if (bytes_eq(key->crv, "P-256")) { key_coord = 32; group = "P-256"; }
        else if (bytes_eq(key->crv, "P-384")) { key_coord = 48; group = "P-384"; }
        else if (bytes_eq(key->crv, "P-521")) { key_coord = 66; group = "P-521"; }
        else return fail(cause, "unsupported: JWT elliptic curve");
    }
    EVP_PKEY *pkey = NULL;
    int built = 0;
    if (key->use == KEY_RSA) built = build_rsa(key, &pkey, cause);
    else if (key->use == KEY_EC) built = build_ec(key, group, key_coord, &pkey, cause);
    else if (key->use == KEY_OKP) built = build_okp(key, &pkey, cause);
    else return 0;
    /* Method.Verify rejects this exported length. That miss does not call the setter. */
    if (built == 2) {
        if (omit_setter) *omit_setter = true;
        return 0;
    }
    if (built) return built < 0 ? -1 : 1;
    if ((key->use == KEY_RSA && (ecdsa || ed)) || (key->use == KEY_EC && !ecdsa) ||
        (key->use == KEY_OKP && !ed)) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    if (ecdsa && signature.len != sig_width * 2) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    unsigned char *der = NULL;
    size_t der_len = 0;
    br_slice sig = signature;
    if (ecdsa) {
        int der_rc = ecdsa_der(signature, sig_width, &der, &der_len);
        if (der_rc) {
            EVP_PKEY_free(pkey);
            return der_rc < 0 ? fail(cause, "cannot verify JWT signature") : 0;
        }
        sig = (br_slice){der, der_len};
    }
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;
    if (!md) {
        free(der);
        EVP_PKEY_free(pkey);
        return fail(cause, "cannot verify JWT signature");
    }
    if (ed) ok = EVP_DigestVerifyInit(md, NULL, NULL, NULL, pkey);
    else ok = EVP_DigestVerifyInit(md, pss ? &pctx : NULL, hash, NULL, pkey);
    if (ok != 1) {
        EVP_MD_CTX_free(md);
        EVP_PKEY_free(pkey);
        free(der);
        return fail(cause, "cannot verify JWT signature");
    }
    if (pss && (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
                EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_AUTO) != 1 ||
                EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, hash) != 1)) {
        EVP_MD_CTX_free(md);
        EVP_PKEY_free(pkey);
        free(der);
        return fail(cause, "cannot verify JWT signature");
    }
    ok = EVP_DigestVerify(md, sig.data, sig.len, signing.data, signing.len);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    free(der);
    if (ok == 1) {
        *valid = true;
        return 0;
    }
    if (ok == 0) return 0;
    return fail(cause, "cannot verify JWT signature");
}

static int copy_limited(br_slice body, br_bytes *out, char **error)
{
    if (body.len && !body.data) return fail(error, "cannot copy JWT response");
    size_t n = body.len > JWT_BODY_LIMIT ? JWT_BODY_LIMIT : body.len;
    unsigned char *copy = malloc(n ? n : 1);
    if (!copy) return fail(error, "cannot copy JWT response");
    if (n) memcpy(copy, body.data, n);
    *out = (br_bytes){copy, n};
    return 0;
}

static int http_get(const br_scan_ctx *ctx, const char *url, br_bytes *body, int *status,
                    bool *failed, char **transport, char **read_error, char **error)
{
    *body = (br_bytes){0};
    *status = 0;
    *failed = false;
    *transport = NULL;
    *read_error = NULL;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_DETECTOR_PUBLIC,
        .timeout_ms = 0, .detector_type = 1039,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    if (send_rc) {
        *failed = true;
        *transport = send_error;
        br_http_release(ctx, &response);
        return 0;
    }
    *status = response.status;
    if (response.status != 200) {
        free(send_error);
        br_http_release(ctx, &response);
        return 0;
    }
    int rc = copy_limited(response.body, body, error);
    char *read_copy = NULL;
    if (response.body_error) {
        read_copy = jwt_strdup(response.body_error);
        if (!read_copy) {
            free(body->data);
            *body = (br_bytes){0};
            br_http_release(ctx, &response);
            free(send_error);
            return fail(error, "cannot copy JWT response");
        }
    }
    br_http_release(ctx, &response);
    free(send_error);
    if (rc) {
        free(read_copy);
        return -1;
    }
    if (read_copy && !body->len) {
        free(body->data);
        *body = (br_bytes){0};
    }
    *read_error = read_copy;
    return 0;
}

static int wrap_request(const char *outer, const char *inner, char **cause)
{
    char *message = NULL;
    if (!inner) return 0;
    if (format_owned(&message, "%s: failed to perform request: %s", outer, inner) < 0)
        return -1;
    *cause = message;
    return 1;
}

typedef struct {
    br_bytes uri;
    bool set;
    char *type_error;
} discovery_state;

static int discovery_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    discovery_state *state = user;
    if (!br_json_field_name(name, "jwks_uri")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        if (!state->type_error &&
            br_json_type_cause(value, ".jwks_uri", "string", &state->type_error) != 0)
            return -1;
        return 0;
    }
    br_slice text = br_json_text(value);
    unsigned char *copy = malloc(text.len ? text.len : 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    free(state->uri.data);
    state->uri = (br_bytes){copy, text.len};
    state->set = true;
    return 0;
}

static int decode_discovery(br_slice body, const char *read_error, br_bytes *jwks, char **cause)
{
    *jwks = (br_bytes){0};
    br_json *root = NULL;
    size_t end = 0;
    char *decode = NULL;
    int rc = br_json_first_document(body, read_error, &root, &end, &decode);
    if (rc < 0) {
        free(decode);
        return fail(cause, "cannot decode JWT discovery document");
    }
    if (rc) {
        char *message = NULL;
        const char *inner = decode ? decode : "unexpected end of JSON input";
        if (format_owned(&message, "failed to decode OIDC discovery document: %s", inner) < 0) {
            free(decode);
            return fail(cause, "cannot decode JWT discovery document");
        }
        free(decode);
        *cause = message;
        return 1;
    }
    if (!root || json_object_is_type(root, json_type_null)) {
        json_object_put(root);
        return 0;
    }
    if (!root || !json_object_is_type(root, json_type_object)) {
        char *type_cause = NULL;
        if (br_json_type_cause(root, NULL, "struct { JWKSUri string \"json:\\\"jwks_uri\\\"\" }", &type_cause) != 0) {
            json_object_put(root);
            return fail(cause, "cannot decode JWT discovery document");
        }
        char *message = NULL;
        if (format_owned(&message, "failed to decode OIDC discovery document: %s", type_cause) < 0) {
            free(type_cause);
            json_object_put(root);
            return fail(cause, "cannot decode JWT discovery document");
        }
        free(type_cause);
        json_object_put(root);
        *cause = message;
        return 1;
    }
    discovery_state fields = {0};
    br_slice object = {body.data, end};
    int visit = br_json_each_member(object, discovery_member, &fields);
    json_object_put(root);
    if (visit) {
        free(fields.uri.data);
        free(fields.type_error);
        return fail(cause, "cannot decode JWT discovery document");
    }
    if (fields.type_error) {
        char *message = NULL;
        if (format_owned(&message, "failed to decode OIDC discovery document: %s", fields.type_error) < 0) {
            free(fields.type_error);
            free(fields.uri.data);
            return fail(cause, "cannot decode JWT discovery document");
        }
        free(fields.type_error);
        free(fields.uri.data);
        *cause = message;
        return 1;
    }
    *jwks = fields.uri;
    return 0;
}

static int parse_request_error(br_slice uri, const br_go_url_error *rejection, char **cause)
{
    char *quoted_url = NULL, *inner = NULL;
    int quoted = go_quote(uri, &quoted_url);
    if (quoted < 0) return -1;
    if (quoted > 0) return 2;
    const char *fixed = NULL;
    switch (rejection->kind) {
    case BR_GO_URL_CONTROL: fixed = "net/url: invalid control character in URL"; break;
    case BR_GO_URL_SCHEME: fixed = "missing protocol scheme"; break;
    case BR_GO_URL_COLON: fixed = "first path segment in URL cannot contain colon"; break;
    case BR_GO_URL_BAD_USER: fixed = "net/url: invalid userinfo"; break;
    case BR_GO_URL_BRACKET: fixed = "missing ']' in host"; break;
    case BR_GO_URL_IP_LITERAL: fixed = "invalid IP-literal"; break;
    case BR_GO_URL_IP_DIAGNOSTIC: fixed = "unsupported: JWT URL parse error text"; break;
    default: break;
    }
    if (fixed) inner = strdup(fixed);
    else if (rejection->kind == BR_GO_URL_ESCAPE || rejection->kind == BR_GO_URL_HOST_CHAR ||
             rejection->kind == BR_GO_URL_PORT) {
        char *quoted = NULL;
        int detail_quote = go_quote(rejection->detail, &quoted);
        if (detail_quote < 0) {
            free(quoted_url);
            return -1;
        }
        if (detail_quote > 0) {
            free(quoted_url);
            return 2;
        }
        const char *fmt = rejection->kind == BR_GO_URL_ESCAPE ? "invalid URL escape %s" :
                          rejection->kind == BR_GO_URL_HOST_CHAR ? "invalid character %s in host name" :
                          "invalid port %s after host";
        if (format_owned(&inner, fmt, quoted) < 0) {
            free(quoted);
            free(quoted_url);
            return -1;
        }
        free(quoted);
    } else inner = strdup("unsupported: JWT URL parse error text");
    if (!inner) {
        free(quoted_url);
        return -1;
    }
    int rc = format_owned(cause, "parse %s: %s", quoted_url, inner);
    free(quoted_url);
    free(inner);
    return rc;
}

static int invalid_jwks_url(br_slice uri, char **cause)
{
    *cause = NULL;
    if (!uri.len) {
        *cause = jwt_strdup("invalid JWKS URL: parse \"\": empty url");
        return *cause ? 1 : -1;
    }
    for (size_t i = 0; i < uri.len; ++i) {
        if (!uri.data[i]) {
            *cause = jwt_strdup("unsupported: JWT URL quote");
            return *cause ? 1 : -1;
        }
    }
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    char *fatal = NULL;
    int rc = br_go_url_parse(uri, &parts, &rejection, &fatal);
    br_go_url_clear(&parts);
    if (rc) {
        *cause = fatal;
        return -1;
    }
    free(fatal);
    if (rejection.kind != BR_GO_URL_OK) {
        char *parsed = NULL;
        int parsed_rc = parse_request_error(uri, &rejection, &parsed);
        if (parsed_rc < 0) return fail(cause, "cannot format JWT verification error");
        if (parsed_rc == 2) {
            *cause = jwt_strdup("unsupported: JWT URL quote");
            return *cause ? 1 : -1;
        }
        if (format_owned(cause, "invalid JWKS URL: %s", parsed) < 0) {
            free(parsed);
            return fail(cause, "cannot format JWT verification error");
        }
        free(parsed);
        return 1;
    }
    if (!https_url(uri)) {
        *cause = strdup("invalid JWKS URL: only https scheme is supported");
        return *cause ? 1 : -1;
    }
    return 0;
}

static int verify_jwt(const br_scan_ctx *ctx, br_slice match, br_slice signing, br_slice signature,
                      const jwt_claims *claims, bool *verified, char **cause, bool *reached_error,
                      bool *omit_setter, char **error)
{
    *verified = false;
    *cause = NULL;
    if (reached_error) *reached_error = false;
    int valid = claims_valid(claims, error);
    if (valid < 0) return -1;
    if (valid > 0) return 0;
    if (!claims->iss_set || !claims->iss.len) return 0;
    if (!https_url(claims->iss)) return 0;
    br_go_url_parts issuer_parts = {0};
    bool issuer_ok = false;
    if (url_status(claims->iss, &issuer_parts, &issuer_ok, error) != 0) {
        br_go_url_clear(&issuer_parts);
        return -1;
    }
    if (!issuer_ok) {
        br_go_url_clear(&issuer_parts);
        return 0;
    }
    char *url = NULL;
    int join = discovery_url(claims->iss, &url, cause, error);
    if (join || *cause) {
        br_go_url_clear(&issuer_parts);
        return join;
    }
    if (!claims->kid_set) {
        free(url);
        br_go_url_clear(&issuer_parts);
        return 0;
    }
    if (!ctx) {
        free(url);
        br_go_url_clear(&issuer_parts);
        *cause = strdup("failed to perform OIDC discovery: failed to create request: net/http: nil Context");
        return *cause ? 0 : fail(error, "cannot format JWT verification error");
    }
    br_bytes body = {0};
    int status = 0;
    bool failed = false;
    char *transport = NULL, *read_error = NULL;
    if (http_get(ctx, url, &body, &status, &failed, &transport, &read_error, error) != 0) {
        free(url);
        br_go_url_clear(&issuer_parts);
        return -1;
    }
    free(url);
    if (failed) {
        if (reached_error) *reached_error = true;
        int wrapped = transport ? wrap_request("failed to perform OIDC discovery", transport, cause) : 0;
        free(transport);
        br_go_url_clear(&issuer_parts);
        return wrapped < 0 ? fail(error, "cannot format JWT verification error") : 0;
    }
    if (status != 200) {
        free(body.data);
        br_go_url_clear(&issuer_parts);
        return fail(error, "unsupported: JWT HTTP status text");
    }
    br_bytes jwks_uri = {0};
    /* A completed first document still decodes when a later read would fail. */
    int decoded = decode_discovery((br_slice){body.data, body.len}, read_error, &jwks_uri, cause);
    free(read_error);
    free(body.data);
    if (decoded) {
        free(jwks_uri.data);
        br_go_url_clear(&issuer_parts);
        return decoded < 0 ? -1 : 0;
    }
    br_slice jwks_slice = {jwks_uri.data, jwks_uri.len};
    char *url_cause = NULL;
    int url_rc = invalid_jwks_url(jwks_slice, &url_cause);
    if (url_rc) {
        free(jwks_uri.data);
        br_go_url_clear(&issuer_parts);
        if (url_rc < 0) {
            *error = url_cause;
            return -1;
        }
        *cause = url_cause;
        return 0;
    }
    br_go_url_parts jwks_parts = {0};
    bool jwks_ok = false;
    if (url_status(jwks_slice, &jwks_parts, &jwks_ok, error) != 0) {
        free(jwks_uri.data);
        br_go_url_clear(&issuer_parts);
        br_go_url_clear(&jwks_parts);
        return -1;
    }
    if (!jwks_ok) {
        free(jwks_uri.data);
        br_go_url_clear(&issuer_parts);
        br_go_url_clear(&jwks_parts);
        return 0;
    }
    if (!slice_eq(issuer_parts.host, jwks_parts.host)) {
        char *quoted = NULL;
        int quoted_rc = go_quote(jwks_slice, &quoted);
        if (quoted_rc < 0) {
            free(jwks_uri.data);
            br_go_url_clear(&issuer_parts);
            br_go_url_clear(&jwks_parts);
            return fail(error, "cannot format JWT verification error");
        }
        if (quoted_rc > 0) {
            free(jwks_uri.data);
            br_go_url_clear(&issuer_parts);
            br_go_url_clear(&jwks_parts);
            *cause = jwt_strdup("unsupported: JWT URL quote");
            return *cause ? 0 : fail(error, "cannot format JWT verification error");
        }
        char *message = NULL;
        if (format_owned(&message, "JWKS host does not match issuer host: %s", quoted) < 0) {
            free(quoted);
            free(jwks_uri.data);
            br_go_url_clear(&issuer_parts);
            br_go_url_clear(&jwks_parts);
            return fail(error, "cannot format JWT verification error");
        }
        free(quoted);
        free(jwks_uri.data);
        br_go_url_clear(&issuer_parts);
        br_go_url_clear(&jwks_parts);
        *cause = message;
        return 0;
    }
    br_go_url_clear(&jwks_parts);
    br_go_url_clear(&issuer_parts);
    char *request_url = malloc(jwks_uri.len + 1);
    if (!request_url) {
        free(jwks_uri.data);
        return fail(error, "cannot format JWT discovery URL");
    }
    if (jwks_uri.len) memcpy(request_url, jwks_uri.data, jwks_uri.len);
    request_url[jwks_uri.len] = '\0';
    free(jwks_uri.data);
    body = (br_bytes){0};
    transport = NULL;
    read_error = NULL;
    status = 0;
    failed = false;
    if (http_get(ctx, request_url, &body, &status, &failed, &transport, &read_error, error) != 0) {
        free(request_url);
        return -1;
    }
    if (failed) {
        if (reached_error) *reached_error = true;
        int wrapped = transport ? wrap_request("failed to fetch JWKS", transport, cause) : 0;
        free(transport);
        free(request_url);
        return wrapped < 0 ? fail(error, "cannot format JWT verification error") : 0;
    }
    if (status != 200) {
        free(body.data);
        free(request_url);
        return fail(error, "unsupported: JWT HTTP status text");
    }
    if (read_error) {
        char *message = NULL;
        int wrapped = format_owned(&message, "failed to parse JWKS: jwk.ParseReader: failed to read from io.Reader: %s", read_error);
        free(read_error);
        free(body.data);
        free(request_url);
        if (wrapped < 0) return fail(error, "cannot format JWT verification error");
        *cause = message;
        return 0;
    }
    jwt_jwk *keys = NULL;
    size_t nkeys = 0;
    int parsed = parse_jwks((br_slice){body.data, body.len}, &keys, &nkeys, cause);
    free(body.data);
    free(request_url);
    if (parsed) {
        for (size_t i = 0; i < nkeys; ++i) jwk_clear(&keys[i]);
        free(keys);
        return parsed < 0 ? -1 : 0;
    }
    const jwt_jwk *match_key = lookup_kid(keys, nkeys, claims->kid);
    if (!match_key) {
        for (size_t i = 0; i < nkeys; ++i) jwk_clear(&keys[i]);
        free(keys);
        return 0;
    }
    bool signature_ok = false;
    int checked = verify_signature(claims->alg, signing, signature, match_key, &signature_ok, omit_setter, cause);
    for (size_t i = 0; i < nkeys; ++i) jwk_clear(&keys[i]);
    free(keys);
    if (checked) return checked < 0 ? -1 : 0;
    *verified = signature_ok;
    (void)match;
    return 0;
}

typedef struct {
    br_slice *items;
    size_t len, cap;
} seen_matches;

static bool already_seen(seen_matches *seen, br_slice match)
{
    for (size_t i = 0; i < seen->len; ++i)
        if (slice_eq(seen->items[i], match)) return true;
    return false;
}

static int remember(seen_matches *seen, br_slice match)
{
    if (seen->len == seen->cap) {
        if (seen->cap > SIZE_MAX / 2) return -1;
        size_t cap = seen->cap ? seen->cap * 2 : 8;
        if (cap > SIZE_MAX / sizeof(*seen->items)) return -1;
        br_slice *items = realloc(seen->items, cap * sizeof(*items));
        if (!items) return -1;
        seen->items = items;
        seen->cap = cap;
    }
    seen->items[seen->len++] = match;
    return 0;
}

static bool drop_unverified(const br_scan_ctx *ctx)
{
    if (!ctx || !ctx->options) return false;
    br_json *value = NULL;
    if (!json_object_object_get_ex(ctx->options, "DropUnverifiedJWTResults", &value) || !value)
        return false;
    if (!json_object_is_type(value, json_type_boolean)) return false;
    return json_object_get_boolean(value);
}

static void rollback(br_results *out, size_t before)
{
    if (!out) return;
    while (out->len > before) {
        br_result_clear(&out->items[out->len - 1]);
        --out->len;
    }
}

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    bool verify, drop_flag;
    seen_matches seen;
    char **error;
} jwt_scan;

static int split_token(br_slice match, br_slice parts[3])
{
    size_t first = SIZE_MAX, second = SIZE_MAX;
    for (size_t i = 0; i < match.len; ++i) {
        if (match.data[i] != '.') continue;
        if (first == SIZE_MAX) first = i;
        else if (second == SIZE_MAX) second = i;
        else return 1;
    }
    if (first == SIZE_MAX || second == SIZE_MAX) return 1;
    parts[0] = (br_slice){match.data, first};
    parts[1] = (br_slice){match.data + first + 1, second - first - 1};
    parts[2] = (br_slice){match.data + second + 1, match.len - second - 1};
    return 0;
}

static int on_match(void *user, const br_span *groups, size_t ngroups)
{
    jwt_scan *scan = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end < groups[1].begin ||
        groups[1].end > scan->input.len)
        return fail(scan->error, "invalid JWT match");
    br_slice match = {scan->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    if (already_seen(&scan->seen, match)) return 0;
    if (remember(&scan->seen, match) != 0) return fail(scan->error, "cannot remember JWT match");
    br_slice parts[3];
    if (split_token(match, parts) != 0) return 0;
    br_bytes header = {0}, claims = {0}, signature = {0};
    int decoded = jwt_segment(parts[0], &header);
    if (decoded < 0) return fail(scan->error, "cannot decode JWT header");
    if (decoded) return 0;
    decoded = jwt_segment(parts[1], &claims);
    if (decoded < 0) {
        free(header.data);
        return fail(scan->error, "cannot decode JWT claims");
    }
    if (decoded) {
        free(header.data);
        return 0;
    }
    jwt_claims parsed = {0};
    bool drop = false;
    if (read_claims((br_slice){header.data, header.len}, (br_slice){claims.data, claims.len}, &parsed, &drop, scan->error) != 0) {
        free(header.data);
        free(claims.data);
        return -1;
    }
    free(header.data);
    free(claims.data);
    if (drop || hmac_alg(parsed.alg)) {
        claims_clear(&parsed);
        return 0;
    }
    decoded = jwt_segment(parts[2], &signature);
    if (decoded < 0) {
        claims_clear(&parsed);
        return fail(scan->error, "cannot decode JWT signature");
    }
    if (decoded) {
        claims_clear(&parsed);
        return 0;
    }
    char *iat = NULL, *exp = NULL;
    if (format_date(parsed.iat, parsed.iat_value, &iat, scan->error) != 0 ||
        format_date(parsed.exp, parsed.exp_value, &exp, scan->error) != 0) {
        free(iat);
        free(signature.data);
        claims_clear(&parsed);
        return -1;
    }
    br_result result = {0};
    if (br_finding_key_bytes(&result, 1039, match, "key") != 0) {
        free(iat);
        free(exp);
        free(signature.data);
        claims_clear(&parsed);
        return fail(scan->error, "cannot create JWT finding");
    }
    result.extra_data = json_object_new_object();
    char *alg = NULL;
    if (!result.extra_data || owned_copy(parsed.alg, &alg) != 0 ||
        put_text(result.extra_data, "alg", alg, alg ? strlen(alg) : 0) != 0 ||
        put_text(result.extra_data, "iss", parsed.iss_set ? (const char *)parsed.iss.data : "", parsed.iss_set ? parsed.iss.len : 0) != 0 ||
        put_text(result.extra_data, "iat", iat, iat ? strlen(iat) : 0) != 0 ||
        put_text(result.extra_data, "exp", exp, exp ? strlen(exp) : 0) != 0) {
        free(alg);
        free(iat);
        free(exp);
        free(signature.data);
        claims_clear(&parsed);
        br_result_clear(&result);
        return fail(scan->error, "cannot create JWT finding");
    }
    free(alg);
    free(iat);
    free(exp);
    char *cause = NULL;
    if (scan->verify) {
        size_t signing_len = parts[0].len + 1 + parts[1].len;
        unsigned char *signing_bytes = malloc(signing_len ? signing_len : 1);
        if (!signing_bytes) {
            free(signature.data);
            claims_clear(&parsed);
            br_result_clear(&result);
            return fail(scan->error, "cannot verify JWT");
        }
        if (parts[0].len) memcpy(signing_bytes, parts[0].data, parts[0].len);
        signing_bytes[parts[0].len] = '.';
        if (parts[1].len) memcpy(signing_bytes + parts[0].len + 1, parts[1].data, parts[1].len);
        bool verified = false, reached_error = false, omit_setter = false;
        int rc = verify_jwt(scan->ctx, match, (br_slice){signing_bytes, signing_len},
                            (br_slice){signature.data, signature.len}, &parsed, &verified, &cause,
                            &reached_error, &omit_setter, scan->error);
        free(signing_bytes);
        free(signature.data);
        claims_clear(&parsed);
        if (rc) {
            if (rc < 0 && cause && scan->error && !*scan->error) *scan->error = cause;
            else free(cause);
            br_result_clear(&result);
            return -1;
        }
        result.verified = verified;
        /* Claim rejection and a reached error, including a NULL diagnostic, still call the setter. */
        if (!omit_setter && br_result_set_verification_error(&result, cause, &match, 1) != 0) {
            free(cause);
            br_result_clear(&result);
            return fail(scan->error, "cannot set JWT verification error");
        }
        free(cause);
        if (scan->drop_flag && !result.verified && !result.verification_error && !reached_error) {
            br_result_clear(&result);
            return 0;
        }
    } else {
        free(signature.data);
        claims_clear(&parsed);
    }
    if (br_results_push(scan->out, &result) != 0) {
        br_result_clear(&result);
        return fail(scan->error, "cannot append JWT finding");
    }
    return 0;
}

static int scan_jwt(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !out || (input.len && !input.data)) return fail(error, "invalid or uninitialized JWT scan");
    const jwt_state *state = detector->state;
    if (!state || !state->regex) return fail(error, "invalid or uninitialized JWT scan");
    size_t before = out->len;
    jwt_scan scan = {
        .detector = detector, .ctx = ctx, .input = input, .out = out, .verify = verify,
        .drop_flag = drop_unverified(ctx), .error = error,
    };
    char *regex_error = NULL;
    int rc = br_regex_each(state->regex, input, on_match, &scan, &regex_error);
    free(scan.seen.items);
    if (error && *error) {
        free(regex_error);
        rollback(out, before);
        return -1;
    }
    if (rc) {
        if (error) *error = regex_error;
        else free(regex_error);
        rollback(out, before);
        return -1;
    }
    free(regex_error);
    return 0;
}

static jwt_state state;
static const br_detector detector = {
    .type = 1039, .version = 0, .name = "JWT", .description = description,
    .keywords = keywords, .nkeywords = 3, .custom_name = "",
    .max_secret_size = 4096, .start_offset = -1, .max_credential_span = -1,
    .state = &state, .scan = scan_jwt,
};

int br_jwt_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!out) return fail(error, "invalid JWT detector output");
    if (!state.regex && br_regex_compile(jwt_pattern, &state.regex, error) != 0) return -1;
    *out = &detector;
    return 0;
}
