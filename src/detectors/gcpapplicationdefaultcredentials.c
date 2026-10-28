/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2 gcpapplicationdefaultcredentials.go and the
 * reachable golang.org/x/oauth2 v0.34.0 ADC refresh/IAM flow. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "gcp_json.h"
#include "gcp_oauth.h"
#include "../utf8.h"
#include "../go_unicode.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ADC_SLICE(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})

static int adc_fail(char **fatal, const char *message)
{
    if (fatal && !*fatal) *fatal = strdup(message);
    return -1;
}

static bool adc_equal(br_slice a, const char *b)
{
    size_t n = strlen(b); return a.len == n && (!n || !memcmp(a.data, b, n));
}

/* A selected JSON callback value is ephemeral. Retain its OWN reference, not
 * merely the containing decoded document. Null preserves the old ref/repair. */
typedef struct { br_json *root; br_slice text; br_bytes owned; } adc_string;

static void adc_string_clear(adc_string *s)
{
    json_object_put(s->root); free(s->owned.data); *s = (adc_string){0};
}

static int adc_string_set(adc_string *s, br_json *value, char **fatal)
{
    if (!value) return 0;
    if (!json_object_is_type(value, json_type_string)) return 1;
    br_slice text = {0}; br_bytes repair = {0};
    if (br_gcp_json_text(value, &text, &repair, fatal) != 0) { free(repair.data); return -1; }
    br_json *root = json_object_get(value);
    adc_string_clear(s); *s = (adc_string){root, text, repair}; return 0;
}

static const char *const adc_names[] = {"client_id", "client_secret", "refresh_token", "type"};
typedef struct { adc_string fields[4]; bool bad; char **fatal; } adc_credentials;

static int adc_credential_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded; adc_credentials *credentials = user;
    for (size_t i = 0; i < 4; ++i) if (br_json_field_name(name, adc_names[i])) {
        int rc = adc_string_set(&credentials->fields[i], value, credentials->fatal);
        if (rc < 0) return -1;
        if (rc > 0) credentials->bad = true; /* Sticky known string type error. */
        break;
    }
    return 0;
}

static int adc_credentials_decode(br_slice input, adc_credentials *credentials, char **fatal)
{
    br_json *root = NULL; char *cause = NULL;
    int rc = br_json_document(input, &root, &cause); free(cause);
    if (rc < 0) { json_object_put(root); return adc_fail(fatal, "cannot decode GCP ADC credential JSON"); }
    if (rc > 0) { json_object_put(root); return 1; }
    if (root && !json_object_is_type(root, json_type_object)) { json_object_put(root); return 1; }
    credentials->fatal = fatal;
    if (root) rc = br_json_each_member(input, adc_credential_member, credentials);
    json_object_put(root);
    if (rc != 0) return adc_fail(fatal, "cannot visit GCP ADC credential JSON");
    return credentials->bad ? 1 : 0; /* Unknown huge numbers are syntax-only. */
}

static int adc_cause(br_gcp_oauth_error *out, br_slice prefix, br_slice value, br_slice suffix, char **fatal)
{
    if (suffix.len == SIZE_MAX || prefix.len > SIZE_MAX - value.len || prefix.len + value.len > SIZE_MAX - suffix.len - 1)
        return adc_fail(fatal, "GCP ADC cause is too large");
    size_t n = prefix.len + value.len + suffix.len; unsigned char *data = malloc(n + 1);
    if (!data) return adc_fail(fatal, "cannot allocate GCP ADC cause");
    size_t at = 0;
    if (prefix.len) { memcpy(data, prefix.data, prefix.len); at += prefix.len; }
    if (value.len) { memcpy(data + at, value.data, value.len); at += value.len; }
    if (suffix.len) memcpy(data + at, suffix.data, suffix.len);
    data[n] = 0; out->text = (br_bytes){data, n}; return 0;
}

static int adc_literal(br_gcp_oauth_error *out, const char *message, char **fatal)
{
    return adc_cause(out, (br_slice){(const unsigned char *)message, strlen(message)}, (br_slice){0}, (br_slice){0}, fatal);
}

static int adc_quoted_cause(br_gcp_oauth_error *out, const char *prefix, br_slice text, const char *suffix, char **fatal)
{
    size_t q = 0, a = strlen(prefix), b = strlen(suffix);
    if (br_gcp_oauth_quote(text, NULL, 0, &q, fatal) != 0) return -1;
    if (a > SIZE_MAX - b - 1 || q > SIZE_MAX - a - b - 1) return adc_fail(fatal, "GCP ADC cause is too large");
    unsigned char *data = malloc(a + q + b + 1);
    if (!data) return adc_fail(fatal, "cannot allocate GCP ADC quoted cause");
    memcpy(data, prefix, a);
    if (br_gcp_oauth_quote(text, data + a, q, &q, fatal) != 0) { free(data); return -1; }
    memcpy(data + a + q, suffix, b + 1); out->text = (br_bytes){data, a + q + b}; return 0;
}

/* Only the already-projected four strings reach CredentialsFromJSON. All other
 * SDK credential/discovery branches lack their required fields. */
static int adc_constructor(const adc_credentials *credentials, br_gcp_oauth_error *cause, char **fatal)
{
    br_slice type = credentials->fields[3].text;
    if (adc_equal(type, "authorized_user") || adc_equal(type, "service_account")) return 0;
    const char *message = NULL;
    if (!type.len) message = "missing 'type' field in credentials";
    else if (adc_equal(type, "external_account")) message = "oauth2/google/externalaccount: Audience must be set";
    else if (adc_equal(type, "external_account_authorized_user")) message = "oauth2/google: Token should be created with fields to make it valid (`token` and `expiry`), or fields to allow it to refresh (`refresh_token`, `token_url`, `client_id`, `client_secret`).";
    else if (adc_equal(type, "impersonated_service_account")) message = "missing 'source_credentials' field or 'service_account_impersonation_url' in credentials";
    if (message) { if (adc_literal(cause, message, fatal) != 0) return -1; }
    else if (adc_quoted_cause(cause, "unknown credential type: ", type, "", fatal) != 0) return -1;
    return 1;
}

/* The MIME result is ONLY the decoder choice. Parameters are unused. Rescan
 * earlier successful parameters to detect unequal duplicate FULL lowercase
 * names without building a MIME map or implementing RFC2231 reconstruction. */
static size_t adc_space(br_slice text, size_t at)
{
    while (at < text.len) {
        uint32_t rune; size_t n = br_utf8_rune((br_slice){text.data + at, text.len - at}, &rune);
        if (!n || !(br_go_unicode_properties(rune) & BR_GO_SPACE)) break;
        at += n;
    }
    return at;
}

static bool adc_mime_token(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        (c && strchr("!#$%&'*+-.^_`{|}~", c));
}

static bool adc_mime_special(unsigned char c) { return c && strchr("()<>@,;:\\\"/[]?=", c); }

typedef struct { br_slice name, value; size_t next; bool quoted; } adc_parameter;

static bool adc_parameter_read(br_slice text, size_t at, adc_parameter *parameter)
{
    at = adc_space(text, at);
    if (at == text.len || text.data[at++] != ';') return false;
    at = adc_space(text, at); size_t begin = at;
    while (at < text.len && adc_mime_token(text.data[at])) ++at;
    if (at == begin) return false;
    parameter->name = (br_slice){text.data + begin, at - begin}; at = adc_space(text, at);
    if (at == text.len || text.data[at++] != '=') return false;
    at = adc_space(text, at); begin = at; parameter->quoted = at < text.len && text.data[at] == '"';
    if (parameter->quoted) {
        ++at;
        while (at < text.len && text.data[at] != '"') {
            unsigned char c = text.data[at++];
            if (c == '\r' || c == '\n') return false;
            if (c == '\\' && at < text.len && adc_mime_special(text.data[at])) ++at;
        }
        if (at == text.len) return false;
        ++at;
    } else {
        while (at < text.len && adc_mime_token(text.data[at])) ++at;
        if (at == begin) return false;
    }
    parameter->value = (br_slice){text.data + begin, at - begin}; parameter->next = at; return true;
}

static unsigned char adc_parameter_byte(const adc_parameter *p, size_t *at)
{
    unsigned char c = p->value.data[(*at)++];
    if (p->quoted && c == '\\' && *at < p->value.len - 1 && adc_mime_special(p->value.data[*at])) c = p->value.data[(*at)++];
    return c;
}

static bool adc_parameter_equal(const adc_parameter *a, const adc_parameter *b)
{
    size_t x = a->quoted ? 1 : 0, y = b->quoted ? 1 : 0;
    size_t end_a = a->value.len - (a->quoted ? 1 : 0), end_b = b->value.len - (b->quoted ? 1 : 0);
    while (x < end_a && y < end_b) if (adc_parameter_byte(a, &x) != adc_parameter_byte(b, &y)) return false;
    return x == end_a && y == end_b;
}

static bool adc_ascii_fold_equal(br_slice a, br_slice b)
{
    if (a.len != b.len) return false;
    for (size_t i = 0; i < a.len; ++i) {
        unsigned char x = a.data[i], y = b.data[i];
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return false;
    }
    return true;
}

static bool adc_mime_base(br_slice base, const char *expected)
{
    size_t at = adc_space(base, 0), i = 0;
    while (expected[i]) {
        if (at == base.len) return false;
        uint32_t rune; size_t n = br_utf8_rune((br_slice){base.data + at, base.len - at}, &rune);
        if (!n || br_go_unicode_lower(rune) != (unsigned char)expected[i++]) return false;
        at += n;
    }
    return adc_space(base, at) == base.len;
}

static bool adc_form_response(br_slice content_type)
{
    size_t end = 0; while (end < content_type.len && content_type.data[end] != ';') ++end;
    br_slice base = {content_type.data, end};
    if (!adc_mime_base(base, "application/x-www-form-urlencoded") && !adc_mime_base(base, "text/plain")) return false;
    size_t at = end;
    while (adc_space(content_type, at) < content_type.len) {
        adc_parameter current;
        if (!adc_parameter_read(content_type, at, &current)) break; /* Bad params KEEP base and STOP. */
        size_t previous = end;
        while (previous < at) {
            adc_parameter old;
            if (!adc_parameter_read(content_type, previous, &old)) break;
            if (adc_ascii_fold_equal(old.name, current.name) && !adc_parameter_equal(&old, &current)) return false;
            previous = old.next;
        }
        at = current.next;
    }
    return true;
}

/* strconv base10 ParseInt, including ParseUint's EARLY unsigned overflow before
 * any later bad byte, then the signed range check. Form Atoi ignores its error. */
static int adc_integer(br_slice text, unsigned bits, int64_t *value)
{
    *value = 0; size_t at = 0; bool negative = false;
    if (text.len && (text.data[0] == '+' || text.data[0] == '-')) { negative = text.data[0] == '-'; ++at; }
    if (at == text.len) return 1;
    uint64_t n = 0, max = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
    uint64_t cutoff = UINT64_C(1) << (bits - 1);
    for (; at < text.len; ++at) {
        unsigned char c = text.data[at];
        if (c < '0' || c > '9') return 1;
        unsigned digit = c - '0';
        if (n > (max - digit) / 10) { *value = negative ? (bits == 64 ? INT64_MIN : -(int64_t)cutoff) : (int64_t)(cutoff - 1); return 2; }
        n = n * 10 + digit;
    }
    if ((!negative && n >= cutoff) || (negative && n > cutoff)) {
        *value = negative ? (bits == 64 ? INT64_MIN : -(int64_t)cutoff) : (int64_t)(cutoff - 1); return 2;
    }
    *value = negative ? (n == (UINT64_C(1) << 63) ? INT64_MIN : -(int64_t)n) : (int64_t)n; return 0;
}

static bool adc_json_number(br_slice text)
{
    size_t at = 0;
    if (at < text.len && text.data[at] == '-') ++at;
    if (at == text.len) return false;
    if (text.data[at] == '0') ++at;
    else { size_t begin = at; while (at < text.len && text.data[at] >= '0' && text.data[at] <= '9') ++at; if (at == begin) return false; }
    if (at < text.len && text.data[at] == '.') { size_t begin = ++at; while (at < text.len && text.data[at] >= '0' && text.data[at] <= '9') ++at; if (at == begin) return false; }
    if (at < text.len && (text.data[at] == 'e' || text.data[at] == 'E')) {
        ++at; if (at < text.len && (text.data[at] == '+' || text.data[at] == '-')) ++at;
        size_t begin = at; while (at < text.len && text.data[at] >= '0' && text.data[at] <= '9') ++at; if (at == begin) return false;
    }
    return at == text.len;
}

static const char *const adc_token_names[] = {"access_token", "token_type", "refresh_token", "error", "error_description", "error_uri"};
static const char *const adc_token_fields[] = {"tokenJSON.access_token", "tokenJSON.token_type", "tokenJSON.refresh_token", "tokenJSON.error", "tokenJSON.error_description", "tokenJSON.error_uri"};
typedef struct {
    adc_string fields[6]; int64_t seconds; bool bad, need_cause;
    struct timespec expiry; bool has_expiry;
    char *cause; char **fatal;
} adc_token;

static void adc_token_clear(adc_token *token)
{
    for (size_t i = 0; i < 6; ++i) adc_string_clear(&token->fields[i]);
    free(token->cause); *token = (adc_token){0};
}

static int adc_expiration(adc_token *token, br_json *value, br_slice encoded)
{
    if (!value) return 0;
    br_slice number = encoded; br_bytes repair = {0};
    bool string = json_object_is_type(value, json_type_string);
    int rc = 0;
    if (string) {
        if (br_gcp_json_text(value, &number, &repair, token->fatal) != 0) { free(repair.data); return -1; }
        if (!adc_json_number(number)) {
            if (token->need_cause) {
                br_gcp_oauth_error error = {0};
                rc = adc_quoted_cause(&error, "json: invalid number literal, trying to unmarshal ", encoded, " into Number", token->fatal);
                if (!rc) { free(token->cause); token->cause = (char *)error.text.data; }
            }
            free(repair.data); return rc < 0 ? -1 : 1;
        }
    } else if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double)) {
        if (token->need_cause) { free(token->cause); token->cause = NULL; rc = br_json_type_cause(value, "tokenJSON.expires_in", "json.Number", &token->cause); }
        return rc < 0 ? -1 : 1;
    }
    int64_t n; int conversion = adc_integer(number, 64, &n);
    if (conversion && token->need_cause) {
        br_gcp_oauth_error error = {0};
        rc = adc_quoted_cause(&error, "strconv.ParseInt: parsing ", number, conversion == 2 ? ": value out of range" : ": invalid syntax", token->fatal);
        if (!rc) { free(token->cause); token->cause = (char *)error.text.data; }
    }
    free(repair.data);
    if (rc < 0) return -1;
    if (conversion) return 1;
    if (n > INT32_MAX) n = INT32_MAX;
    else { uint32_t low = (uint32_t)(uint64_t)n; n = low <= INT32_MAX ? (int64_t)low : (int64_t)low - INT64_C(4294967296); }
    token->seconds = n; return 0;
}

static int adc_token_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    adc_token *token = user;
    if (br_json_field_name(name, "expires_in")) return adc_expiration(token, value, encoded); /* Custom errors abort immediately, superseding saved type errors. */
    for (size_t i = 0; i < 6; ++i) if (br_json_field_name(name, adc_token_names[i])) {
        int rc = adc_string_set(&token->fields[i], value, token->fatal);
        if (rc < 0) return -1;
        if (rc > 0) {
            if (!token->bad && token->need_cause && br_json_type_cause(value, adc_token_fields[i], "string", &token->cause) != 0) return -1;
            token->bad = true;
        }
        break;
    }
    return 0;
}

static int adc_json_token(br_slice body, adc_token *token)
{
    br_json *root = NULL; char *cause = NULL; int rc = br_json_document(body, &root, &cause);
    if (rc) {
        json_object_put(root);
        if (rc < 0) { free(cause); return adc_fail(token->fatal, "cannot decode GCP ADC token JSON"); }
        if (token->need_cause) token->cause = cause; else free(cause);
        return 1;
    }
    if (root && !json_object_is_type(root, json_type_object)) {
        if (token->need_cause && br_json_type_cause(root, NULL, "internal.tokenJSON", &token->cause) != 0) rc = -1; else rc = 1;
    } else if (root) rc = br_json_each_member(body, adc_token_member, token);
    json_object_put(root); return rc < 0 ? -1 : rc > 0 || token->bad ? 1 : 0;
}

static int adc_hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool adc_query_valid(br_slice text, br_slice *bad)
{
    for (size_t i = 0; i < text.len; ++i) if (text.data[i] == '%') {
        if (text.len - i < 3 || adc_hex(text.data[i + 1]) < 0 || adc_hex(text.data[i + 2]) < 0) { *bad = (br_slice){text.data + i, text.len - i > 3 ? 3 : text.len - i}; return false; }
        i += 2;
    }
    return true;
}

static unsigned char adc_query_byte(br_slice text, size_t *at)
{
    unsigned char c = text.data[(*at)++];
    if (c == '+') return ' ';
    if (c == '%') { int x = adc_hex(text.data[*at]), y = adc_hex(text.data[*at + 1]); *at += 2; return (unsigned char)(x * 16 + y); }
    return c;
}

static bool adc_query_key(br_slice key, const char *name)
{
    size_t at = 0, i = 0;
    while (at < key.len && name[i]) if (adc_query_byte(key, &at) != (unsigned char)name[i++]) return false;
    return at == key.len && !name[i];
}

static int adc_query_value(br_slice value, adc_string *out, char **fatal)
{
    size_t n = 0, at = 0; while (at < value.len) { (void)adc_query_byte(value, &at); ++n; }
    unsigned char *data = malloc(n + 1);
    if (!data) return adc_fail(fatal, "cannot allocate GCP ADC form response value");
    at = 0; n = 0; while (at < value.len) data[n++] = adc_query_byte(value, &at);
    data[n] = 0; out->owned = (br_bytes){data, n}; out->text = (br_slice){data, n}; return 0;
}

static int adc_form_token(br_slice body, adc_token *token)
{
    size_t parameters = 1; for (size_t i = 0; i < body.len; ++i) parameters += body.data[i] == '&';
    /* Pinned default, NOT an arbitrary detector cap. Nondefault GODEBUG
     * urlmaxqueryparams configuration is not represented by the frozen ABI. */
    int error = parameters > 10000 ? 3 : 0; br_slice bad = {0};
    size_t at = 0;
    while (error != 3 && at < body.len) {
        size_t end = at; while (end < body.len && body.data[end] != '&') ++end;
        br_slice segment = {body.data + at, end - at}; at = end < body.len ? end + 1 : end;
        if (memchr(segment.data, ';', segment.len)) { error = 2; continue; } /* Semicolon OVERWRITES earlier escape error. */
        size_t equal = 0; while (equal < segment.len && segment.data[equal] != '=') ++equal;
        br_slice key = {segment.data, equal}, value = {segment.data + equal + (equal < segment.len), segment.len - equal - (equal < segment.len)}, current = {0};
        if (!adc_query_valid(key, &current) || !adc_query_valid(value, &current)) { if (!error) { error = 1; bad = current; } }
    }
    if (error) {
        if (token->need_cause) {
            br_gcp_oauth_error cause = {0}; int rc;
            if (error == 1) rc = adc_quoted_cause(&cause, "invalid URL escape ", bad, "", token->fatal);
            else rc = adc_literal(&cause, error == 2 ? "invalid semicolon separator in query" : "number of URL query parameters exceeded limit", token->fatal);
            if (rc != 0) return -1;
            token->cause = (char *)cause.text.data;
        }
        return 1;
    }
    bool seen[7] = {0}; at = 0;
    while (at < body.len) {
        size_t end = at; while (end < body.len && body.data[end] != '&') ++end;
        br_slice segment = {body.data + at, end - at}; at = end < body.len ? end + 1 : end;
        size_t equal = 0; while (equal < segment.len && segment.data[equal] != '=') ++equal;
        br_slice key = {segment.data, equal}, value = {segment.data + equal + (equal < segment.len), segment.len - equal - (equal < segment.len)};
        for (size_t i = 0; i < 7; ++i) if (!seen[i] && adc_query_key(key, i < 6 ? adc_token_names[i] : "expires_in")) {
            seen[i] = true;
            if (i < 6) { if (adc_query_value(value, &token->fields[i], token->fatal) != 0) return -1; }
            else {
                adc_string expiry = {0}; if (adc_query_value(value, &expiry, token->fatal) != 0) return -1;
                (void)adc_integer(expiry.text, sizeof(intptr_t) * CHAR_BIT, &token->seconds); adc_string_clear(&expiry);
            }
            break;
        }
    }
    return 0;
}

static int adc_now(struct timespec *now, char **fatal)
{
    if (clock_gettime(CLOCK_REALTIME, now) != 0 || now->tv_nsec < 0 || now->tv_nsec >= 1000000000)
        return adc_fail(fatal, "unsupported: GCP ADC realtime clock unavailable");
    return 0;
}

static int adc_set_expiry(adc_token *token, char **fatal)
{
    if (!token->seconds) return 0;
    struct timespec now; if (adc_now(&now, fatal) != 0) return -1;
    uint64_t wrapped = (uint64_t)token->seconds * UINT64_C(1000000000);
    int64_t duration = wrapped <= INT64_MAX ? (int64_t)wrapped : -1 - (int64_t)(UINT64_MAX - wrapped);
    int64_t seconds = duration / INT64_C(1000000000), nanos = duration % INT64_C(1000000000);
    if ((seconds > 0 && (int64_t)now.tv_sec > INT64_MAX - seconds - 1) || (seconds < 0 && (int64_t)now.tv_sec < INT64_MIN - seconds + 1))
        return adc_fail(fatal, "unsupported: GCP ADC expiry exceeds native time range");
    int64_t sec = (int64_t)now.tv_sec + seconds, ns = now.tv_nsec + nanos;
    if (ns < 0) { --sec; ns += 1000000000; } else if (ns >= 1000000000) { ++sec; ns -= 1000000000; }
    if ((int64_t)(time_t)sec != sec) return adc_fail(fatal, "unsupported: GCP ADC expiry exceeds native time range");
    token->expiry = (struct timespec){(time_t)sec, (long)ns}; token->has_expiry = true; return 0;
}

static int adc_token_valid(const adc_token *token, bool *valid, char **fatal)
{
    *valid = false; if (!token->fields[0].text.len) return 0;
    if (!token->has_expiry) { *valid = true; return 0; }
    struct timespec now; if (adc_now(&now, fatal) != 0) return -1;
    if ((int64_t)token->expiry.tv_sec < INT64_MIN + 10) return adc_fail(fatal, "unsupported: GCP ADC validity time range");
    int64_t sec = (int64_t)token->expiry.tv_sec - 10;
    *valid = sec > (int64_t)now.tv_sec || (sec == (int64_t)now.tv_sec && token->expiry.tv_nsec >= now.tv_nsec); return 0;
}

static bool adc_temporary(int status) { return status == 500 || status == 503 || status == 408 || status == 429; }

static int adc_io_ready(const br_gcp_adc_state *state, char **fatal)
{
    if (!state->io) return adc_fail(fatal, "unsupported: GCP ADC native SDK HTTP byte I/O is not implemented");
    if (!state->io->send || !state->io->read || !state->io->release) return adc_fail(fatal, "invalid GCP ADC HTTP byte I/O");
    return 0;
}

/* Returns 0 token, +1 ordinary token error, -1 owned/fatal. First-token plain or
 * non-Temporary errors are suppressed BEFORE diagnostic-only formatting guards.
 * Only actual parsed RetrieveError provenance may become AuthenticationError. */
static int adc_refresh(const br_gcp_adc_state *state, const br_scan_ctx *ctx,
                        const adc_credentials *credentials, br_slice refresh, bool later,
                        adc_token *token, br_gcp_oauth_error *cause, char **fatal)
{
    br_gcp_oauth_pair fields[4]; size_t count = 0;
    if (credentials->fields[0].text.len) fields[count++] = (br_gcp_oauth_pair){"client_id", credentials->fields[0].text};
    if (credentials->fields[1].text.len) fields[count++] = (br_gcp_oauth_pair){"client_secret", credentials->fields[1].text};
    fields[count++] = (br_gcp_oauth_pair){"grant_type", ADC_SLICE("refresh_token")}; fields[count++] = (br_gcp_oauth_pair){"refresh_token", refresh};
    br_bytes form = {0};
    if (br_gcp_oauth_form(fields, count, &form, fatal) != 0) return -1;
    if (!ctx) { free(form.data); return adc_fail(fatal, "unsupported: GCP ADC refresh Request.WithContext(nil) panic boundary"); }
    if (adc_io_ready(state, fatal) != 0) { free(form.data); return -1; }
    const br_gcp_oauth_header headers[] = {{"Content-Type", ADC_SLICE("application/x-www-form-urlencoded")}};
    const br_gcp_oauth_request request = {.role = BR_GCP_REFRESH_POST, .method = "POST", .url = ADC_SLICE("https://oauth2.googleapis.com/token"), .body = {form.data, form.len}, .headers = headers, .nheaders = 1};
    br_gcp_oauth_response response = {0}; br_gcp_oauth_error io_error = {0}; br_bytes body = {0}; int outcome = -1;
    int rc = state->io->send(state->user, ctx, &request, &response, &io_error);
    if (rc < 0) { adc_fail(fatal, "GCP ADC refresh send failed fatally"); goto done; }
    if (rc > 0) {
        if (later) { *cause = io_error; io_error = (br_gcp_oauth_error){0}; }
        outcome = 1; goto done;
    }
    br_gcp_oauth_error_clear(&io_error);
    rc = br_gcp_oauth_read(state->io, state->user, &response, &body, &io_error, fatal);
    if (rc < 0) goto done;
    if (rc > 0) {
        if (later && adc_cause(cause, ADC_SLICE("oauth2: cannot fetch token: "), (br_slice){io_error.text.data, io_error.text.len}, (br_slice){0}, fatal) != 0) goto done;
        outcome = 1; goto done; /* Plain even for status500, and %v does NOT unwrap. */
    }
    bool failure = response.status < 200 || response.status > 299;
    token->need_cause = later && !failure; token->fatal = fatal;
    bool form_response = adc_form_response(response.content_type);
    rc = form_response ? adc_form_token((br_slice){body.data, body.len}, token) : adc_json_token((br_slice){body.data, body.len}, token);
    if (rc < 0) goto done;
    if (rc > 0 && !failure) {
        if (later && adc_cause(cause, form_response ? ADC_SLICE("oauth2: cannot parse response: ") : ADC_SLICE("oauth2: cannot parse json: "),
                (br_slice){(const unsigned char *)token->cause, token->cause ? strlen(token->cause) : 0}, (br_slice){0}, fatal) != 0) goto done;
        outcome = 1; goto done;
    }
    if (failure || token->fields[3].text.len) {
        if (later || adc_temporary(response.status)) {
            br_slice empty = {0};
            if (br_gcp_oauth_retrieve_error(response.status_text, (br_slice){body.data, body.len}, rc ? empty : token->fields[3].text,
                    rc ? empty : token->fields[4].text, rc ? empty : token->fields[5].text, cause, fatal) != 0) goto done;
        }
        outcome = 1; goto done;
    }
    if (!token->fields[0].text.len) {
        if (later && adc_literal(cause, "oauth2: server response missing access_token", fatal) != 0) goto done;
        outcome = 1; goto done;
    }
    if (adc_set_expiry(token, fatal) != 0) goto done;
    outcome = 0;
done:
    state->io->release(state->user, &response); /* Every send, request values STILL live. */
    br_gcp_oauth_error_clear(&io_error); free(body.data); free(form.data); return outcome;
}

static int adc_iam(const br_gcp_adc_state *state, const br_scan_ctx *ctx, adc_token *token,
                    br_result *result, br_gcp_oauth_error *cause, char **fatal)
{
    if (adc_io_ready(state, fatal) != 0) return -1;
    br_bytes auth = {0}; br_gcp_oauth_header header = {"Authorization", {0}};
    if (!state->fake_transport) {
        br_slice type = token->fields[1].text, access = token->fields[0].text;
        if (!type.len || br_json_field_name(type, "bearer")) type = ADC_SLICE("Bearer");
        else if (br_json_field_name(type, "mac")) type = ADC_SLICE("MAC");
        else if (br_json_field_name(type, "basic")) type = ADC_SLICE("Basic");
        if (access.len > SIZE_MAX - 2 || type.len > SIZE_MAX - access.len - 2) return adc_fail(fatal, "GCP ADC authorization is too large");
        auth.data = malloc(type.len + access.len + 2);
        if (!auth.data) return adc_fail(fatal, "cannot allocate GCP ADC authorization");
        memcpy(auth.data, type.data, type.len); auth.data[type.len] = ' ';
        memcpy(auth.data + type.len + 1, access.data, access.len); auth.len = type.len + 1 + access.len; auth.data[auth.len] = 0;
        header.value = (br_slice){auth.data, auth.len}; /* Byte length, NEVER truncate NUL-bearing access/type. */
        /* The OAuth layer adds this header before DefaultTransport validates
         * its value. Do not let byte-I/O mocks accept a header Go would reject. */
        for (size_t i = 0; i < auth.len; ++i) if ((auth.data[i] < 32 && auth.data[i] != '\t') || auth.data[i] == 127) {
            int rc = adc_literal(cause, "net/http: invalid header field value for \"Authorization\"", fatal);
            free(auth.data); return rc;
        }
    }
    const br_gcp_oauth_request request = {
        .role = state->fake_transport ? BR_GCP_ADC_FAKE_IAM : BR_GCP_ADC_IAM, .method = "GET", .url = ADC_SLICE("https://iam.googleapis.com/v1/roles"),
        .headers = state->fake_transport ? NULL : &header, .nheaders = state->fake_transport ? 0 : 1,
        .timeout_ns = state->custom_client ? state->timeout_ns : INT64_C(5000000000),
    };
    br_gcp_oauth_response response = {0}; br_gcp_oauth_error io_error = {0}; int outcome = -1;
    int rc = state->io->send(state->user, ctx, &request, &response, &io_error);
    if (rc < 0) { adc_fail(fatal, "GCP ADC IAM send failed fatally"); goto done; }
    if (rc > 0) { *cause = io_error; io_error = (br_gcp_oauth_error){0}; outcome = 0; goto done; }
    if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401) {
        char status[64]; snprintf(status, sizeof(status), "unexpected HTTP response status %d", response.status);
        if (adc_literal(cause, status, fatal) != 0) goto done;
    }
    /* IAM drains to EOF, no token endpoint one-MiB cap. Plain drain errors are
     * ignored, OWN fatal/invalid-length errors cannot be hidden by io.Copy. */
    for (;;) {
        unsigned char discard[8192]; size_t n = 0; br_gcp_oauth_error_clear(&io_error);
        rc = state->io->read(state->user, &response, discard, sizeof(discard), &n, &io_error);
        if (rc < 0 || n > sizeof(discard)) { adc_fail(fatal, "GCP ADC IAM drain failed fatally"); goto done; }
        if (rc > 0 || !n) break;
    }
    outcome = 0;
done:
    state->io->release(state->user, &response);
    br_gcp_oauth_error_clear(&io_error); free(auth.data); return outcome;
}

static int adc_verify(const br_gcp_adc_state *state, const br_scan_ctx *ctx,
                       const adc_credentials *credentials, br_result *result,
                       br_gcp_oauth_error *cause, char **fatal)
{
    int rc = adc_constructor(credentials, cause, fatal);
    if (rc) return rc < 0 ? -1 : 0;
    /* Projected service_account has NO private_key, and authorized_user without
     * refresh_token fails Token() before I/O. Ordinary non-Temporary: suppressed. */
    if (adc_equal(credentials->fields[3].text, "service_account") || !credentials->fields[2].text.len) return 0;
    adc_token first = {0}, second = {0};
    rc = adc_refresh(state, ctx, credentials, credentials->fields[2].text, false, &first, cause, fatal);
    if (rc) { rc = rc < 0 ? -1 : 0; goto done; }
    bool valid = false;
    if (adc_token_valid(&first, &valid, fatal) != 0) { rc = -1; goto done; }
    if (!valid) { rc = 0; goto done; }
    /* Context-bound fixed IAM constructor precedes transport replacement and
     * its second TokenSource.Token. Exact value sentinel alone bypasses auth. */
    if (!ctx) { rc = adc_literal(cause, "net/http: nil Context", fatal); goto done; }
    adc_token *active = &first;
    if (!state->fake_transport) {
        if (adc_token_valid(&first, &valid, fatal) != 0) { rc = -1; goto done; }
        if (!valid) {
            br_slice refresh = first.fields[2].text.len ? first.fields[2].text : credentials->fields[2].text;
            rc = adc_refresh(state, ctx, credentials, refresh, true, &second, cause, fatal);
            if (rc) { rc = rc < 0 ? -1 : 0; goto done; } /* Later errors RETAINED, never first-token suppression. */
            active = &second;
        }
    }
    rc = adc_iam(state, ctx, active, result, cause, fatal);
done:
    adc_token_clear(&first); adc_token_clear(&second); return rc;
}

/* Frozen shared API exposes a C-string setter, not the draft's assumed byte
 * setter. Apply the source's full-match redaction to the selected leaf bytes
 * FIRST, then reject only an unrepresentable FINAL NUL and use that setter. */
static int adc_set_error(br_result *result, const br_gcp_oauth_error *cause, br_slice match, char **fatal)
{
    if (!cause->has_leaf && !cause->text.data) return 0;
    br_slice text = cause->has_leaf ? (br_slice){cause->leaf.data, cause->leaf.len} : (br_slice){cause->text.data, cause->text.len};
    static const char replacement[] = "[REDACTED]";
    size_t count = 0;
    for (size_t i = 0; match.len && i < text.len;) {
        if (match.len <= text.len - i && !memcmp(text.data + i, match.data, match.len)) { ++count; i += match.len; }
        else ++i;
    }
    size_t n = text.len, width = sizeof(replacement) - 1;
    if (n == SIZE_MAX) return adc_fail(fatal, "GCP ADC verification error is too large");
    if (width > match.len) {
        size_t growth = width - match.len;
        if (count > (SIZE_MAX - n - 1) / growth) return adc_fail(fatal, "GCP ADC verification error is too large");
        n += count * growth;
    } else n -= count * (match.len - width);
    unsigned char *data = malloc(n + 1);
    if (!data) return adc_fail(fatal, "cannot allocate GCP ADC verification error");
    size_t at = 0;
    for (size_t i = 0; i < text.len;) {
        if (match.len && match.len <= text.len - i && !memcmp(text.data + i, match.data, match.len)) {
            memcpy(data + at, replacement, width); at += width; i += match.len;
        } else data[at++] = text.data[i++];
    }
    data[at] = 0;
    int rc = 0;
    if (memchr(data, 0, at)) rc = adc_fail(fatal, "unsupported: GCP ADC final verification error contains NUL; ABI1 cannot represent it");
    else if (br_result_set_verification_error(result, (const char *)data, NULL, 0) != 0) rc = adc_fail(fatal, "cannot set GCP ADC verification error");
    free(data); return rc;
}

typedef struct { br_slice input; br_captures matches; char *cause; } adc_matches;
static int adc_capture(void *user, const br_span *groups, size_t count)
{
    adc_matches *matches = user;
    if (!count || groups[0].end > matches->input.len || groups[0].end <= groups[0].begin)
        return adc_fail(&matches->cause, "invalid GCP ADC whole match");
    return br_captures_push(&matches->matches, (br_slice){matches->input.data + groups[0].begin, groups[0].end - groups[0].begin}, false, &matches->cause);
}

static int adc_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return adc_fail(fatal, "invalid or uninitialized GCP ADC scan");
    const br_gcp_adc_state *state = detector->state; adc_matches matches = {.input = input}; char *owned_error = NULL;
    size_t original = out->len; int rc = br_regex_each(state->regex, input, adc_capture, &matches, &owned_error);
    if (matches.cause) { free(owned_error); owned_error = matches.cause; }
    for (size_t i = 0; rc == 0 && i < matches.matches.len; ++i) {
        br_slice match = br_captures_at(&matches.matches, i); adc_credentials credentials = {0}; br_result result = {0}; br_bytes marshaled = {0}; br_gcp_oauth_error cause = {0};
        int decoded = adc_credentials_decode(match, &credentials, &owned_error); size_t redacted_len = 0;
        if (decoded < 0) rc = -1;
        if (!decoded) {
            br_slice id = credentials.fields[0].text, refresh = credentials.fields[2].text;
            const unsigned char *dot = id.len ? memchr(id.data, '.', id.len) : NULL; if (dot) id.len = (size_t)(dot - id.data);
            if (br_finding_pair_bytes(&result, detector->type, id, "client_id", refresh, "refresh_token", (br_slice){0}) != 0)
                rc = adc_fail(&owned_error, "cannot create GCP ADC finding");
            if (rc == 0 && refresh.len > 3) {
                size_t tail = refresh.len - 1 < 47 ? refresh.len - 1 : 47;
                if (refresh.len - tail > SIZE_MAX - 7) rc = adc_fail(&owned_error, "GCP ADC redaction is too large");
                else {
                    redacted_len = 6 + refresh.len - tail; result.redacted = malloc(redacted_len + 1);
                    if (!result.redacted) rc = adc_fail(&owned_error, "cannot allocate GCP ADC redaction");
                    else { memcpy(result.redacted, refresh.data, 3); memcpy(result.redacted + 3, "...", 3); memcpy(result.redacted + 6, refresh.data + tail, refresh.len - tail); result.redacted[redacted_len] = 0; }
                }
            }
            if (rc == 0 && verify) {
                br_slice values[4]; for (size_t f = 0; f < 4; ++f) values[f] = credentials.fields[f].text;
                if (br_gcp_json_object(adc_names, values, 4, &marshaled, &owned_error) != 0) rc = -1;
                if (rc == 0 && adc_verify(state, ctx, &credentials, &result, &cause, &owned_error) != 0) rc = -1;
                /* Unwrap/redact ORIGINAL full match bytes BEFORE checking the
                 * final error NUL boundary. NULL cause remains a no-op. */
                if (rc == 0 && adc_set_error(&result, &cause, match, &owned_error) != 0) rc = -1;
            }
            /* Only the ACTUAL final byte-sliced redaction is ABI1's C string.
             * An omitted-middle NUL is fine; non-NUL invalid UTF8 is preserved. */
            if (rc == 0 && redacted_len && memchr(result.redacted, 0, redacted_len)) rc = adc_fail(&owned_error, "unsupported: GCP ADC final Redacted contains NUL; ABI1 cannot represent it");
            if (rc == 0 && br_results_push(out, &result) != 0) rc = adc_fail(&owned_error, "cannot append GCP ADC finding");
        }
        br_gcp_oauth_error_clear(&cause); free(marshaled.data); br_result_clear(&result);
        for (size_t f = 0; f < 4; ++f) adc_string_clear(&credentials.fields[f]);
    }
    if (rc != 0) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&matches.matches);
    if (fatal) *fatal = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const adc_keywords[] = {".apps.googleusercontent.com"};
static br_gcp_adc_state adc_state;
static br_detector adc_detector = {
    .type = 983, .version = 0, .name = "GCPApplicationDefaultCredentials", .custom_name = "",
    .description = "GCP Application Default Credentials are used to authenticate and authorize API requests to Google Cloud services.",
    .keywords = adc_keywords, .nkeywords = 1, .max_secret_size = 1024, .start_offset = 1024, .max_credential_span = -1, .scan = adc_scan,
};

int br_gcpapplicationdefaultcredentials_init(const br_detector **out, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!out) return adc_fail(fatal, "invalid GCP ADC detector output");
    *out = NULL;
    if (!adc_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\{[^{]+client_secret[^}]+\\}", &regex, fatal) != 0) return -1;
        adc_state = (br_gcp_adc_state){.regex = regex}; adc_detector.state = &adc_state;
    }
    *out = &adc_detector; return 0;
}
