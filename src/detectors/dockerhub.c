/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/dockerhub/{v1,v2}/dockerhub.go.
 * The private ParseUnverified path follows golang-jwt/jwt/v5 v5.2.3 (MIT),
 * parser.go, errors_go1_20.go, registered_claims.go and types.go. */
#include "detectors.h"
#include "captures.h"
#include "email_pattern.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <json-c/json_util.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *token, *username, *email;
    const char *url, *body_start, *body_middle, *token_field;
} hub_version;
typedef struct { br_json *scope, *email; char *saved, *custom; } hub_claims;

static int hub_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int hub_cause(char **out, const char *prefix, const char *detail, const char *suffix)
{
    size_t a = strlen(prefix), b = strlen(detail), c = strlen(suffix);
    if (a > SIZE_MAX - b || a + b >= SIZE_MAX - c) return -1;
    *out = malloc(a + b + c + 1);
    if (!*out) return -1;
    memcpy(*out, prefix, a); memcpy(*out + a, detail, b); memcpy(*out + a + b, suffix, c + 1);
    return 0;
}

static bool hub_exact(br_slice name, const char *expected)
{
    return name.len == strlen(expected) && !memcmp(name.data, expected, name.len);
}

/* All source struct tags are ASCII. Include the two non-ASCII simple-fold
 * equivalents of ASCII letters (long-s/Kelvin), without a shared API change. */
static bool hub_field(br_slice name, const char *expected)
{
    size_t at = 0;
    for (size_t i = 0; expected[i]; ++i) {
        if (at == name.len) return false;
        unsigned char c = name.data[at++];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c == (unsigned char)expected[i]) continue;
        if (expected[i] == 's' && c == 0xc5 && at < name.len && name.data[at] == 0xbf) { ++at; continue; }
        if (expected[i] == 'k' && c == 0xe2 && name.len - at >= 2 &&
            name.data[at] == 0x84 && name.data[at + 1] == 0xaa) { at += 2; continue; }
        return false;
    }
    return at == name.len;
}

/* 0 decoded, 1 owned ordinary cause, -1 resource/unsupported. Guard only a
 * consumed JSON stage, never the input chunk, ignored status bodies or reads. */
static int hub_document(br_slice bytes, br_json **root, char **cause, char **error, const char *stage)
{
    *root = NULL; *cause = NULL;
    if (bytes.len > INT_MAX) return hub_fail(error, "unsupported: Dockerhub JSON exceeds native API limit");
    if (!br_utf8_valid(bytes)) return hub_fail(error, stage);
    int rc = br_json_document(bytes, root, cause);
    return rc < 0 ? hub_fail(error, "cannot decode Dockerhub JSON") : rc;
}

static int hub_type(br_json *value, const char *field, const char *expected, char **saved)
{
    if (*saved) return 0; /* Go saves the FIRST ordinary type error and continues. */
    return br_json_type_cause(value, field, expected, saved) == 0 ? 0 : -1;
}

static int hub_string(br_json *value, br_json **slot, const char *field, char **saved)
{
    if (!value) return 0; /* null into a string does not erase its old value. */
    if (!json_object_is_type(value, json_type_string)) return hub_type(value, field, "string", saved);
    if (slot) { json_object_put(*slot); *slot = json_object_get(value); }
    return 0;
}

typedef struct { const char *field, *qualified; br_json *text; char *saved; } hub_token_response;
static int hub_response_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    hub_token_response *response = user;
    return hub_field(name, response->field) ? hub_string(value, &response->text, response->qualified, &response->saved) : 0;
}

static int hub_response(br_slice body, bool mfa, const hub_version *version,
                         br_json **text, char **cause, char **error)
{
    br_json *root = NULL;
    int rc = hub_document(body, &root, cause, error, "unsupported: Dockerhub invalid UTF-8 response JSON semantics");
    if (rc) { json_object_put(root); return rc; }
    hub_token_response response = {
        .field = mfa ? "login_2fa_token" : version->token_field,
        .qualified = mfa ? "mfaRequiredResponse.login_2fa_token" :
                     !strcmp(version->token_field, "token") ? "tokenResponse.token" : "tokenResponse.access_token",
    };
    if (root && !json_object_is_type(root, json_type_object))
        rc = hub_type(root, NULL, mfa ? "dockerhub.mfaRequiredResponse" : "dockerhub.tokenResponse", &response.saved);
    else if (root) rc = br_json_each_member(body, hub_response_member, &response);
    json_object_put(root);
    if (rc != 0) {
        json_object_put(response.text); free(response.saved);
        return hub_fail(error, "cannot project Dockerhub token response");
    }
    if (response.saved) { *cause = response.saved; json_object_put(response.text); return 1; }
    *text = response.text;
    return 0;
}

/* RawURLEncoding only: ignore CR/LF, reject padding/standard alphabet, accept
 * nonzero unused tail bits. Offsets count ORIGINAL bytes, including newlines. */
static int hub_segment(br_slice input, br_bytes *out, size_t *bad)
{
    *out = (br_bytes){0};
    out->data = malloc(input.len ? input.len : 1);
    if (!out->data) return -1;
    unsigned values[4], count = 0;
    for (size_t i = 0; i < input.len; ++i) {
        unsigned char c = input.data[i]; unsigned value;
        if (c == '\r' || c == '\n') continue;
        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
        else if (c >= '0' && c <= '9') value = c - '0' + 52;
        else if (c == '-') value = 62;
        else if (c == '_') value = 63;
        else { *bad = i; return 1; }
        values[count++] = value;
        if (count == 4) {
            out->data[out->len++] = (unsigned char)((values[0] << 2) | (values[1] >> 4));
            out->data[out->len++] = (unsigned char)((values[1] << 4) | (values[2] >> 2));
            out->data[out->len++] = (unsigned char)((values[2] << 6) | values[3]);
            count = 0;
        }
    }
    if (count == 1) { *bad = input.len - count; return 1; }
    if (count >= 2) out->data[out->len++] = (unsigned char)((values[0] << 2) | (values[1] >> 4));
    if (count == 3) out->data[out->len++] = (unsigned char)((values[1] << 4) | (values[2] >> 2));
    return 0;
}

static int hub_header_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    if (hub_exact(name, "alg")) { br_json **alg = user; json_object_put(*alg); *alg = json_object_get(value); }
    return 0; /* Map keys are exact, including case and embedded NUL. */
}

static br_slice hub_span(br_slice span)
{
    while (span.len && strchr(" \t\r\n", span.data[span.len - 1]) && span.data[span.len - 1]) --span.len;
    return span;
}

static bool hub_number(br_slice number)
{
    size_t at = 0;
    if (at < number.len && number.data[at] == '-') ++at;
    if (at == number.len) return false;
    if (number.data[at] == '0') ++at;
    else {
        if (number.data[at] < '1' || number.data[at] > '9') return false;
        do { ++at; } while (at < number.len && number.data[at] >= '0' && number.data[at] <= '9');
    }
    if (at < number.len && number.data[at] == '.') {
        size_t start = ++at;
        while (at < number.len && number.data[at] >= '0' && number.data[at] <= '9') ++at;
        if (at == start) return false;
    }
    if (at < number.len && (number.data[at] == 'e' || number.data[at] == 'E')) {
        ++at;
        if (at < number.len && (number.data[at] == '+' || number.data[at] == '-')) ++at;
        size_t start = at;
        while (at < number.len && number.data[at] >= '0' && number.data[at] <= '9') ++at;
        if (at == start) return false;
    }
    return at == number.len;
}

/* Only NumericDate diagnostics need Go %q here. Preserve ASCII quoting exactly;
 * non-ASCII diagnostic quoting is an explicit unsupported boundary, not a
 * locale-sensitive approximation. Ordinary Unicode/NUL metadata is unaffected. */
static int hub_quote(br_slice bytes, char **out, char **error)
{
    if (bytes.len > (SIZE_MAX - 3) / 4) return hub_fail(error, "Dockerhub diagnostic too large");
    for (size_t i = 0; i < bytes.len; ++i)
        if (bytes.data[i] >= 128) return hub_fail(error, "unsupported: Dockerhub non-ASCII NumericDate diagnostic quoting");
    char *quoted = malloc(bytes.len * 4 + 3);
    if (!quoted) return hub_fail(error, "cannot quote Dockerhub NumericDate cause");
    static const char hex[] = "0123456789abcdef";
    size_t at = 0; quoted[at++] = '"';
    for (size_t i = 0; i < bytes.len; ++i) {
        unsigned char c = bytes.data[i]; const char *escape = NULL;
        switch (c) {
        case '\a': escape = "\\a"; break; case '\b': escape = "\\b"; break;
        case '\f': escape = "\\f"; break; case '\n': escape = "\\n"; break;
        case '\r': escape = "\\r"; break; case '\t': escape = "\\t"; break;
        case '\v': escape = "\\v"; break; case '"': escape = "\\\""; break;
        case '\\': escape = "\\\\"; break;
        }
        if (escape) { memcpy(quoted + at, escape, 2); at += 2; }
        else if (c < 32 || c == 127) {
            quoted[at++] = '\\'; quoted[at++] = 'x'; quoted[at++] = hex[c >> 4]; quoted[at++] = hex[c & 15];
        } else quoted[at++] = (char)c;
    }
    quoted[at++] = '"'; quoted[at] = '\0'; *out = quoted;
    return 0;
}

static int hub_numeric_date(br_json *value, br_slice encoded, hub_claims *claims, char **error)
{
    if (!value) return 0; /* Null resets the unused *NumericDate pointer. */
    encoded = hub_span(encoded);
    br_slice number = encoded;
    char *inner = NULL, *quoted = NULL;
    int rc = 0;
    if (json_object_is_type(value, json_type_string)) {
        number = br_json_text(value);
        if (!hub_number(number)) {
            rc = hub_quote(encoded, &quoted, error);
            if (!rc) rc = hub_cause(&inner, "json: invalid number literal, trying to unmarshal ", quoted, " into Number");
        }
    } else if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double))
        rc = br_json_type_cause(value, NULL, "json.Number", &inner) == 0 ? 0 : -1;
    if (rc < 0) { free(quoted); return -1; }
    free(quoted); quoted = NULL;
    if (inner) {
        rc = hub_cause(&claims->custom, "could not parse NumericData: ", inner, ""); free(inner);
        return rc ? -1 : 1;
    }
    if (number.len == SIZE_MAX) return -1;
    char *token = malloc(number.len + 1);
    if (!token) return -1;
    memcpy(token, number.data, number.len); token[number.len] = '\0';
    double parsed = 0;
    bool invalid = json_parse_double(token, &parsed) != 0 || !isfinite(parsed);
    free(token);
    if (!invalid) return 0; /* Dates are never validated or emitted. No float->int conversion. */
    rc = hub_quote(number, &quoted, error);
    if (!rc) rc = hub_cause(&claims->custom,
        "could not convert json number value to float: strconv.ParseFloat: parsing ", quoted, ": value out of range");
    free(quoted);
    return rc ? -1 : 1;
}

static int hub_audience_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index; (void)encoded;
    hub_claims *claims = user;
    if (value && json_object_is_type(value, json_type_string)) return 0;
    return hub_cause(&claims->custom, "", "invalid type for claim", "") ? -1 : 1;
}

static int hub_audience(br_json *value, br_slice encoded, hub_claims *claims, char **error)
{
    /* ClaimStrings first unmarshals into any, so even an ultimately invalid
     * audience converts every original number before checking string types. */
    int rc = br_json_check_float64_numbers(encoded, &claims->custom);
    if (rc == 1) {
        /* That custom error is an UnmarshalTypeError, not a wrapping error:
         * decodeState.addErrorContext adds the outer embedded field path.
         * Adapt ONLY this known helper-produced float64 cause, never injected
         * diagnostics or arbitrary error envelopes. Keep its original number. */
        static const char plain[] = " into Go value of type float64";
        static const char field[] = " into Go struct field hubJwtClaims.RegisteredClaims.aud of type float64";
        size_t len = strlen(claims->custom);
        if (len < sizeof(plain) - 1 || memcmp(claims->custom + len - (sizeof(plain) - 1), plain, sizeof(plain)) != 0)
            return hub_fail(error, "unsupported: Dockerhub float64 helper cause format");
        size_t prefix = len - (sizeof(plain) - 1);
        if (prefix > SIZE_MAX - sizeof(field)) return -1;
        char *contextual = malloc(prefix + sizeof(field));
        if (!contextual) return -1;
        memcpy(contextual, claims->custom, prefix);
        memcpy(contextual + prefix, field, sizeof(field));
        free(claims->custom); claims->custom = contextual;
        return 1;
    }
    if (rc) return rc;
    if (!value || json_object_is_type(value, json_type_string)) return 0;
    if (json_object_is_type(value, json_type_array)) return br_json_each_element(encoded, hub_audience_element, claims);
    return hub_cause(&claims->custom, "", "invalid type for claim", "") ? -1 : 1;
}

static int hub_user_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    hub_claims *claims = user;
    if (hub_field(name, "email")) return hub_string(value, &claims->email, "userClaims.https://hub.docker.com.email", &claims->saved);
    if (hub_field(name, "username")) return hub_string(value, NULL, "userClaims.https://hub.docker.com.username", &claims->saved);
    return 0;
}

typedef struct { hub_claims *claims; char **error; } hub_claim_visit;
static int hub_claim_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    hub_claim_visit *visit = user; hub_claims *claims = visit->claims;
    if (hub_field(name, "scope")) return hub_string(value, &claims->scope, "hubJwtClaims.scope", &claims->saved);
    if (hub_field(name, "https://hub.docker.com")) {
        if (!value) return 0; /* Duplicate value-struct objects merge; null is a no-op. */
        if (!json_object_is_type(value, json_type_object))
            return hub_type(value, "hubJwtClaims.https://hub.docker.com", "dockerhub.userClaims", &claims->saved);
        return br_json_each_member(encoded, hub_user_member, claims);
    }
    if (hub_field(name, "iss")) return hub_string(value, NULL, "hubJwtClaims.RegisteredClaims.iss", &claims->saved);
    if (hub_field(name, "sub")) return hub_string(value, NULL, "hubJwtClaims.RegisteredClaims.sub", &claims->saved);
    if (hub_field(name, "jti")) return hub_string(value, NULL, "hubJwtClaims.RegisteredClaims.jti", &claims->saved);
    if (hub_field(name, "aud")) return hub_audience(value, encoded, claims, visit->error);
    if (hub_field(name, "exp") || hub_field(name, "nbf") || hub_field(name, "iat"))
        return hub_numeric_date(value, encoded, claims, visit->error);
    return 0; /* Unknown fields, including huge numbers, are skipped as typed JSON. */
}

static void hub_claims_clear(hub_claims *claims)
{
    json_object_put(claims->scope); json_object_put(claims->email);
    free(claims->saved); free(claims->custom); *claims = (hub_claims){0};
}

static int hub_read_claims(br_slice bytes, hub_claims *claims, char **cause, char **error)
{
    br_json *root = NULL;
    int rc = hub_document(bytes, &root, cause, error, "unsupported: Dockerhub invalid UTF-8 JWT claims JSON semantics");
    if (!rc) {
        if (root && !json_object_is_type(root, json_type_object)) rc = hub_type(root, NULL, "dockerhub.hubJwtClaims", &claims->saved);
        else if (root) {
            hub_claim_visit visit = {claims, error};
            rc = br_json_each_member(bytes, hub_claim_member, &visit);
        }
        if (rc >= 0 && (claims->custom || claims->saved)) {
            /* A custom UnmarshalJSON failure aborts and outranks an earlier
             * saved ordinary type error. Later valid duplicates cannot erase it. */
            char **selected = claims->custom ? &claims->custom : &claims->saved;
            *cause = *selected; *selected = NULL; rc = 1;
        }
    }
    json_object_put(root);
    return rc < 0 && (!error || !*error) ? hub_fail(error, "cannot project Dockerhub typed JWT claims") : rc;
}

static bool hub_algorithm(br_json *alg)
{
    if (!alg || !json_object_is_type(alg, json_type_string)) return false;
    static const char *const known[] = {"none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
                                       "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"};
    br_slice text = br_json_text(alg);
    for (size_t i = 0; i < sizeof(known) / sizeof(*known); ++i) if (hub_exact(text, known[i])) return true;
    return false;
}

/* Only this provider's consumed ParseUnverified stages, NOT a verifier/framework.
 * +1 is a source ordinary error (the credential is STILL verified); -1 is fatal. */
static int hub_jwt(br_slice token, hub_claims *claims, char **cause, char **error)
{
    br_slice dot = {(const unsigned char *)".", 1};
    size_t first = br_slice_find(token, dot, 0), second = SIZE_MAX;
    if (first != SIZE_MAX) second = br_slice_find(token, dot, first + 1);
    if (second == SIZE_MAX || br_slice_find(token, dot, second + 1) != SIZE_MAX)
        return hub_cause(cause, "", "token is malformed", "") ? -1 : 1; /* ONE %w unwraps to sentinel. */
    br_bytes header = {0}, payload = {0};
    br_json *root = NULL, *alg = NULL; char *inner = NULL;
    size_t bad = 0; char base64_cause[96];
    const char *envelope = "token is malformed: could not base64 decode header: ";
    int rc = hub_segment((br_slice){token.data, first}, &header, &bad);
    if (rc < 0) goto resource;
    if (rc) goto base64_error;
    envelope = "token is malformed: could not JSON decode header: ";
    rc = hub_document((br_slice){header.data, header.len}, &root, &inner, error,
                      "unsupported: Dockerhub invalid UTF-8 JWT header JSON semantics");
    if (rc < 0) goto cleanup;
    if (rc) goto wrapped_error;
    if (root && !json_object_is_type(root, json_type_object)) {
        rc = br_json_type_cause(root, NULL, "map[string]interface {}", &inner);
        if (rc) goto resource;
        goto wrapped_error;
    }
    if (root) {
        rc = br_json_check_float64_numbers((br_slice){header.data, header.len}, &inner);
        if (rc < 0) goto resource;
        if (rc) goto wrapped_error;
        if (br_json_each_member((br_slice){header.data, header.len}, hub_header_member, &alg) != 0) goto resource;
    }
    envelope = "token is malformed: could not base64 decode claim: ";
    rc = hub_segment((br_slice){token.data + first + 1, second - first - 1}, &payload, &bad);
    if (rc < 0) goto resource;
    if (rc) goto base64_error;
    envelope = "token is malformed: could not JSON decode claim: ";
    rc = hub_read_claims((br_slice){payload.data, payload.len}, claims, &inner, error);
    if (rc < 0) goto cleanup;
    if (rc) goto wrapped_error;
    /* Method lookup follows complete typed claim decoding; no signature bytes,
     * expiry/issuer/audience validation, keyfunc or cryptographic verification. */
    if (!hub_algorithm(alg)) {
        rc = hub_cause(cause, "", "token is unverifiable", "") ? -1 : 1;
        goto cleanup; /* ONE %w, including missing/wrong/unavailable alg. */
    }
    rc = 0;
    goto cleanup;
base64_error: {
        int len = snprintf(base64_cause, sizeof(base64_cause), "illegal base64 data at input byte %zu", bad);
        if (len < 0 || (size_t)len >= sizeof(base64_cause)) goto resource;
        rc = hub_cause(cause, envelope, base64_cause, "") ? -1 : 1;
        goto cleanup;
    }
wrapped_error:
    /* TWO %w implements Unwrap() []error. Source errors.Unwrap stops HERE:
     * retain the whole envelope, even if its inner NumericDate error wraps. */
    rc = hub_cause(cause, envelope, inner, "") ? -1 : 1;
    goto cleanup;
resource:
    rc = -1;
cleanup:
    free(inner); free(header.data); free(payload.data); json_object_put(root); json_object_put(alg);
    if (rc < 0 && (!error || !*error)) return hub_fail(error, "cannot decode Dockerhub JWT");
    return rc;
}

static int hub_add(br_json *object, const char *key, br_json *owned)
{
    if (!owned) return -1;
    if (json_object_object_add(object, key, owned) == 0) return 0;
    json_object_put(owned); return -1;
}

static br_json *hub_text_value(br_slice value)
{
    return value.len <= INT_MAX ? json_object_new_string_len(value.data ? (const char *)value.data : "", (int)value.len) : NULL;
}

static int hub_extra(br_result *result, br_slice username, const hub_claims *claims, bool mfa)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data || hub_add(result->extra_data, "hub_username", hub_text_value(username)) != 0) return -1;
    if (mfa) return hub_add(result->extra_data, "2fa_required", json_object_new_string("true"));
    br_slice empty = {(const unsigned char *)"", 0};
    if (hub_add(result->extra_data, "hub_email", claims->email ? json_object_get(claims->email) : hub_text_value(empty)) != 0) return -1;
    return hub_add(result->extra_data, "hub_scope", claims->scope ? json_object_get(claims->scope) : hub_text_value(empty));
}

static int hub_verify(const hub_version *version, const br_scan_ctx *ctx, br_slice username,
                       br_slice token, br_result *result, char **error)
{
    size_t a = strlen(version->body_start), b = strlen(version->body_middle);
    if (username.len > SIZE_MAX - a || token.len > SIZE_MAX - a - username.len ||
        a + username.len + token.len > SIZE_MAX - b - 3) return hub_fail(error, "Dockerhub request body too large");
    size_t length = a + username.len + b + token.len + 2;
    unsigned char *body = malloc(length + 1);
    if (!body) return hub_fail(error, "cannot construct Dockerhub request body");
    size_t at = 0;
    memcpy(body + at, version->body_start, a); at += a;
    memcpy(body + at, username.data, username.len); at += username.len;
    memcpy(body + at, version->body_middle, b); at += b;
    memcpy(body + at, token.data, token.len); at += token.len;
    memcpy(body + at, "\"}", 3);
    /* One necessary complete, UNESCAPED body allocation. Finding/RawV2/map
     * resources precede it, and it precedes the context-bound constructor. */
    const char *leaf = NULL; char *owned = NULL, *transport_error = NULL;
    br_json *issued = NULL; hub_claims claims = {0}; br_http_response response = {0};
    int rc = 0; bool sent = false;
    if (!ctx) leaf = "net/http: nil Context";
    else {
        const br_header headers[] = {{"Content-Type", "application/json"}};
        const br_http_request request = {
            .method = "POST", .url = version->url, .profile = BR_HTTP_SANE,
            .headers = headers, .nheaders = 1, .body = {body, length}, .detector_type = 921,
        };
        sent = true;
        if (br_http_send(ctx, &request, &response, &transport_error) != 0)
            leaf = transport_error ? transport_error : "HTTP transport failed";
        else if (response.body_error != NULL) leaf = response.body_error; /* Even an empty error precedes EVERY status. */
        else if (response.status == 200 || response.status == 401) {
            bool mfa = response.status == 401;
            int decoded = hub_response(response.body, mfa, version, &issued, &owned, error);
            if (decoded < 0) rc = -1;
            else if (mfa && decoded) { free(owned); owned = NULL; } /* Ordinary MFA decode errors suppressed, never resources. */
            else if (!decoded && br_json_text(issued).len) {
                if (mfa) {
                    result->verified = true;
                    if (hub_extra(result, username, &claims, true) != 0) rc = hub_fail(error, "cannot create Dockerhub MFA metadata");
                } else {
                    int parsed = hub_jwt(br_json_text(issued), &claims, &owned, error);
                    if (parsed < 0) rc = -1;
                    else {
                        result->verified = true; /* JWT errors still verify; append THEN break. */
                        if (!parsed && hub_extra(result, username, &claims, false) != 0)
                            rc = hub_fail(error, "cannot create Dockerhub claim metadata");
                    }
                }
            }
        } else {
            char status[64];
            int len = snprintf(status, sizeof(status), "unexpected response status %d", response.status);
            if (len < 0 || (size_t)len >= sizeof(status) || hub_cause(&owned, "", status, "") != 0)
                rc = hub_fail(error, "cannot create Dockerhub status cause");
        }
    }
    if (!rc && br_result_set_verification_error(result, owned ? owned : leaf, NULL, 0) != 0)
        rc = hub_fail(error, "cannot set Dockerhub verification error");
    /* Copy borrowed errors and retain JSON strings before release; request body
     * stays alive through release. Source Close errors are ignored. Buffered
     * Reader/close timing, POST redirects, private clients and typed transport
     * error chains remain ABI/runtime gaps; do not weaken native guards. */
    if (sent) br_http_release(ctx, &response);
    free(body); free(owned); free(transport_error); json_object_put(issued); hub_claims_clear(&claims);
    return rc;
}

static int hub_raw_v2(br_result *result, br_slice username, br_slice token)
{
    if (username.len == SIZE_MAX || token.len > SIZE_MAX - username.len - 1) return -1;
    result->raw_v2.len = username.len + 1 + token.len;
    result->raw_v2.data = malloc(result->raw_v2.len);
    if (!result->raw_v2.data) return -1;
    memcpy(result->raw_v2.data, username.data, username.len); result->raw_v2.data[username.len] = ':';
    memcpy(result->raw_v2.data + username.len + 1, token.data, token.len);
    return 0;
}

static int hub_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return hub_fail(error, "invalid Dockerhub scan");
    const hub_version *version = detector->state;
    if (!version->token || !version->username || !version->email) return hub_fail(error, "uninitialized Dockerhub scan");
    size_t original_len = out->len;
    br_captures tokens = {0}, usernames = {0}; char *owned_error = NULL;
    int rc = br_captures_find(version->token, input, &tokens, true, &owned_error);
    if (!rc && tokens.len) rc = br_captures_find(version->username, input, &usernames, true, &owned_error);
    if (!rc && tokens.len) rc = br_captures_find(version->email, input, &usernames, true, &owned_error);
    /* Native first-source set order is one iteration choice, not Go map-order
     * parity. Username pass precedes email union; never trim or normalize bytes. */
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        br_slice token = br_captures_at(&tokens, i);
        br_result result = {0}; br_json *parts = NULL; const char *sticky = NULL;
        if (br_finding_key_bytes(&result, 921, token, "pat") != 0) rc = hub_fail(&owned_error, "cannot create Dockerhub finding");
        if (!rc) parts = json_object_get(result.secret_parts); /* Per-token mutable SOURCE map. */
        if (!rc && !usernames.len && br_results_push(out, &result) != 0) rc = hub_fail(&owned_error, "cannot append Dockerhub PAT finding");
        for (size_t j = 0; !rc && j < usernames.len; ++j) {
            br_slice username = br_captures_at(&usernames, j);
            if (j) {
                result.detector_type = 921;
                result.raw.data = malloc(token.len);
                if (!result.raw.data) rc = hub_fail(&owned_error, "cannot copy Dockerhub finding");
                else { memcpy(result.raw.data, token.data, token.len); result.raw.len = token.len; }
                result.secret_parts = json_object_get(parts);
                /* Appended C errors must be independent immutable snapshots.
                 * NULL setter updates do not erase the prior attempt's error. */
                if (!rc && br_result_set_verification_error(&result, sticky, NULL, 0) != 0)
                    rc = hub_fail(&owned_error, "cannot snapshot Dockerhub verification error");
            }
            if (!rc && hub_raw_v2(&result, username, token) != 0) rc = hub_fail(&owned_error, "cannot create Dockerhub RawV2");
            if (!rc && hub_add(parts, "username", hub_text_value(username)) != 0) rc = hub_fail(&owned_error, "cannot update Dockerhub shared username");
            if (!rc && verify) rc = hub_verify(version, ctx, username, token, &result, &owned_error);
            bool verified = result.verified;
            if (!rc && br_results_push(out, &result) != 0) rc = hub_fail(&owned_error, "cannot append Dockerhub finding");
            if (!rc) sticky = out->items[out->len - 1].verification_error; /* Borrowed until invocation rollback. */
            if (verified) break;
        }
        br_result_clear(&result); json_object_put(parts);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens); br_captures_clear(&usernames);
    if (rc && !owned_error) hub_fail(&owned_error, "cannot process Dockerhub findings");
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static hub_version hub_v1 = {
    .url = "https://hub.docker.com/v2/users/login", .body_start = "{\"username\": \"",
    .body_middle = "\", \"password\": \"", .token_field = "token",
};
static hub_version hub_v2 = {
    .url = "https://hub.docker.com/v2/auth/token", .body_start = "{\"identifier\": \"",
    .body_middle = "\", \"secret\": \"", .token_field = "access_token",
};
static const char *const hub_keywords_v1[] = {"docker"};
static const char *const hub_keywords_v2[] = {"docker", "dckr_pat_", "dckr_oat_"};
static br_detector hub_detector_v1 = {
    .type = 921, .version = 1, .name = "Dockerhub", .custom_name = "",
    .description = "Docker is a platform used to develop, ship, and run applications. Docker access tokens can be used to authenticate and interact with Docker services.",
    .keywords = hub_keywords_v1, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &hub_v1, .scan = hub_scan,
};
static br_detector hub_detector_v2 = {
    .type = 921, .version = 2, .name = "Dockerhub", .custom_name = "",
    .description = "Dockerhub is a cloud-based repository in which Docker users and partners create, test, store and distribute container images. Dockerhub personal access tokens (PATs) can be used to access and manage these container images.",
    .keywords = hub_keywords_v2, .nkeywords = 3, .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &hub_v2, .scan = hub_scan,
};

static int hub_init(br_detector *detector, hub_version *version, const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hub_fail(error, "invalid Dockerhub detector output");
    *out = NULL;
    if (!version->token) {
        br_regex *token = NULL, *username = NULL, *email = NULL;
        /* RE2 \\s has FIVE ASCII whitespace characters, excluding VT. PCRE2's
         * \\s/\\S differ: translate only these source username classes locally. */
        const char *user_pattern = "(?im)(?:user|usr|-u|id)[^\\t\\n\\f\\r ]{0,40}?[:=\\t\\n\\f\\r ]{1,3}[ '\"=]?([a-zA-Z0-9]{4,40})\\b";
        int rc;
        if (detector->version == 1) {
            rc = br_regex_compile_prefixed(hub_keywords_v1, 1, "\\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\\b", &token, error);
            if (!rc) rc = br_regex_compile_prefixed(hub_keywords_v1, 1, user_pattern, &username, error);
            if (!rc) rc = br_regex_compile_prefixed(hub_keywords_v1, 1, br_email_pattern, &email, error);
        } else {
            rc = br_regex_compile("\\b(dckr_pat_[a-zA-Z0-9_-]{27}|dckr_oat_[a-zA-Z0-9_-]{32})(?:[^a-zA-Z0-9_-]|\\z)", &token, error);
            if (!rc) rc = br_regex_compile(user_pattern, &username, error);
            if (!rc) rc = br_regex_compile(br_email_pattern, &email, error);
        }
        if (rc) { br_regex_free(token); br_regex_free(username); br_regex_free(email); return -1; }
        version->token = token; version->username = username; version->email = email;
    }
    *out = detector;
    return 0;
}

int br_dockerhub_v1_init(const br_detector **out, char **error) { return hub_init(&hub_detector_v1, &hub_v1, out, error); }
int br_dockerhub_v2_init(const br_detector **out, char **error) { return hub_init(&hub_detector_v2, &hub_v2, out, error); }
