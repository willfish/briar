/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/docker/docker_auth_config.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct { br_bytes auth, username, password, email; } docker_auth;
typedef struct { br_bytes registry; docker_auth auth; } docker_entry;
typedef struct { docker_entry *items; size_t len, cap; char *cause; } docker_auths;

static int docker_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int docker_format(char **out, const char *format, ...)
{
    *out = NULL;
    va_list args, copy;
    va_start(args, format); va_copy(copy, args);
    int n = vsnprintf(NULL, 0, format, args);
    va_end(args);
    if (n < 0) { va_end(copy); return -1; }
    char *text = malloc((size_t)n + 1);
    if (!text) { va_end(copy); return -1; }
    int written = vsnprintf(text, (size_t)n + 1, format, copy);
    va_end(copy);
    if (written != n) { free(text); return -1; }
    *out = text;
    return 0;
}

static br_slice docker_slice(const br_bytes *bytes)
{
    return (br_slice){bytes->data, bytes->len};
}

static bool docker_equal(br_slice bytes, const char *text)
{
    size_t len = strlen(text);
    return bytes.len == len && (!len || !memcmp(bytes.data, text, len));
}

static int docker_set_bytes(br_bytes *out, br_slice value)
{
    if (value.len == SIZE_MAX || (!value.data && value.len)) return -1;
    unsigned char *data = NULL;
    if (value.len) {
        data = malloc(value.len + 1);
        if (!data) return -1;
        memcpy(data, value.data, value.len); data[value.len] = 0;
    }
    free(out->data); *out = (br_bytes){data, value.len};
    return 0;
}

/* Relevant JSON strings must not silently inherit json-c's invalid-UTF8 byte
 * behavior. Go replacement and unpaired-surrogate details remain a native gap. */
static int docker_utf8(br_slice text)
{
    br_slice decoded = {0}; br_bytes storage = {0}; char *error = NULL;
    int rc = br_utf8_decode(text, &decoded, &storage, &error);
    free(error);
    bool replaced = storage.data != NULL;
    free(storage.data);
    return rc != 0 ? -1 : replaced ? 1 : 0;
}

static void docker_auth_clear(docker_auth *auth)
{
    free(auth->auth.data); free(auth->username.data);
    free(auth->password.data); free(auth->email.data);
    memset(auth, 0, sizeof(*auth));
}

static void docker_entries_clear(docker_auths *auths)
{
    for (size_t i = 0; i < auths->len; ++i) {
        free(auths->items[i].registry.data); docker_auth_clear(&auths->items[i].auth);
    }
    free(auths->items); auths->items = NULL; auths->len = auths->cap = 0;
}

typedef struct { docker_auth *auth; char **cause; } docker_auth_fields;

static int docker_read_auth_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    docker_auth_fields *fields = user;
    br_bytes *target = NULL; const char *field = NULL;
    if (br_json_field_name(name, "auth")) { target = &fields->auth->auth; field = "dockerAuth.auths.auth"; }
    else if (br_json_field_name(name, "username")) { target = &fields->auth->username; field = "dockerAuth.auths.username"; }
    else if (br_json_field_name(name, "password")) { target = &fields->auth->password; field = "dockerAuth.auths.password"; }
    else if (br_json_field_name(name, "email")) { target = &fields->auth->email; field = "dockerAuth.auths.email"; }
    if (!target || !value) return 0; /* Unknown fields ignored; primitive null is a no-op. */
    if (!json_object_is_type(value, json_type_string))
        return br_json_type_cause(value, field, "string", fields->cause) == 0 ? 1 : -1;
    br_slice text = br_json_text(value);
    int utf8 = docker_utf8(text);
    if (utf8 != 0) return docker_fail(fields->cause, utf8 < 0 ? "cannot validate Docker JSON string" : "unsupported: Docker invalid UTF-8 JSON string conversion");
    return docker_set_bytes(target, text);
}

static int docker_read_registry(void *user, br_slice name, br_json *value, br_slice encoded)
{
    docker_auths *auths = user;
    int utf8 = docker_utf8(name);
    if (utf8 != 0) return docker_fail(&auths->cause, utf8 < 0 ? "cannot validate Docker registry" : "unsupported: Docker invalid UTF-8 registry conversion");
    size_t at = 0;
    while (at < auths->len && (auths->items[at].registry.len != name.len ||
           (name.len && memcmp(auths->items[at].registry.data, name.data, name.len)))) ++at;
    if (at == auths->len) {
        if (auths->len == auths->cap) {
            size_t cap = auths->cap ? auths->cap * 2 : 8;
            if (cap < auths->cap || cap > SIZE_MAX / sizeof(*auths->items)) return -1;
            docker_entry *items = realloc(auths->items, cap * sizeof(*items));
            if (!items) return -1;
            auths->items = items; auths->cap = cap;
        }
        auths->items[at] = (docker_entry){0};
        if (docker_set_bytes(&auths->items[at].registry, name) != 0) return -1;
        ++auths->len;
    } else docker_auth_clear(&auths->items[at].auth);
    /* A map value is a FRESH struct, including for duplicate registry keys. */
    if (!value) return 0;
    if (!json_object_is_type(value, json_type_object))
        return br_json_type_cause(value, "dockerAuths.auths", "docker.dockerAuth", &auths->cause) == 0 ? 1 : -1;
    docker_auth_fields fields = {&auths->items[at].auth, &auths->cause};
    return br_json_each_member(encoded, docker_read_auth_field, &fields);
}

static int docker_read_root_field(void *user, br_slice name, br_json *value, br_slice encoded)
{
    docker_auths *auths = user;
    if (!br_json_field_name(name, "auths")) return 0;
    if (!value) { docker_entries_clear(auths); return 0; }
    if (!json_object_is_type(value, json_type_object))
        return br_json_type_cause(value, "dockerAuths.auths", "map[string]docker.dockerAuth", &auths->cause) == 0 ? 1 : -1;
    /* Repeated object-valued auths fields merge into the existing map. */
    return br_json_each_member(encoded, docker_read_registry, auths);
}

/* 0 = typed decode success, +1 = ordinary Decode cause, -1 = own resources or
 * explicitly unsupported conversion. Unknown huge numbers are never float64-checked. */
static int docker_decode(br_slice config, docker_auths *auths)
{
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(config, NULL, &root, &end, &auths->cause);
    if (rc != 0) return rc;
    if (!root) return 0;
    if (!json_object_is_type(root, json_type_object))
        rc = br_json_type_cause(root, NULL, "docker.dockerAuths", &auths->cause) == 0 ? 1 : -1;
    else rc = br_json_each_member((br_slice){config.data, end}, docker_read_root_field, auths);
    json_object_put(root);
    return rc;
}

/* NewReplacer scans ORIGINAL bytes once, using leftmost non-overlapping pairs.
 * Do not repeatedly replace the newly produced text or JSON-unescape it here. */
static int docker_normalize(br_slice original, br_bytes *out)
{
    if (original.len == SIZE_MAX) return -1;
    out->data = malloc(original.len + 1);
    if (!out->data) return -1;
    size_t n = 0;
    for (size_t i = 0; i < original.len;) {
        if (original.data[i] == '\\' && i + 1 < original.len) {
            unsigned char next = original.data[i + 1];
            if (next == 'n' || next == 'r' || next == 't' || next == '\\') { i += 2; continue; }
            if (next == '"') { out->data[n++] = '"'; i += 2; continue; }
        }
        out->data[n++] = original.data[i++];
    }
    out->data[n] = 0; out->len = n;
    return 0;
}

static int docker_sextet(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* StdEncoding validity only: CR/LF ignored, padding required as appropriate,
 * nonzero pad bits accepted. Invalid partial output is discarded entirely. */
static int docker_decode_auth(br_slice input, br_bytes *out)
{
    size_t count = 0;
    for (size_t i = 0; i < input.len; ++i) if (input.data[i] != '\r' && input.data[i] != '\n') ++count;
    if (count % 4) return 1;
    if (!count) return 0;
    out->data = malloc(count / 4 * 3);
    if (!out->data) return -1;
    size_t at = 0, used = 0;
    for (size_t group = 0; group < count / 4; ++group) {
        unsigned char q[4];
        for (size_t j = 0; j < 4; ++j) {
            while (at < input.len && (input.data[at] == '\r' || input.data[at] == '\n')) ++at;
            q[j] = input.data[at++];
        }
        int a = docker_sextet(q[0]), b = docker_sextet(q[1]);
        int c = docker_sextet(q[2]), d = docker_sextet(q[3]);
        bool last = group + 1 == count / 4;
        if (a < 0 || b < 0 || (q[2] == '=' ? q[3] != '=' || !last : c < 0) ||
            (q[2] != '=' && (q[3] == '=' ? !last : d < 0))) {
            free(out->data); *out = (br_bytes){0}; return 1;
        }
        out->data[used++] = (unsigned char)((a << 2) | (b >> 4));
        if (q[2] != '=') {
            out->data[used++] = (unsigned char)((b << 4) | (c >> 2));
            if (q[3] != '=') out->data[used++] = (unsigned char)((c << 6) | d);
        }
    }
    out->len = used;
    return 0;
}

static bool docker_hub(br_slice registry)
{
    static const char target[] = "docker.io";
    size_t at = 0;
    for (size_t i = 0; i < sizeof(target) - 1; ++i) {
        if (at == registry.len) return false;
        unsigned char c = registry.data[at++];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c == (unsigned char)target[i]) continue;
        /* Go EqualFold's only non-ASCII equivalent relevant to docker.io. */
        if (target[i] == 'k' && c == 0xe2 && at + 1 < registry.len && registry.data[at] == 0x84 && registry.data[at + 1] == 0xaa) { at += 2; continue; }
        return false;
    }
    return at == registry.len;
}

static bool docker_example(br_slice registry)
{
    static const char *const examples[] = {"https://index.docker.io/v1/", "registry.hostname.com",
        "registry.example.com:5000", "registry2.example.com:5000", "your.private.registry.example.com"};
    for (size_t i = 0; i < sizeof(examples) / sizeof(examples[0]); ++i) if (docker_equal(registry, examples[i])) return true;
    return false;
}

static int docker_add_part(br_json *object, const char *name, br_slice value)
{
    if (value.len > INT_MAX) return -1;
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "", (int)value.len);
    if (!part) return -1;
    if (json_object_object_add(object, name, part) != 0) { json_object_put(part); return -1; }
    return 0;
}

static int docker_result(br_result *result, br_slice registry, br_slice username, const char *authorization)
{
    br_slice encoded = {(const unsigned char *)authorization + 6, strlen(authorization + 6)};
    if (br_finding_key_bytes(result, 343, encoded, "auth") != 0 ||
        docker_add_part(result->secret_parts, "registry", registry) != 0) return -1;
    result->extra_data = json_object_new_object();
    if (!result->extra_data || docker_add_part(result->extra_data, "Username", username) != 0) return -1;
    static const char prefix[] = "{\"registry\":\"", middle[] = "\",\"auth\":\"", suffix[] = "\"}";
    size_t overhead = sizeof(prefix) - 1 + sizeof(middle) - 1 + sizeof(suffix) - 1;
    if (registry.len > SIZE_MAX - overhead || encoded.len > SIZE_MAX - overhead - registry.len) return -1;
    result->raw_v2.len = overhead + registry.len + encoded.len;
    result->raw_v2.data = malloc(result->raw_v2.len);
    if (!result->raw_v2.data) return -1;
    unsigned char *p = result->raw_v2.data;
    memcpy(p, prefix, sizeof(prefix) - 1); p += sizeof(prefix) - 1;
    if (registry.len) { memcpy(p, registry.data, registry.len); p += registry.len; }
    memcpy(p, middle, sizeof(middle) - 1); p += sizeof(middle) - 1;
    memcpy(p, encoded.data, encoded.len); p += encoded.len;
    memcpy(p, suffix, sizeof(suffix) - 1); /* Deliberately NOT JSON-escaped. */
    return 0;
}

/* Go TrimSpace's Unicode White_Space set, not C locale/ASCII-only isspace. */
static size_t docker_space(br_slice text)
{
    if (!text.len) return 0;
    unsigned char c = text.data[0];
    if (c == ' ' || (c >= '\t' && c <= '\r')) return 1;
    if (text.len >= 2 && c == 0xc2 && (text.data[1] == 0x85 || text.data[1] == 0xa0)) return 2;
    if (text.len < 3) return 0;
    if (c == 0xe1 && text.data[1] == 0x9a && text.data[2] == 0x80) return 3;
    if (c != 0xe2) return 0;
    if (text.data[1] == 0x80 && ((text.data[2] >= 0x80 && text.data[2] <= 0x8a) ||
        text.data[2] == 0xa8 || text.data[2] == 0xa9 || text.data[2] == 0xaf)) return 3;
    if (text.data[1] == 0x81 && text.data[2] == 0x9f) return 3;
    /* U+3000 starts with E3, handled separately below. */
    return 0;
}

static size_t docker_space_prefix(br_slice text)
{
    if (text.len >= 3 && text.data[0] == 0xe3 && text.data[1] == 0x80 && text.data[2] == 0x80) return 3;
    return docker_space(text);
}

static br_slice docker_trim(br_slice text)
{
    size_t n;
    while ((n = docker_space_prefix(text)) != 0) { text.data += n; text.len -= n; }
    for (;;) {
        n = 0;
        for (size_t width = 1; width <= 3 && width <= text.len; ++width)
            if (docker_space_prefix((br_slice){text.data + text.len - width, width}) == width) { n = width; break; }
        if (!n) return text;
        text.len -= n;
    }
}

static int docker_auth_params(const char *header, br_bytes *realm, br_bytes *service, char **cause)
{
    const char *space = strchr(header, ' ');
    if (!space) return docker_format(cause, "invalid WWW-Authenticate header format") == 0 ? 1 : -1;
    const char *end = strchr(space + 1, ' ');
    if (!end) end = header + strlen(header);
    const unsigned char *at = (const unsigned char *)space + 1, *last = (const unsigned char *)end;
    /* Exactly parts[1], then comma pieces; quoting does not protect spaces or commas. */
    while (at <= last) {
        const unsigned char *comma = at;
        while (comma < last && *comma != ',') ++comma;
        br_slice part = docker_trim((br_slice){at, (size_t)(comma - at)});
        size_t equals = 0; while (equals < part.len && part.data[equals] != '=') ++equals;
        if (equals < part.len) {
            br_slice name = docker_trim((br_slice){part.data, equals});
            br_slice value = docker_trim((br_slice){part.data + equals + 1, part.len - equals - 1});
            while (value.len && value.data[0] == '"') { ++value.data; --value.len; }
            while (value.len && value.data[value.len - 1] == '"') --value.len;
            br_bytes *target = docker_equal(name, "realm") ? realm : docker_equal(name, "service") ? service : NULL;
            if (target && docker_set_bytes(target, value) != 0) return -1;
        }
        if (comma == last) break;
        at = comma + 1;
    }
    return 0;
}

static bool docker_query_safe(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

static int docker_query_length(br_slice value, size_t *length)
{
    *length = 0;
    for (size_t i = 0; i < value.len; ++i) {
        size_t n = docker_query_safe(value.data[i]) || value.data[i] == ' ' ? 1 : 3;
        if (*length > SIZE_MAX - n) return -1;
        *length += n;
    }
    return 0;
}

static unsigned char *docker_query_write(unsigned char *out, br_slice value)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        if (docker_query_safe(c)) *out++ = c;
        else if (c == ' ') *out++ = '+';
        else { *out++ = '%'; *out++ = (unsigned char)hex[c >> 4]; *out++ = (unsigned char)hex[c & 15]; }
    }
    return out;
}

/* Known constructor-invalid syntax is distinct from valid Go URL forms that
 * this port cannot faithfully serialize. The latter fail closed, never send a
 * guessed/normalized URL. Full Go URL/Reader/error-string parity remains open. */
typedef enum { DOCKER_URL_OK, DOCKER_URL_BAD, DOCKER_URL_UNSUPPORTED } docker_url_kind;

static bool docker_hex(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static docker_url_kind docker_url_check(br_slice url, bool replace_query)
{
    size_t query = SIZE_MAX, fragment = SIZE_MAX;
    for (size_t i = 0; i < url.len; ++i) {
        unsigned char c = url.data[i];
        if (c < 0x20 || c == 0x7f) return DOCKER_URL_BAD;
        if (c == '#' && fragment == SIZE_MAX) fragment = i;
        if (c == '?' && query == SIZE_MAX && fragment == SIZE_MAX) query = i;
    }
    for (size_t i = 0; i < url.len; ++i) {
        bool in_query = query != SIZE_MAX && i > query && (fragment == SIZE_MAX || i < fragment);
        if (in_query && replace_query) continue; /* Only the challenge replaces RawQuery. */
        unsigned char c = url.data[i];
        if (c == '%' && (i + 2 >= url.len || !docker_hex(url.data[i + 1]) || !docker_hex(url.data[i + 2]))) return DOCKER_URL_BAD;
        if (c == ' ' || c >= 0x80 || c == '\\' || c == '"' || c == '<' || c == '>' || c == '{' || c == '}') return DOCKER_URL_UNSUPPORTED;
    }
    size_t scheme = url.len >= 8 && !memcmp(url.data, "https://", 8) ? 8 : url.len >= 7 && !memcmp(url.data, "http://", 7) ? 7 : 0;
    if (!scheme) {
        if (url.len && url.data[0] == ':') return DOCKER_URL_BAD;
        return DOCKER_URL_UNSUPPORTED;
    }
    size_t end = scheme;
    while (end < url.len && url.data[end] != '/' && url.data[end] != '?' && url.data[end] != '#') ++end;
    if (end == scheme) return DOCKER_URL_UNSUPPORTED;
    /* Valid Go user-info syntax must not be mistaken for a malformed port.
     * Keep this unported serialization form explicitly fail-closed. */
    if (memchr(url.data + scheme, '@', end - scheme)) return DOCKER_URL_UNSUPPORTED;
    if (url.data[scheme] == '[') {
        bool closed = false; for (size_t i = scheme + 1; i < end; ++i) if (url.data[i] == ']') closed = true;
        return closed ? DOCKER_URL_UNSUPPORTED : DOCKER_URL_BAD;
    }
    bool port = false;
    for (size_t i = scheme; i < end; ++i) {
        unsigned char c = url.data[i];
        if (c == ']') return DOCKER_URL_BAD;
        if (c == ':') { if (port) return DOCKER_URL_UNSUPPORTED; port = true; if (i + 1 == end) return DOCKER_URL_UNSUPPORTED; continue; }
        if (port) { if (c < '0' || c > '9') return DOCKER_URL_BAD; }
        else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return DOCKER_URL_UNSUPPORTED;
    }
    return DOCKER_URL_OK;
}

static int docker_registry_url(br_slice registry, char **out)
{
    if (registry.len && registry.data[registry.len - 1] == '/') --registry.len; /* ONE slash. */
    bool has_scheme = (registry.len >= 7 && !memcmp(registry.data, "http://", 7)) ||
                      (registry.len >= 8 && !memcmp(registry.data, "https://", 8));
    size_t prefix = has_scheme ? 0 : sizeof("https://") - 1;
    if (registry.len > SIZE_MAX - prefix - sizeof("/v2/")) return -1;
    size_t length = prefix + registry.len + sizeof("/v2/");
    *out = malloc(length);
    if (!*out) return -1;
    if (prefix) memcpy(*out, "https://", prefix);
    if (registry.len) memcpy(*out + prefix, registry.data, registry.len);
    memcpy(*out + prefix + registry.len, "/v2/", sizeof("/v2/"));
    return 0;
}

static int docker_challenge_url(br_slice realm, br_slice username, br_slice service, char **out)
{
    size_t fragment = realm.len, prefix = realm.len;
    for (size_t i = 0; i < realm.len; ++i) {
        if (realm.data[i] == '#' && fragment == realm.len) { fragment = i; break; }
        if (realm.data[i] == '?' && prefix == realm.len) prefix = i;
    }
    if (prefix > fragment) prefix = fragment;
    size_t tail = fragment < realm.len && fragment + 1 < realm.len ? realm.len - fragment : 0;
    size_t account_len, service_len;
    if (docker_query_length(username, &account_len) != 0 || docker_query_length(service, &service_len) != 0) return -1;
    size_t overhead = sizeof("?account=") - 1 + sizeof("&service=");
    if (prefix > SIZE_MAX - overhead || account_len > SIZE_MAX - overhead - prefix ||
        service_len > SIZE_MAX - overhead - prefix - account_len || tail > SIZE_MAX - overhead - prefix - account_len - service_len) return -1;
    *out = malloc(prefix + overhead + account_len + service_len + tail);
    if (!*out) return -1;
    unsigned char *p = (unsigned char *)*out;
    if (prefix) { memcpy(p, realm.data, prefix); p += prefix; }
    memcpy(p, "?account=", sizeof("?account=") - 1); p += sizeof("?account=") - 1;
    p = docker_query_write(p, username);
    memcpy(p, "&service=", sizeof("&service=") - 1); p += sizeof("&service=") - 1;
    p = docker_query_write(p, service);
    if (tail) { memcpy(p, realm.data + fragment, tail); p += tail; }
    *p = 0;
    return 0;
}

static int docker_verify(const br_scan_ctx *ctx, br_slice registry, br_slice username,
                          const char *authorization, br_slice normalized, br_result *result, char **error)
{
    char *url = NULL, *auth_url = NULL, *initial_error = NULL, *auth_error = NULL, *owned_cause = NULL;
    const char *cause = NULL;
    br_bytes realm = {0}, service = {0};
    br_http_response initial = {0}, auth = {0};
    bool initial_called = false, auth_called = false, verified = false;
    int rc = 0;
    if (docker_registry_url(registry, &url) != 0) { rc = docker_fail(error, "cannot allocate Docker registry URL"); goto cleanup; }
    /* Embedded NUL cannot be handed to ABI1 C-string URLs. */
    if (registry.len && memchr(registry.data, 0, registry.len)) {
        if (docker_format(&owned_cause, "unsupported: Docker registry URL contains NUL") != 0) { rc = -1; goto cleanup; }
        cause = owned_cause; goto record;
    }
    if (docker_url_check((br_slice){(const unsigned char *)url, strlen(url)}, false) != DOCKER_URL_OK) {
        if (docker_format(&owned_cause, "unsupported: Docker registry URL construction outside native ASCII http(s) subset") != 0) { rc = -1; goto cleanup; }
        cause = owned_cause; goto record;
    }
    const br_header headers[] = {{"Authorization", authorization}, {"Accept", "application/json"}, {"Content-Type", "application/json"}};
    const br_http_request request = {.method = "GET", .url = url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = 343};
    initial_called = true;
    if (br_http_send(ctx, &request, &initial, &initial_error) != 0) { cause = initial_error ? initial_error : "HTTP transport failed"; goto record; }
    if (initial.status == 200) {
        if (initial.body_error != NULL) { cause = initial.body_error; goto record; }
        br_json *document = NULL; char *json_cause = NULL;
        int decoded = br_json_document(initial.body, &document, &json_cause);
        json_object_put(document); free(json_cause);
        if (decoded < 0) { rc = docker_fail(error, "cannot validate Docker registry JSON body"); goto cleanup; }
        verified = decoded == 0; /* json.Valid accepts null, scalars and huge numbers. */
        goto record;
    }
    if (initial.status != 401) {
        if (docker_format(&owned_cause, "unexpected HTTP response status %d for '%s'", initial.status, url) != 0) { rc = -1; goto cleanup; }
        cause = owned_cause; goto record;
    }
    const char *challenge = "";
    if (initial.nheaders && !initial.headers) { rc = docker_fail(error, "unsupported: Docker response headers missing"); goto cleanup; }
    for (size_t i = 0; i < initial.nheaders; ++i) {
        if (initial.headers[i].name && !strcasecmp(initial.headers[i].name, "Www-Authenticate")) {
            challenge = initial.headers[i].value ? initial.headers[i].value : ""; break;
        }
    }
    if (!*challenge) goto record;
    int utf8 = docker_utf8((br_slice){(const unsigned char *)challenge, strlen(challenge)});
    if (utf8 != 0) { rc = docker_fail(error, utf8 < 0 ? "cannot validate Docker auth header" : "unsupported: Docker invalid UTF-8 auth header"); goto cleanup; }
    if (strncmp(challenge, "Bearer", 6)) {
        if (docker_format(&owned_cause, "unsupported WWW-Authenticate auth scheme: %s", challenge) != 0) { rc = -1; goto cleanup; }
        cause = owned_cause; goto record;
    }
    int parsed = docker_auth_params(challenge, &realm, &service, &owned_cause);
    if (parsed < 0) { rc = docker_fail(error, "cannot parse Docker auth header"); goto cleanup; }
    if (parsed > 0) { cause = owned_cause; goto record; } /* %w unwraps to this leaf. */
    if (!realm.len) {
        if (docker_format(&owned_cause, "unexpected empty realm for WWW-Authenticate header: %s", challenge) != 0) { rc = -1; goto cleanup; }
        cause = owned_cause; goto record;
    }
    docker_url_kind kind = docker_url_check(docker_slice(&realm), true);
    if (kind == DOCKER_URL_BAD) goto record; /* Auth NewRequest constructor error is false,nil. */
    if (kind == DOCKER_URL_UNSUPPORTED) {
        if (docker_format(&owned_cause, "unsupported: Docker realm URL outside native ASCII http(s) subset") != 0) { rc = -1; goto cleanup; }
        cause = owned_cause; goto record;
    }
    if (docker_challenge_url(docker_slice(&realm), username, docker_slice(&service), &auth_url) != 0) { rc = docker_fail(error, "cannot allocate Docker auth query URL"); goto cleanup; }
    const br_http_request auth_request = {.method = "GET", .url = auth_url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_SANE, .detector_type = 343};
    auth_called = true;
    if (br_http_send(ctx, &auth_request, &auth, &auth_error) != 0) { cause = auth_error ? auth_error : "HTTP transport failed"; goto record; }
    switch (auth.status) {
    case 200: verified = true; break; /* No body/JWT read, including body errors. */
    case 401: case 403: break;
    default:
        if (docker_format(&owned_cause, "unexpected HTTP response status %d for '%s'", auth.status, auth_url) != 0) { rc = -1; goto cleanup; }
        cause = owned_cause; break;
    }
record:
    result->verified = verified;
    /* Redact ONLY the complete normalized configuration, not Raw/user/password.
     * Flat injected errors are already leaves: never strip/classify their text. */
    if (br_result_set_verification_error(result, cause, &normalized, 1) != 0)
        rc = docker_fail(error, "cannot store Docker verification error");
cleanup:
    /* The initial challenge/header remains borrowed through the nested send.
     * Match source's LIFO response lifetimes; native draining/Reader timing is partial. */
    if (auth_called) br_http_release(ctx, &auth);
    if (initial_called) br_http_release(ctx, &initial);
    free(initial_error); free(auth_error); free(owned_cause);
    free(auth_url); free(url); free(realm.data); free(service.data);
    return rc == 0 ? 0 : -1;
}

static int docker_process(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           docker_entry *entry, br_slice normalized, br_results *out, char **error)
{
    (void)detector;
    if (docker_hub(docker_slice(&entry->registry))) {
        static const unsigned char hub[] = "index.docker.io";
        if (docker_set_bytes(&entry->registry, (br_slice){hub, sizeof(hub) - 1}) != 0) return docker_fail(error, "cannot rewrite Docker hub registry");
    }
    if (docker_example(docker_slice(&entry->registry))) return 0;
    br_slice username = {0}, password = {0};
    if (entry->auth.username.len && entry->auth.password.len) {
        username = docker_slice(&entry->auth.username); password = docker_slice(&entry->auth.password);
    }
    br_bytes decoded = {0};
    if (entry->auth.auth.len) {
        int rc = docker_decode_auth(docker_slice(&entry->auth.auth), &decoded);
        if (rc < 0) return docker_fail(error, "cannot decode Docker Base64 auth");
        if (rc == 0) {
            size_t colon = 0; while (colon < decoded.len && decoded.data[colon] != ':') ++colon;
            if (colon < decoded.len) {
                username = (br_slice){decoded.data, colon};
                password = (br_slice){decoded.data + colon + 1, decoded.len - colon - 1};
            }
        } /* Invalid decode and valid decode without colon both preserve explicit fallback. */
    }
    if (!username.len && !password.len) { free(decoded.data); return 0; }
    int utf8 = docker_utf8(username);
    if (utf8 != 0) { free(decoded.data); return docker_fail(error, utf8 < 0 ? "cannot validate Docker username" : "unsupported: Docker invalid UTF-8 username metadata"); }
    char *authorization = NULL;
    int rc = br_http_basic_auth(username, password, &authorization, error);
    if (rc != 0) { free(decoded.data); return -1; }
    br_result result = {0};
    if (docker_result(&result, docker_slice(&entry->registry), username, authorization) != 0)
        rc = docker_fail(error, "cannot create Docker result");
    if (rc == 0 && verify) rc = docker_verify(ctx, docker_slice(&entry->registry), username, authorization, normalized, &result, error);
    if (rc == 0 && br_results_push(out, &result) != 0) rc = docker_fail(error, "cannot append Docker result");
    br_result_clear(&result); free(authorization); free(decoded.data);
    return rc == 0 ? 0 : -1;
}

typedef struct { br_slice input; br_captures *matches; char *error; } docker_matches;

static int docker_collect(void *user, const br_span *groups, size_t ngroups)
{
    docker_matches *matches = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin || groups[0].end > matches->input.len)
        return docker_fail(&matches->error, "invalid Docker full match");
    return br_captures_push(matches->matches, (br_slice){matches->input.data + groups[0].begin, groups[0].end - groups[0].begin}, true, &matches->error);
}

static int docker_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    /* AddLogger(nil) dereferences the source context before even an empty/NoV
     * scan. Explicit unsupported fatal is safer than inventing a background context. */
    if (!ctx) return docker_fail(error, "unsupported: Docker nil context panics in source AddLogger");
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return docker_fail(error, "invalid or uninitialized Docker scan");
    size_t original_len = out->len;
    br_captures unique = {0}; docker_matches matches = {input, &unique, NULL};
    char *owned_error = NULL;
    int rc = br_regex_each(detector->state, input, docker_collect, &matches, &owned_error);
    if (matches.error) { free(owned_error); owned_error = matches.error; }
    if (rc != 0) rc = -1;
    /* Deduplicate ORIGINAL matches before normalization. Source map order is
     * unspecified; first-seen iteration is one permitted traversal. */
    for (size_t i = 0; rc == 0 && i < unique.len; ++i) {
        br_bytes normalized = {0}; docker_auths auths = {0};
        if (docker_normalize(br_captures_at(&unique, i), &normalized) != 0)
            rc = docker_fail(&owned_error, "cannot normalize Docker config");
        else {
            rc = docker_decode(docker_slice(&normalized), &auths);
            if (rc != 0) {
                if (auths.cause) { owned_error = auths.cause; auths.cause = NULL; }
                else rc = docker_fail(&owned_error, "cannot decode Docker config resources");
            }
        }
        for (size_t r = 0; rc == 0 && r < auths.len; ++r)
            rc = docker_process(detector, ctx, verify, &auths.items[r], docker_slice(&normalized), out, &owned_error);
        free(auths.cause); docker_entries_clear(&auths); free(normalized.data);
    }
    /* IMPORTANT: ordinary config Decode returns accumulated findings PLUS its
     * cause (+1). Only provider-own/resource/unsupported failures (-1) roll back
     * this invocation. Engine handling of partial decode results needs integration. */
    if (rc < 0) {
        if (!owned_error) docker_fail(&owned_error, "cannot allocate Docker detector resources");
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    }
    br_captures_clear(&unique);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc < 0 ? -1 : rc;
}

static const char *const docker_keywords[] = {"\"auths\"", "\\\"auths\\"};
static br_detector docker_detector = {
    .type = 343, .version = 0, .name = "Docker", .custom_name = "",
    .description = "Docker credentials can be used to pull images from private registries.",
    .keywords = docker_keywords, .nkeywords = 2,
    .max_secret_size = 4096, .start_offset = -1, .max_credential_span = -1,
    .scan = docker_scan,
};

int br_docker_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return docker_fail(error, "invalid Docker detector output");
    *out = NULL;
    if (!docker_detector.state) {
        /* RE2 Perl \\s excludes VT. Keep that exact private ASCII class rather
         * than PCRE2 \\s/POSIX space, which would match extra source separators. */
        static const char pattern[] =
            "{(?:[\\t\\n\\f\\r ]|\\\\+[nrt])*\\\\*\"auths\\\\*\"(?:[\\t\\n\\f\\r ]|\\\\+t)*:"
            "(?:[\\t\\n\\f\\r ]|\\\\+t)*{(?:[\\t\\n\\f\\r ]|\\\\+[nrt])*\\\\*\""
            "(?i:https?://)?[a-z0-9\\-.:/]+\\\\*\"(?:[\\t\\n\\f\\r ]|\\\\+t)*:"
            "(?:[\\t\\n\\f\\r ]|\\\\+t)*{(?:(?:[\\t\\n\\f\\r ]|\\\\+[nrt])*\\\\*\""
            "(?i:auth|email|username|password)\\\\*\"[\\t\\n\\f\\r ]*:[\\t\\n\\f\\r ]*\\\\*\".*?\\\\*\"[\\t\\n\\f\\r ]*,?)+?"
            "(?:[\\t\\n\\f\\r ]|\\\\+[nrt])*}(?:[\\t\\n\\f\\r ]|\\\\+[nrt])*}(?:[\\t\\n\\f\\r ]|\\\\+[nrt])*}";
        br_regex *compiled = NULL;
        if (br_regex_compile(pattern, &compiled, error) != 0) return -1;
        docker_detector.state = compiled;
    }
    *out = &docker_detector;
    return 0;
}
