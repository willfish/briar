/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog's Jira helpers and selected Go 1.26.7 URL.String,
 * net/http constructor and Client.Do rules. Go copyright 2009, 2021, 2025
 * The Go Authors; see LICENSES/BSD-3-Clause-Go.txt. */
#include "jiratoken_url.h"
#include "../go_url.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static br_slice part(br_slice s, size_t at, size_t len)
{
    return (br_slice){s.data ? s.data + at : NULL, len};
}

static bool contains(br_slice s, const char *text)
{
    return br_slice_find(s, (br_slice){(const unsigned char *)text, strlen(text)}, 0) != SIZE_MAX;
}

static unsigned hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return c - 'a' + 10;
}

static unsigned char decoded_byte(br_slice s, size_t *at)
{
    unsigned char c = s.data[(*at)++];
    if (c == '%') {
        c = (unsigned char)((hex(s.data[*at]) << 4) | hex(s.data[*at + 1])); *at += 2;
    }
    return c;
}

static bool decoded_contains_no_host(br_slice s)
{
    static const char needle[] = "no such host";
    size_t matched = 0;
    for (size_t at = 0; at < s.len;) {
        unsigned char c = decoded_byte(s, &at);
        if (c == (unsigned char)needle[matched]) {
            if (++matched == sizeof(needle) - 1) return true;
        } else matched = c == (unsigned char)needle[0] ? 1 : 0;
    }
    return false;
}

static br_slice trim_space(br_slice s)
{
    size_t begin = 0, end = 0;
    for (size_t at = 0; at < s.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune(part(s, at, s.len - at), &rune);
        if (!width) { width = 1; rune = 0xfffd; }
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) end = at + width;
        else if (at == begin) begin += width;
        at += width;
    }
    if (end < begin) end = begin;
    return part(s, begin, end - begin);
}

static int copy_bytes(br_slice s, br_bytes *out)
{
    if (s.len == SIZE_MAX || !(out->data = malloc(s.len + 1))) return -1;
    if (s.len) memcpy(out->data, s.data, s.len);
    out->data[s.len] = 0; out->len = s.len;
    return 0;
}

int br_jiratoken_endpoint_host(br_slice endpoint, br_bytes *host, char **error)
{
    if (error) *error = NULL;
    if (!host || (!endpoint.data && endpoint.len)) return fail(error, "invalid Jira endpoint arguments");
    *host = (br_bytes){0};
    endpoint = trim_space(endpoint);
    if (endpoint.len && endpoint.data[endpoint.len - 1] == '/') --endpoint.len;
    br_go_url_parts parsed = {0}; br_go_url_error ordinary = {0};
    int rc = br_go_url_parse(endpoint, &parsed, &ordinary, error);
    if (rc == 0) {
        if (ordinary.kind == BR_GO_URL_OK && parsed.host.len && parsed.host_storage.data) {
            *host = parsed.host_storage; parsed.host_storage = (br_bytes){0};
        } else if (copy_bytes(ordinary.kind == BR_GO_URL_OK && parsed.host.len ? parsed.host : endpoint, host) != 0)
            rc = fail(error, "cannot project Jira endpoint host");
    }
    br_go_url_clear(&parsed);
    return rc == 0 ? 0 : -1;
}

typedef struct {
    unsigned char *data;
    br_slice original;
    size_t len;
    bool equal, overflow;
} writer;

static void put(writer *out, unsigned char c)
{
    if (out->len == SIZE_MAX) { out->overflow = true; return; }
    if (out->len >= out->original.len || c != out->original.data[out->len]) out->equal = false;
    if (out->data) out->data[out->len] = c;
    ++out->len;
}

static void put_slice(writer *out, br_slice s)
{
    for (size_t i = 0; i < s.len; ++i) put(out, s.data[i]);
}

static void escaped_write(writer *out, br_slice raw, br_go_url_encoding mode, bool decode)
{
    static const unsigned char digits[] = "0123456789ABCDEF";
    for (size_t at = 0; at < raw.len;) {
        unsigned char c = decode ? decoded_byte(raw, &at) : raw.data[at++];
        if (br_go_url_byte_allowed(c, mode)) put(out, c);
        else { put(out, '%'); put(out, digits[c >> 4]); put(out, digits[c & 15]); }
    }
}

static bool valid_encoded(br_slice s, br_go_url_encoding mode)
{
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (c && strchr("!$&'()*+,;=:@[]%", c)) continue;
        if (!br_go_url_byte_allowed(c, mode)) return false;
    }
    return true;
}

static void write_target(writer *out, const br_go_url_parts *p)
{
    put_slice(out, (br_slice){(const unsigned char *)"https:", 6});
    br_slice host = p->host;
    if (host.len && host.data[host.len - 1] == ':') --host.len;
    if (host.len || p->raw_path.len || p->has_user) {
        put(out, '/'); put(out, '/');
        if (p->has_user) {
            escaped_write(out, p->raw_user, BR_GO_URL_USER, true);
            if (p->has_password) { put(out, ':'); escaped_write(out, p->raw_password, BR_GO_URL_USER, true); }
            put(out, '@');
        }
        escaped_write(out, host, BR_GO_URL_HOST, false);
    }
    if (p->raw_path.len && p->raw_path.data[0] != '/' && host.len) put(out, '/');
    if (valid_encoded(p->raw_path, BR_GO_URL_PATH)) put_slice(out, p->raw_path);
    else escaped_write(out, p->raw_path, BR_GO_URL_PATH, true);
    if (p->force_query || p->raw_query.len) { put(out, '?'); put_slice(out, p->raw_query); }
    if (p->raw_fragment.len) {
        put(out, '#');
        if (valid_encoded(p->raw_fragment, BR_GO_URL_FRAGMENT)) put_slice(out, p->raw_fragment);
        else escaped_write(out, p->raw_fragment, BR_GO_URL_FRAGMENT, true);
    }
}

static int constructor_cause(br_go_url_error ordinary, char **cause, char **error)
{
    const char *literal = NULL, *prefix = NULL, *suffix = "";
    switch (ordinary.kind) {
    case BR_GO_URL_CONTROL: literal = "net/url: invalid control character in URL"; break;
    case BR_GO_URL_SCHEME: literal = "missing protocol scheme"; break;
    case BR_GO_URL_COLON: literal = "first path segment in URL cannot contain colon"; break;
    case BR_GO_URL_BAD_USER: literal = "net/url: invalid userinfo"; break;
    case BR_GO_URL_BRACKET: literal = "missing ']' in host"; break;
    case BR_GO_URL_IP_LITERAL: literal = "invalid IP-literal"; break;
    case BR_GO_URL_ESCAPE: prefix = "invalid URL escape "; break;
    case BR_GO_URL_HOST_CHAR: prefix = "invalid character "; suffix = " in host name"; break;
    case BR_GO_URL_PORT: prefix = "invalid port "; suffix = " after host"; break;
    case BR_GO_URL_IP_DIAGNOSTIC: return fail(error, "unsupported: Jira invalid-IP diagnostic projection");
    case BR_GO_URL_OK: return fail(error, "invalid Jira constructor outcome");
    }
    if (literal) {
        *cause = strdup(literal);
        return *cause ? 0 : fail(error, "cannot construct Jira URL cause");
    }
    size_t n = strlen(prefix) + strlen(suffix) + 2;
    for (size_t i = 0; i < ordinary.detail.len; ++i) {
        unsigned char c = ordinary.detail.data[i]; uint32_t rune;
        if (c >= 128 && br_utf8_rune(part(ordinary.detail, i, ordinary.detail.len - i), &rune))
            return fail(error, "unsupported: Jira non-ASCII URL diagnostic quoting");
        size_t width = c >= 128 || c < 32 || c == 127 ? 4 : c == '"' || c == '\\' ? 2 : 1;
        if (c && strchr("\a\b\f\n\r\t\v", c)) width = 2;
        if (n > SIZE_MAX - width) return fail(error, "Jira URL cause too large");
        n += width;
    }
    if (n == SIZE_MAX || !(*cause = malloc(n + 1))) return fail(error, "cannot construct Jira URL cause");
    char *at = *cause; size_t length = strlen(prefix);
    memcpy(at, prefix, length); at += length; *at++ = '"';
    static const char controls[] = "\a\b\f\n\r\t\v", names[] = "abfnrtv", digits[] = "0123456789abcdef";
    for (size_t i = 0; i < ordinary.detail.len; ++i) {
        unsigned char c = ordinary.detail.data[i]; const char *named = c ? strchr(controls, c) : NULL;
        if (named) { *at++ = '\\'; *at++ = names[named - controls]; }
        else if (c < 32 || c >= 127) { *at++ = '\\'; *at++ = 'x'; *at++ = digits[c >> 4]; *at++ = digits[c & 15]; }
        else { if (c == '"' || c == '\\') *at++ = '\\'; *at++ = (char)c; }
    }
    *at++ = '"'; length = strlen(suffix); memcpy(at, suffix, length); at += length; *at = 0;
    return 0;
}

void br_jiratoken_target_clear(br_jiratoken_target *target)
{
    if (!target) return;
    free(target->original.data); free(target->projected.data); free(target->cause);
    *target = (br_jiratoken_target){0};
}

int br_jiratoken_target_init(br_slice host, bool context_present,
                            br_jiratoken_target *out, char **error)
{
    static const char prefix[] = "https://", suffix[] = "/gateway/api/graphql";
    if (error) *error = NULL;
    if (!out || (!host.data && host.len)) return fail(error, "invalid Jira request URL arguments");
    *out = (br_jiratoken_target){0};
    const size_t fixed = sizeof(prefix) - 1 + sizeof(suffix);
    if (host.len > SIZE_MAX - fixed || !(out->original.data = malloc(fixed + host.len)))
        return fail(error, "cannot construct Jira original URL");
    memcpy(out->original.data, prefix, sizeof(prefix) - 1);
    if (host.len) memcpy(out->original.data + sizeof(prefix) - 1, host.data, host.len);
    memcpy(out->original.data + sizeof(prefix) - 1 + host.len, suffix, sizeof(suffix));
    out->original.len = fixed + host.len - 1;
    int rc = 0;
    br_go_url_parts parsed = {0}; br_go_url_error ordinary = {0};
    if (!context_present) {
        out->cause = strdup("net/http: nil Context");
        if (!out->cause) rc = fail(error, "cannot construct Jira nil-context cause");
    } else {
        br_slice original = {out->original.data, out->original.len};
        rc = br_go_url_parse(original, &parsed, &ordinary, error);
        if (rc == 0 && ordinary.kind != BR_GO_URL_OK) rc = constructor_cause(ordinary, &out->cause, error);
        else if (rc == 0) {
            writer measure = {.original = original, .equal = true}; write_target(&measure, &parsed);
            if (measure.overflow || measure.len == SIZE_MAX) rc = fail(error, "Jira projected URL too large");
            else if (measure.equal && measure.len == original.len) out->url = (const char *)original.data;
            else {
                out->projected.data = malloc(measure.len + 1);
                if (!out->projected.data) rc = fail(error, "cannot project Jira request URL");
                else {
                    writer result = {.data = out->projected.data, .original = original};
                    write_target(&result, &parsed); out->projected.len = result.len;
                    out->projected.data[result.len] = 0; out->url = (const char *)out->projected.data;
                }
            }
            if (rc == 0) {
                /* stripPassword reinserts DECODED username when passwordSet.
                 * RawQuery is the other source of this exact spaced phrase. */
                out->error_url_has_no_host = contains(parsed.raw_query, "no such host") ||
                    (parsed.has_password && decoded_contains_no_host(parsed.raw_user));
            }
        }
    }
    br_go_url_clear(&parsed);
    if (rc != 0) br_jiratoken_target_clear(out);
    return rc == 0 ? 0 : -1;
}
