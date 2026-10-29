/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected Go1.26.7 net/url and net/netip parsing/escaping projection.
 * Copyright 2009, 2021, 2025 The Go Authors. BSD-3-Clause-Go.txt applies. */
#include "go_url.h"

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

static size_t find(br_slice s, unsigned char c)
{
    if (!s.len) return SIZE_MAX;
    const unsigned char *p = memchr(s.data, c, s.len);
    return p ? (size_t)(p - s.data) : SIZE_MAX;
}

static size_t last(br_slice s, unsigned char c)
{
    for (size_t i = s.len; i; --i) if (s.data[i - 1] == c) return i - 1;
    return SIZE_MAX;
}

static bool starts(br_slice s, const char *prefix)
{
    size_t n = strlen(prefix);
    return s.len >= n && !memcmp(s.data, prefix, n);
}

static int hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool br_go_url_byte_allowed(unsigned char c, br_go_url_encoding mode)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || (c && strchr("-._~", c))) return true;
    if (!c) return false;
    switch (mode) {
    case BR_GO_URL_HOST: case BR_GO_URL_ZONE: return strchr("!\"$&'()*+,:;<=>[]", c) != NULL;
    case BR_GO_URL_USER: return strchr("$&+,;=", c) != NULL;
    case BR_GO_URL_PATH: return strchr("$&+,/:;=@", c) != NULL;
    case BR_GO_URL_FRAGMENT: return strchr("!$&()*+,/:;=?@", c) != NULL;
    }
    return false;
}

static int reject(br_go_url_error *error, br_go_url_error_kind kind, br_slice detail)
{
    *error = (br_go_url_error){kind, detail};
    return 1;
}

static bool escapes_valid(br_slice s, br_go_url_encoding mode, br_go_url_error *error)
{
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (c == '%') {
            size_t left = s.len - i;
            if (left < 3 || hex(s.data[i + 1]) < 0 || hex(s.data[i + 2]) < 0) {
                reject(error, BR_GO_URL_ESCAPE, part(s, i, left < 3 ? left : 3)); return false;
            }
            unsigned char value = (unsigned char)((hex(s.data[i + 1]) << 4) | hex(s.data[i + 2]));
            bool percent = s.data[i + 1] == '2' && s.data[i + 2] == '5';
            if ((mode == BR_GO_URL_HOST && value < 128 && !percent) ||
                (mode == BR_GO_URL_ZONE && !percent && value != ' ' && !br_go_url_byte_allowed(value, BR_GO_URL_HOST))) {
                reject(error, BR_GO_URL_ESCAPE, part(s, i, 3)); return false;
            }
            i += 2;
        } else if ((mode == BR_GO_URL_HOST || mode == BR_GO_URL_ZONE) && c < 128 && !br_go_url_byte_allowed(c, mode)) {
            reject(error, BR_GO_URL_HOST_CHAR, part(s, i, 1)); return false;
        }
    }
    return true;
}

static unsigned char decoded(br_slice s, size_t *at, bool query)
{
    unsigned char c = s.data[(*at)++];
    if (c == '%') {
        c = (unsigned char)((hex(s.data[*at]) << 4) | hex(s.data[*at + 1])); *at += 2;
    } else if (c == '+' && query) c = ' ';
    return c;
}

static int decode_valid(br_slice s, bool query, br_bytes *out)
{
    if (!s.len) return 0;
    if (s.len == SIZE_MAX || !(out->data = malloc(s.len + 1))) return -1;
    for (size_t at = 0; at < s.len;) out->data[out->len++] = decoded(s, &at, query);
    out->data[out->len] = 0;
    return 0;
}

int br_go_url_decode(br_slice s, bool query, br_bytes *out, bool *valid, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!out || !valid || (!s.data && s.len)) return fail(fatal, "invalid URL decode arguments");
    *out = (br_bytes){0}; *valid = false;
    br_go_url_error ordinary = {0};
    if (!escapes_valid(s, BR_GO_URL_PATH, &ordinary)) return 0;
    if (decode_valid(s, query, out) != 0) return fail(fatal, "cannot decode URL bytes");
    *valid = true; return 0;
}

static int host_decode(br_slice raw, br_go_url_parts *out)
{
    out->host = raw;
    if (find(raw, '%') == SIZE_MAX) return 0;
    if (decode_valid(raw, false, &out->host_storage) != 0) return -1;
    out->host = (br_slice){out->host_storage.data, out->host_storage.len};
    return 0;
}

static bool valid_port(br_slice port)
{
    if (!port.len) return true;
    if (port.data[0] != ':') return false;
    for (size_t i = 1; i < port.len; ++i) if (port.data[i] < '0' || port.data[i] > '9') return false;
    return true;
}

static bool ipv4(br_slice s)
{
    unsigned value = 0, digits = 0, fields = 0;
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (c >= '0' && c <= '9') {
            if (digits == 1 && !value) return false;
            value = value * 10 + c - '0';
            if (++digits > 3 || value > 255) return false;
        } else if (c == '.') {
            if (!digits || ++fields > 3) return false;
            value = digits = 0;
        } else return false;
    }
    return fields == 3 && digits != 0;
}

static bool ipv6(br_slice input)
{
    size_t zone = find(input, '%');
    if (zone != SIZE_MAX) {
        if (zone + 1 == input.len) return false;
        input.len = zone;
    }
    bool ellipsis = starts(input, "::");
    br_slice s = ellipsis ? part(input, 2, input.len - 2) : input;
    if (ellipsis && !s.len) return true;
    unsigned bytes = 0;
    while (bytes < 16) {
        size_t n = 0;
        while (n < s.len && hex(s.data[n]) >= 0) if (++n > 4) return false;
        if (!n) return false;
        if (n < s.len && s.data[n] == '.') {
            if ((!ellipsis && bytes != 12) || bytes + 4 > 16 || !ipv4(s)) return false;
            bytes += 4; s.len = 0; break;
        }
        bytes += 2; s = part(s, n, s.len - n);
        if (!s.len) break;
        if (s.data[0] != ':' || s.len == 1) return false;
        s = part(s, 1, s.len - 1);
        if (s.data[0] == ':') {
            if (ellipsis) return false;
            ellipsis = true; s = part(s, 1, s.len - 1);
            if (!s.len) break;
        }
    }
    return !s.len && (bytes < 16 ? ellipsis : !ellipsis);
}

static int parse_host(br_slice raw, br_go_url_parts *out, br_go_url_error *error)
{
    size_t open = last(raw, '[');
    if (open != SIZE_MAX && open > 0) return reject(error, BR_GO_URL_IP_LITERAL, (br_slice){0});
    if (open == 0) {
        size_t close = last(raw, ']');
        if (close == SIZE_MAX) return reject(error, BR_GO_URL_BRACKET, (br_slice){0});
        br_slice port = part(raw, close + 1, raw.len - close - 1);
        if (!valid_port(port)) return reject(error, BR_GO_URL_PORT, port);
        if (!escapes_valid(port, BR_GO_URL_HOST, error)) return 1;
        br_slice hostname = part(raw, 1, close - 1);
        size_t zone = br_slice_find(hostname, (br_slice){(const unsigned char *)"%25", 3}, 0);
        if (zone != SIZE_MAX) {
            if (!escapes_valid(part(hostname, 0, zone), BR_GO_URL_HOST, error) ||
                !escapes_valid(part(hostname, zone, hostname.len - zone), BR_GO_URL_ZONE, error)) return 1;
        } else if (!escapes_valid(hostname, BR_GO_URL_HOST, error)) return 1;
        if (host_decode(raw, out) != 0) return -1;
        close = last(out->host, ']');
        if (close == SIZE_MAX || close == 0) return -1;
        hostname = part(out->host, 1, close - 1);
        if (ipv4(hostname)) return reject(error, BR_GO_URL_IP_LITERAL, (br_slice){0});
        if (!ipv6(hostname)) return reject(error, BR_GO_URL_IP_DIAGNOSTIC, hostname);
        return 0;
    }
    size_t colon = last(raw, ':');
    /* The selected binary fixes urlstrictcolons=0; no numeric port-range cap. */
    if (colon != SIZE_MAX && !valid_port(part(raw, colon, raw.len - colon)))
        return reject(error, BR_GO_URL_PORT, part(raw, colon, raw.len - colon));
    if (!escapes_valid(raw, BR_GO_URL_HOST, error)) return 1;
    return host_decode(raw, out) == 0 ? 0 : -1;
}

static bool valid_user(br_slice s)
{
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) continue;
        if (!c || !strchr("-._:~!$&'()*+,;=%@", c)) return false;
    }
    return true;
}

static int parse(br_slice raw, br_go_url_parts *out, br_go_url_error *error)
{
    size_t hash = find(raw, '#');
    br_slice rest = hash == SIZE_MAX ? raw : part(raw, 0, hash);
    out->raw_fragment = hash == SIZE_MAX ? (br_slice){0} : part(raw, hash + 1, raw.len - hash - 1);
    for (size_t i = 0; i < rest.len; ++i)
        if (rest.data[i] < ' ' || rest.data[i] == 127) return reject(error, BR_GO_URL_CONTROL, (br_slice){0});
    bool scheme = false;
    for (size_t i = 0; i < rest.len; ++i) {
        unsigned char c = rest.data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) continue;
        if ((c >= '0' && c <= '9') || (c && strchr("+-.", c))) { if (!i) break; continue; }
        if (c == ':') {
            if (!i) return reject(error, BR_GO_URL_SCHEME, (br_slice){0});
            scheme = true; rest = part(rest, i + 1, rest.len - i - 1);
        }
        break;
    }
    size_t question = find(rest, '?');
    if (question != SIZE_MAX) {
        out->force_query = question + 1 == rest.len;
        out->raw_query = part(rest, question + 1, rest.len - question - 1); rest.len = question;
    }
    if (!starts(rest, "/")) {
        if (scheme) return escapes_valid(out->raw_fragment, BR_GO_URL_FRAGMENT, error) ? 0 : 1;
        size_t slash = find(rest, '/');
        if (find(part(rest, 0, slash == SIZE_MAX ? rest.len : slash), ':') != SIZE_MAX)
            return reject(error, BR_GO_URL_COLON, (br_slice){0});
    }
    if (starts(rest, "//") && (scheme || !starts(rest, "///"))) {
        br_slice authority = part(rest, 2, rest.len - 2);
        size_t slash = find(authority, '/');
        rest = slash == SIZE_MAX ? (br_slice){0} : part(authority, slash, authority.len - slash);
        authority.len = slash == SIZE_MAX ? authority.len : slash;
        size_t at = last(authority, '@');
        br_slice host = at == SIZE_MAX ? authority : part(authority, at + 1, authority.len - at - 1);
        int rc = parse_host(host, out, error); if (rc) return rc;
        if (at != SIZE_MAX) {
            br_slice userinfo = part(authority, 0, at);
            if (!valid_user(userinfo)) return reject(error, BR_GO_URL_BAD_USER, (br_slice){0});
            size_t colon = find(userinfo, ':');
            out->has_user = true; out->has_password = colon != SIZE_MAX;
            out->raw_user = part(userinfo, 0, colon == SIZE_MAX ? userinfo.len : colon);
            out->raw_password = colon == SIZE_MAX ? (br_slice){0} : part(userinfo, colon + 1, userinfo.len - colon - 1);
            if (!escapes_valid(out->raw_user, BR_GO_URL_USER, error) || !escapes_valid(out->raw_password, BR_GO_URL_USER, error)) return 1;
        }
    }
    out->raw_path = rest;
    return escapes_valid(out->raw_path, BR_GO_URL_PATH, error) &&
        escapes_valid(out->raw_fragment, BR_GO_URL_FRAGMENT, error) ? 0 : 1;
}

void br_go_url_clear(br_go_url_parts *out)
{
    if (!out) return;
    free(out->host_storage.data); *out = (br_go_url_parts){0};
}

int br_go_url_parse(br_slice input, br_go_url_parts *out, br_go_url_error *rejection, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!out || !rejection || (!input.data && input.len)) return fail(fatal, "invalid URL parse arguments");
    *out = (br_go_url_parts){0}; *rejection = (br_go_url_error){0};
    if (parse(input, out, rejection) >= 0) return 0;
    br_go_url_clear(out); return fail(fatal, "cannot parse URL bytes");
}

static bool decoded_equal(br_slice raw, br_slice key)
{
    size_t at = 0, i = 0;
    while (at < raw.len) {
        unsigned char c = decoded(raw, &at, true);
        if (i == key.len || c != key.data[i++]) return false;
    }
    return i == key.len;
}

int br_go_url_query_get(br_slice query, br_slice key, br_bytes *out, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!out || (!query.data && query.len) || (!key.data && key.len)) return fail(fatal, "invalid URL query arguments");
    *out = (br_bytes){0};
    size_t segments = 1;
    for (size_t i = 0; i < query.len; ++i) if (query.data[i] == '&' && ++segments > 10000) return 0;
    bool found = false;
    for (size_t at = 0; at < query.len;) {
        br_slice tail = part(query, at, query.len - at);
        size_t amp = find(tail, '&');
        br_slice pair = part(tail, 0, amp == SIZE_MAX ? tail.len : amp);
        at += pair.len + (amp != SIZE_MAX);
        if (!pair.len || find(pair, ';') != SIZE_MAX) continue;
        size_t equal = find(pair, '=');
        br_slice name = part(pair, 0, equal == SIZE_MAX ? pair.len : equal);
        br_slice value = equal == SIZE_MAX ? (br_slice){0} : part(pair, equal + 1, pair.len - equal - 1);
        br_go_url_error ordinary = {0};
        if (!escapes_valid(name, BR_GO_URL_PATH, &ordinary) || !escapes_valid(value, BR_GO_URL_PATH, &ordinary)) continue;
        if (!found && decoded_equal(name, key)) {
            if (decode_valid(value, true, out) != 0) return fail(fatal, "cannot decode URL query value");
            found = true;
        }
    }
    return 0;
}
