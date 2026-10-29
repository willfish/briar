/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected Go1.26.7 net/url.String escaping, LDAP authority shapes only.
 * Copyright 2009 The Go Authors. BSD-3-Clause-Go.txt applies. */
#include "ldap_private.h"
#include "../go_url.h"
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned char *data; size_t len; bool overflow; } writer;

static int fail(char **fatal, const char *message)
{
    if (fatal) *fatal = strdup(message);
    return -1;
}

static void put(writer *out, unsigned char c)
{
    if (out->len == SIZE_MAX) { out->overflow = true; return; }
    if (out->data) out->data[out->len] = c;
    ++out->len;
}

static void put_slice(writer *out, br_slice s)
{
    for (size_t i = 0; i < s.len; ++i) put(out, s.data[i]);
}

static unsigned hex(unsigned char c)
{
    return c <= '9' ? c - '0' : c <= 'F' ? c - 'A' + 10 : c - 'a' + 10;
}

static void escaped(writer *out, br_slice raw, br_go_url_encoding mode, bool decode)
{
    static const unsigned char digits[] = "0123456789ABCDEF";
    for (size_t at = 0; at < raw.len;) {
        unsigned char c = raw.data[at++];
        if (decode && c == '%') {
            /* Parse already validated every escape in these components. */
            c = (unsigned char)((hex(raw.data[at]) << 4) | hex(raw.data[at + 1]));
            at += 2;
        }
        if (br_go_url_byte_allowed(c, mode)) put(out, c);
        else { put(out, '%'); put(out, digits[c >> 4]); put(out, digits[c & 15]); }
    }
}

static bool valid_encoded(br_slice raw, br_go_url_encoding mode)
{
    for (size_t i = 0; i < raw.len; ++i) {
        unsigned char c = raw.data[i];
        if (c && strchr("!$&'()*+,;=:@[]%", c)) continue;
        if (!br_go_url_byte_allowed(c, mode)) return false;
    }
    return true;
}

static void write_url(writer *out, const char *scheme, const br_go_url_parts *p)
{
    put_slice(out, (br_slice){(const unsigned char *)scheme, strlen(scheme)});
    if (p->host.len || p->raw_path.len || p->has_user) {
        put(out, '/'); put(out, '/');
        if (p->has_user) {
            escaped(out, p->raw_user, BR_GO_URL_USER, true);
            if (p->has_password) { put(out, ':'); escaped(out, p->raw_password, BR_GO_URL_USER, true); }
            put(out, '@');
        }
        escaped(out, p->host, BR_GO_URL_HOST, false);
    }
    if (p->raw_path.len && p->raw_path.data[0] != '/' && p->host.len) put(out, '/');
    if (valid_encoded(p->raw_path, BR_GO_URL_PATH)) put_slice(out, p->raw_path);
    else escaped(out, p->raw_path, BR_GO_URL_PATH, true);
    if (p->force_query || p->raw_query.len) { put(out, '?'); put_slice(out, p->raw_query); }
    if (p->raw_fragment.len) {
        put(out, '#');
        if (valid_encoded(p->raw_fragment, BR_GO_URL_FRAGMENT)) put_slice(out, p->raw_fragment);
        else escaped(out, p->raw_fragment, BR_GO_URL_FRAGMENT, true);
    }
}

static const char *ldap_scheme(br_slice input)
{
    static const unsigned char prefix[] = "ldap";
    if (input.len < 7) return NULL;
    for (size_t i = 0; i < 4; ++i) {
        unsigned char c = input.data[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != prefix[i]) return NULL;
    }
    if (!memcmp(input.data + 4, "://", 3)) return "ldap:";
    if (input.len >= 8 && (input.data[4] == 's' || input.data[4] == 'S') &&
        !memcmp(input.data + 5, "://", 3)) return "ldaps:";
    return NULL;
}

int br_ldap_url_string(br_slice input, br_bytes *out, bool *accepted, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (out) *out = (br_bytes){0};
    if (accepted) *accepted = false;
    if (!out || !accepted || (!input.data && input.len))
        return fail(fatal, "invalid LDAP URL projection arguments");
    br_go_url_parts parts = {0}; br_go_url_error rejection = {0};
    int rc = br_go_url_parse(input, &parts, &rejection, fatal);
    if (rc != 0) { br_go_url_clear(&parts); return rc; }
    if (rejection.kind != BR_GO_URL_OK) { br_go_url_clear(&parts); return 0; }
    const char *scheme = ldap_scheme(input);
    if (!scheme) { br_go_url_clear(&parts); return fail(fatal, "unsupported: non-authority LDAP URL projection"); }
    writer measure = {0}; write_url(&measure, scheme, &parts);
    if (measure.overflow || measure.len == SIZE_MAX) {
        br_go_url_clear(&parts); return fail(fatal, "LDAP URL projection too large");
    }
    unsigned char *data = malloc(measure.len + 1);
    if (!data) { br_go_url_clear(&parts); return fail(fatal, "cannot construct LDAP URL projection"); }
    writer value = {.data = data}; write_url(&value, scheme, &parts);
    data[value.len] = 0;
    *out = (br_bytes){data, value.len}; *accepted = true;
    br_go_url_clear(&parts);
    return 0;
}
