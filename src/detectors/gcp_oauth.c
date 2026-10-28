/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected golang.org/x/oauth2 v0.34.0 byte codecs, BSD-3-Clause.
 * See NOTICE and LICENSES/BSD-3-Clause-Go.txt. */
#include "gcp_oauth.h"

#include <stdlib.h>
#include <string.h>

static int oauth_fail(char **fatal, const char *message)
{
    if (fatal) *fatal = strdup(message);
    return -1;
}

void br_gcp_oauth_error_clear(br_gcp_oauth_error *error)
{
    if (!error) return;
    free(error->text.data); free(error->leaf.data); *error = (br_gcp_oauth_error){0};
}

static bool query_safe(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
}

static int query_size(br_slice value, size_t *size, char **fatal)
{
    if (!value.data && value.len) return oauth_fail(fatal, "invalid Google OAuth form value");
    for (size_t i = 0; i < value.len; ++i) {
        size_t n = query_safe(value.data[i]) || value.data[i] == ' ' ? 1 : 3;
        if (*size > SIZE_MAX - n - 1) return oauth_fail(fatal, "Google OAuth form is too large");
        *size += n;
    }
    return 0;
}

static unsigned char *query_write(unsigned char *out, br_slice value)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        if (query_safe(c)) *out++ = c;
        else if (c == ' ') *out++ = '+';
        else { *out++ = '%'; *out++ = (unsigned char)hex[c >> 4]; *out++ = (unsigned char)hex[c & 15]; }
    }
    return out;
}

int br_gcp_oauth_form(const br_gcp_oauth_pair *fields, size_t count, br_bytes *out, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!out || (!fields && count)) return oauth_fail(fatal, "invalid Google OAuth form");
    *out = (br_bytes){0}; size_t size = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!fields[i].name) return oauth_fail(fatal, "invalid Google OAuth form field");
        size_t delimiters = i ? 2 : 1;
        if (size > SIZE_MAX - delimiters - 1) return oauth_fail(fatal, "Google OAuth form is too large");
        size += delimiters;
        if (query_size((br_slice){(const unsigned char *)fields[i].name, strlen(fields[i].name)}, &size, fatal) ||
            query_size(fields[i].value, &size, fatal)) return -1;
    }
    unsigned char *data = malloc(size + 1);
    if (!data) return oauth_fail(fatal, "cannot allocate Google OAuth form");
    unsigned char *at = data;
    for (size_t i = 0; i < count; ++i) {
        if (i) *at++ = '&';
        at = query_write(at, (br_slice){(const unsigned char *)fields[i].name, strlen(fields[i].name)});
        *at++ = '='; at = query_write(at, fields[i].value);
    }
    *at = 0; *out = (br_bytes){data, size}; return 0;
}

int br_gcp_oauth_read(const br_gcp_oauth_io *io, void *user, br_gcp_oauth_response *response,
                      br_bytes *body, br_gcp_oauth_error *error, char **fatal)
{
    const size_t limit = (size_t)1 << 20;
    if (fatal) *fatal = NULL;
    if (!io || !io->read || !response || !body || !error)
        return oauth_fail(fatal, "invalid Google OAuth response reader");
    *body = (br_bytes){0}; *error = (br_gcp_oauth_error){0};
    /* Preserve the selected byte/error/limit semantics, not Go allocator sizes
     * or Reader-call timing. The buffer is the owned result, not heap staging. */
    size_t capacity = 512;
    body->data = malloc(capacity + 1);
    if (!body->data) return oauth_fail(fatal, "cannot allocate Google OAuth response");
    for (;;) {
        size_t n = 0;
        int rc = io->read(user, response, body->data + body->len, capacity - body->len, &n, error);
        if (n > capacity - body->len) return oauth_fail(fatal, "invalid Google OAuth response read length");
        body->len += n; body->data[body->len] = 0;
        if (rc < 0) return oauth_fail(fatal, "Google OAuth response reader failed fatally");
        if (rc > 0) return 1;
        if (!n || body->len == limit) return 0;
        if (body->len == capacity) {
            size_t next = capacity > limit / 2 ? limit : capacity * 2;
            unsigned char *data = realloc(body->data, next + 1);
            if (!data) return oauth_fail(fatal, "cannot grow Google OAuth response");
            body->data = data; capacity = next;
        }
    }
}

static const char *go_escape(unsigned char c)
{
    switch (c) {
    case '"': return "\\\"";
    case '\\': return "\\\\";
    case '\a': return "\\a";
    case '\b': return "\\b";
    case '\f': return "\\f";
    case '\n': return "\\n";
    case '\r': return "\\r";
    case '\t': return "\\t";
    case '\v': return "\\v";
    default: return NULL;
    }
}

static int go_quote_size(br_slice text, size_t *size, char **fatal)
{
    *size = 2;
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i];
        if (c >= 128) return oauth_fail(fatal, "unsupported: Google OAuth non-ASCII quoted diagnostic requires Go quoting");
        size_t n = go_escape(c) ? 2 : (c < 32 || c == 127 ? 4 : 1);
        if (*size > SIZE_MAX - n - 1) return oauth_fail(fatal, "Google OAuth diagnostic is too large");
        *size += n;
    }
    return 0;
}

static unsigned char *go_quote_write(unsigned char *out, br_slice text)
{
    static const char hex[] = "0123456789abcdef";
    *out++ = '"';
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i]; const char *escaped = go_escape(c);
        if (escaped) { memcpy(out, escaped, 2); out += 2; }
        else if (c < 32 || c == 127) { *out++ = '\\'; *out++ = 'x'; *out++ = (unsigned char)hex[c >> 4]; *out++ = (unsigned char)hex[c & 15]; }
        else *out++ = c;
    }
    *out++ = '"'; return out;
}

int br_gcp_oauth_quote(br_slice text, unsigned char *dst, size_t capacity,
                       size_t *written, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (!written || (!text.data && text.len)) return oauth_fail(fatal, "invalid Google OAuth quoted cause");
    *written = 0;
    if (go_quote_size(text, written, fatal)) return -1;
    if (dst) {
        if (*written > capacity) return oauth_fail(fatal, "Google OAuth quoted cause is too large");
        (void)go_quote_write(dst, text);
    }
    return 0;
}

int br_gcp_oauth_retrieve_error(br_slice status, br_slice body, br_slice code,
                                br_slice description, br_slice uri,
                                br_gcp_oauth_error *out, char **fatal)
{
    static const char raw_prefix[] = "oauth2: cannot fetch token: ";
    static const char raw_separator[] = "\nResponse: ";
    if (fatal) *fatal = NULL;
    if (!out || (!status.data && status.len) || (!body.data && body.len) ||
        (!code.data && code.len) || (!description.data && description.len) || (!uri.data && uri.len))
        return oauth_fail(fatal, "invalid Google OAuth retrieve error");
    *out = (br_gcp_oauth_error){0}; size_t size;
    if (code.len) {
        size_t a, b = 0, c = 0;
        if (go_quote_size(code, &a, fatal) || (description.len && go_quote_size(description, &b, fatal)) ||
            (uri.len && go_quote_size(uri, &c, fatal))) return -1;
        size = sizeof("oauth2: ") - 1;
        const size_t lengths[] = {a, b, c};
        for (size_t i = 0; i < 3; ++i) if (lengths[i]) {
            size_t delimiter = i ? 1 : 0;
            if (size > SIZE_MAX - delimiter - 1 || lengths[i] > SIZE_MAX - size - delimiter - 1)
                return oauth_fail(fatal, "Google OAuth diagnostic is too large");
            size += delimiter + lengths[i];
        }
    } else {
        size = sizeof(raw_prefix) - 1 + sizeof(raw_separator) - 1;
        if (status.len > SIZE_MAX - size - 1 || body.len > SIZE_MAX - size - status.len - 1)
            return oauth_fail(fatal, "Google OAuth diagnostic is too large");
        size += status.len + body.len;
    }
    unsigned char *data = malloc(size + 1);
    if (!data) return oauth_fail(fatal, "cannot allocate Google OAuth diagnostic");
    unsigned char *at = data;
    if (code.len) {
        memcpy(at, "oauth2: ", 8); at += 8; at = go_quote_write(at, code);
        if (description.len) { *at++ = ' '; at = go_quote_write(at, description); }
        if (uri.len) { *at++ = ' '; at = go_quote_write(at, uri); }
    } else {
        memcpy(at, raw_prefix, sizeof(raw_prefix) - 1); at += sizeof(raw_prefix) - 1;
        if (status.len) { memcpy(at, status.data, status.len); at += status.len; }
        memcpy(at, raw_separator, sizeof(raw_separator) - 1); at += sizeof(raw_separator) - 1;
        if (body.len) { memcpy(at, body.data, body.len); at += body.len; }
    }
    *at = 0; out->text = (br_bytes){data, size}; return 0;
}
