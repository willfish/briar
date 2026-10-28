/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected Go 1.26.7 encoding/json string behavior, BSD-3-Clause.
 * See NOTICE and LICENSES/BSD-3-Clause-Go.txt. */
#include "gcp_json.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

static int gcp_json_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

int br_gcp_json_text(br_json *value, br_slice *out, br_bytes *repair, char **error)
{
    if (error) *error = NULL;
    if (!out || !repair || (value && !json_object_is_type(value, json_type_string)))
        return gcp_json_fail(error, "invalid Google JSON string projection");
    *out = br_json_text(value); *repair = (br_bytes){0};
    if (br_utf8_valid(*out)) return 0;
    size_t size = 0;
    for (size_t i = 0; i < out->len;) {
        uint32_t rune; size_t n = br_utf8_rune((br_slice){out->data + i, out->len - i}, &rune);
        size_t add = n ? n : 3;
        if (size > SIZE_MAX - add - 1) return gcp_json_fail(error, "Google JSON string is too large");
        size += add; i += n ? n : 1;
    }
    repair->data = malloc(size + 1);
    if (!repair->data) return gcp_json_fail(error, "cannot repair Google JSON string");
    size_t at = 0;
    for (size_t i = 0; i < out->len;) {
        uint32_t rune; size_t n = br_utf8_rune((br_slice){out->data + i, out->len - i}, &rune);
        if (n) { memcpy(repair->data + at, out->data + i, n); at += n; i += n; }
        else { memcpy(repair->data + at, "\xef\xbf\xbd", 3); at += 3; ++i; }
    }
    repair->data[at] = 0; repair->len = at;
    *out = (br_slice){repair->data, repair->len}; return 0;
}

/* One pass can count or write. Only fixed-size escape fragments use stack
 * storage; complete unbounded objects are measured before their allocation. */
static int gcp_json_put(unsigned char *dst, size_t capacity, size_t *at,
                         const void *data, size_t len, char **error)
{
    if (len > SIZE_MAX - *at || (dst && (len > capacity || *at > capacity - len)))
        return gcp_json_fail(error, "Google JSON output is too large");
    if (dst && len) memcpy(dst + *at, data, len);
    *at += len; return 0;
}

int br_gcp_json_string(br_slice text, unsigned char *dst, size_t capacity,
                       size_t *written, char **error)
{
    static const char hex[] = "0123456789abcdef";
    if (error) *error = NULL;
    if (!written || (!text.data && text.len)) return gcp_json_fail(error, "invalid Google JSON string");
    *written = 0;
    if (gcp_json_put(dst, capacity, written, "\"", 1, error)) return -1;
    for (size_t i = 0; i < text.len;) {
        unsigned char c = text.data[i]; const char *escape = NULL;
        if (c < 128) {
            switch (c) {
            case '"': escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default: break;
            }
            if (escape) {
                if (gcp_json_put(dst, capacity, written, escape, 2, error)) return -1;
            } else if (c < 32 || c == '<' || c == '>' || c == '&') {
                char encoded[] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
                if (gcp_json_put(dst, capacity, written, encoded, sizeof(encoded), error)) return -1;
            } else if (gcp_json_put(dst, capacity, written, text.data + i, 1, error)) return -1;
            ++i; continue;
        }
        uint32_t rune; size_t n = br_utf8_rune((br_slice){text.data + i, text.len - i}, &rune);
        if (!n) {
            if (gcp_json_put(dst, capacity, written, "\\ufffd", 6, error)) return -1;
            ++i;
        } else if (rune == 0x2028 || rune == 0x2029) {
            const char *encoded = rune == 0x2028 ? "\\u2028" : "\\u2029";
            if (gcp_json_put(dst, capacity, written, encoded, 6, error)) return -1;
            i += n;
        } else {
            if (gcp_json_put(dst, capacity, written, text.data + i, n, error)) return -1;
            i += n;
        }
    }
    return gcp_json_put(dst, capacity, written, "\"", 1, error);
}

int br_gcp_json_object(const char *const *names, const br_slice *values,
                       size_t count, br_bytes *out, char **error)
{
    if (error) *error = NULL;
    if (!out || ((!names || !values) && count)) return gcp_json_fail(error, "invalid Google credential JSON output");
    *out = (br_bytes){0}; size_t total = 2;
    for (size_t i = 0; i < count; ++i) {
        if (!names[i]) return gcp_json_fail(error, "invalid Google credential field name");
        size_t name_len, value_len;
        if (br_gcp_json_string((br_slice){(const unsigned char *)names[i], strlen(names[i])}, NULL, 0, &name_len, error) ||
            br_gcp_json_string(values[i], NULL, 0, &value_len, error)) return -1;
        size_t delimiter = i ? 2 : 1; /* Optional comma plus colon. */
        if (total > SIZE_MAX - delimiter || name_len > SIZE_MAX - total - delimiter ||
            value_len >= SIZE_MAX - total - delimiter - name_len)
            return gcp_json_fail(error, "Google credential JSON is too large");
        total += delimiter + name_len + value_len;
    }
    if (total == SIZE_MAX) return gcp_json_fail(error, "Google credential JSON is too large");
    unsigned char *data = malloc(total + 1);
    if (!data) return gcp_json_fail(error, "cannot allocate Google credential JSON");
    size_t at = 0; data[at++] = '{';
    for (size_t i = 0; i < count; ++i) {
        size_t n;
        if (i) data[at++] = ',';
        if (br_gcp_json_string((br_slice){(const unsigned char *)names[i], strlen(names[i])}, data + at, total - at, &n, error)) goto fail;
        at += n; data[at++] = ':';
        if (br_gcp_json_string(values[i], data + at, total - at, &n, error)) goto fail;
        at += n;
    }
    data[at++] = '}'; data[at] = 0;
    out->data = data; out->len = at; return 0;
fail:
    free(data); return -1;
}
