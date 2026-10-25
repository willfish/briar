/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/decoders/base64.go. */
#include "briar_decoders.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error)
{
    if (error) {
        const char message[] = "cannot decode Base64 chunk";
        *error = malloc(sizeof(message));
        if (*error) memcpy(*error, message, sizeof(message));
    }
    return -1;
}

static int sextet(unsigned char c, bool url)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == (url ? '-' : '+')) return 62;
    if (c == (url ? '_' : '/')) return 63;
    return -1;
}

static bool charset(unsigned char c)
{
    return sextet(c, false) >= 0 || c == '-' || c == '_' || c == '=';
}

static bool end_char(unsigned char c)
{
    return c == '+' || c == '/' || c == '-' || c == '_' || c == '=';
}

/* Go uses non-Strict encodings, so unused final bits need not be zero. */
static int decode_ascii(br_slice input, bool url, br_bytes *out)
{
    *out = (br_bytes){0};
    size_t meaningful = input.len;
    if (url) {
        if (meaningful % 4 == 1) return 0;
    } else {
        if (meaningful % 4) return 0;
        if (meaningful && input.data[meaningful - 1] == '=') --meaningful;
        if (meaningful && input.data[meaningful - 1] == '=') --meaningful;
        size_t padding = input.len - meaningful;
        if ((padding == 1 && meaningful % 4 != 3) ||
            (padding == 2 && meaningful % 4 != 2)) return 0;
    }
    size_t len = meaningful / 4 * 3 + meaningful % 4 * 6 / 8;
    if (!len) return 0;
    unsigned char *bytes = malloc(len);
    if (!bytes) return -1;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    size_t written = 0;
    for (size_t i = 0; i < meaningful; ++i) {
        int value = sextet(input.data[i], url);
        if (value < 0) { free(bytes); return 0; }
        accumulator = (accumulator << 6) | (unsigned)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            unsigned char byte = (unsigned char)(accumulator >> bits);
            if (byte > 127) { free(bytes); return 0; }
            bytes[written++] = byte;
        }
    }
    out->data = bytes;
    out->len = written;
    return 1;
}

static size_t find_bytes(br_slice input, br_slice needle)
{
    if (needle.len > input.len) return SIZE_MAX;
    for (size_t i = 0; i <= input.len - needle.len; ++i)
        if (input.data[i] == needle.data[0] &&
            !memcmp(input.data + i, needle.data, needle.len)) return i;
    return SIZE_MAX;
}

int br_base64_decode(br_slice input, br_bytes *decoded, bool *applied, char **error)
{
    if (error) *error = NULL;
    if (decoded) *decoded = (br_bytes){0};
    if (applied) *applied = false;
    if (!decoded || !applied || (!input.data && input.len)) return fail(error);
    br_bytes output = {0};
    size_t scan = 0, copied = 0, written = 0;
    bool found = false;
    while (scan < input.len) {
        while (scan < input.len && !charset(input.data[scan])) ++scan;
        size_t begin = scan;
        while (scan < input.len && charset(input.data[scan])) ++scan;
        size_t end = scan;
        /* Threshold is tested before trimming, and is strictly greater than 20. */
        if (end - begin <= 20) continue;
        while (begin < end && end_char(input.data[begin])) ++begin;
        size_t trimmed_end = end;
        while (trimmed_end > begin && end_char(input.data[trimmed_end - 1])) --trimmed_end;
        for (size_t i = begin; i < trimmed_end; ++i) {
            if (input.data[i] == '=') { begin = i + 1; break; }
        }
        br_slice encoded = {input.data + begin, end - begin};
        br_bytes value = {0}, url_value = {0};
        if (decode_ascii(encoded, false, &value) < 0) goto memory_error;
        int url_status = decode_ascii(encoded, true, &url_value);
        if (url_status < 0) { free(value.data); goto memory_error; }
        if (url_status) { free(value.data); value = url_value; }
        if (!value.data) continue;
        if (!found) {
            output.data = malloc(input.len);
            if (!output.data) { free(value.data); goto memory_error; }
            found = true;
        }
        /* Upstream maps immutable candidate strings to decoded values. Repeating
         * that pure decode has the same result without a second dictionary.
         * Preserve bytes.Index semantics rather than assuming the run's offset. */
        br_slice remainder = {input.data + copied, input.len - copied};
        size_t offset = find_bytes(remainder, encoded);
        if (offset != SIZE_MAX) {
            memcpy(output.data + written, input.data + copied, offset);
            written += offset;
            memcpy(output.data + written, value.data, value.len);
            written += value.len;
            copied += offset + encoded.len;
        }
        free(value.data);
    }
    if (found) {
        memcpy(output.data + written, input.data + copied, input.len - copied);
        output.len = written + input.len - copied;
        *decoded = output;
        *applied = true;
    }
    return 0;
memory_error:
    free(output.data);
    return fail(error);
}
