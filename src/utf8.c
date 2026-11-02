/* SPDX-License-Identifier: AGPL-3.0-only */
/* PLAIN normalization from TruffleHog v3.97.2, pkg/decoders/utf8.go. */
#include "briar.h"
#include "utf8.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

static bool continuation(unsigned char c) { return (c & 0xc0) == 0x80; }

/* Width of one valid UTF-8 scalar, or zero for an invalid/truncated encoding. */
static size_t rune_width(const unsigned char *p, size_t len)
{
    unsigned char c = p[0];
    if (c < 0x80) return 1;
    if (c >= 0xc2 && c <= 0xdf)
        return len >= 2 && continuation(p[1]) ? 2 : 0;
    if (c >= 0xe0 && c <= 0xef) {
        if (len < 3 || !continuation(p[1]) || !continuation(p[2]) ||
            (c == 0xe0 && p[1] < 0xa0) || (c == 0xed && p[1] >= 0xa0)) return 0;
        return 3;
    }
    if (c >= 0xf0 && c <= 0xf4) {
        if (len < 4 || !continuation(p[1]) || !continuation(p[2]) || !continuation(p[3]) ||
            (c == 0xf0 && p[1] < 0x90) || (c == 0xf4 && p[1] >= 0x90)) return 0;
        return 4;
    }
    return 0;
}

bool br_utf8_valid(br_slice input)
{
    if (!input.data && input.len) return false;
    for (size_t at = 0; at < input.len;) {
        /* ASCII bytes are already complete scalars, including controls/NUL.
         * Skip a machine word at a time without alignment or aliasing assumptions. */
        while (input.len - at >= sizeof(uint64_t)) {
            uint64_t word;
            memcpy(&word, input.data + at, sizeof(word));
            if (word & UINT64_C(0x8080808080808080)) break;
            at += sizeof(word);
        }
        while (at < input.len && input.data[at] < 0x80) ++at;
        if (at == input.len) break;
        size_t width = rune_width(input.data + at, input.len - at);
        if (!width) return false;
        at += width;
    }
    return true;
}

size_t br_utf8_rune(br_slice input, uint32_t *rune)
{
    if (!rune || !input.data || !input.len) return 0;
    size_t width = rune_width(input.data, input.len);
    if (!width) return 0;
    uint32_t value = input.data[0] & (width == 1 ? 0x7fu : 0x7fu >> width);
    for (size_t i = 1; i < width; ++i) value = (value << 6) | (input.data[i] & 0x3fu);
    *rune = value;
    return width;
}

int br_utf8_decode(br_slice input, br_slice *decoded, br_bytes *storage, char **error)
{
    if (error) *error = NULL;
    if (decoded) *decoded = (br_slice){0};
    if (storage) *storage = (br_bytes){0};
    if (!decoded || !storage || (!input.data && input.len))
        return fail(error, "invalid PLAIN decoder arguments");

    /* Upstream returns valid input untouched, including NUL, controls and U+FFFD. */
    if (br_utf8_valid(input)) {
        *decoded = input;
        return 0;
    }
    if (input.len > SIZE_MAX / 3) return fail(error, "PLAIN decoder output size overflow");
    unsigned char *output = malloc(input.len * 3);
    if (!output) return fail(error, "out of memory normalizing PLAIN input");
    static const unsigned char replacement[] = { 0xef, 0xbf, 0xbd };
    size_t used = 0;
    for (size_t i = 0; i < input.len;) {
        unsigned char c = input.data[i];
        size_t width = rune_width(input.data + i, input.len - i);
        bool rune_error = width == 3 && !memcmp(input.data + i, replacement, 3);
        if ((c < 0x80 && (c < 32 || c == 127)) || !width || rune_error) {
            memcpy(output + used, replacement, sizeof(replacement));
            used += sizeof(replacement);
            /* Match DecodeRune's RuneError branch exactly, even for literal U+FFFD. */
            ++i;
        } else {
            memcpy(output + used, input.data + i, width);
            used += width;
            i += width;
        }
    }
    *storage = (br_bytes){ output, used };
    *decoded = (br_slice){ output, used };
    return 0;
}
