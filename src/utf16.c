/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/decoders/utf16.go and isPrintableByte. */
#include "briar_decoders.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error)
{
    if (error) {
        const char message[] = "cannot decode UTF16 chunk";
        *error = malloc(sizeof(message));
        if (*error) memcpy(*error, message, sizeof(message));
    }
    return -1;
}

static bool printable(unsigned char c) { return c > 31 && c < 127; }

int br_utf16_decode(br_slice input, br_bytes *decoded, bool *applied, char **error)
{
    if (error) *error = NULL;
    if (decoded) *decoded = (br_bytes){0};
    if (applied) *applied = false;
    if (!decoded || !applied || (!input.data && input.len)) return fail(error);
    if (input.len < 2) return 0;
    size_t len = 0;
    for (size_t i = 0; i < input.len - 1; i += 2) {
        if (!input.data[i + 1] && printable(input.data[i])) ++len;
        if (!input.data[i] && printable(input.data[i + 1])) ++len;
    }
    if (!len) return 0;
    unsigned char *bytes = malloc(len);
    if (!bytes) return fail(error);
    size_t used = 0;
    /* Upstream concatenates two buffers, not a BOM-selected or interleaved view.
     * The zero high byte makes ValidRune redundant for retained ASCII values. */
    for (size_t endian = 0; endian < 2; ++endian) {
        for (size_t i = 0; i < input.len - 1; i += 2) {
            unsigned char value = input.data[i + endian];
            if (!input.data[i + 1 - endian] && printable(value)) bytes[used++] = value;
        }
    }
    *decoded = (br_bytes){bytes, used};
    *applied = true;
    return 0;
}
