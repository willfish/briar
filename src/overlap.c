/* SPDX-License-Identifier: AGPL-3.0-only */
/* Engine policy from TruffleHog v3.97.2, pkg/engine/engine.go likelyDuplicate.
 * Unit-cost rune distance matches its pinned strutil v0.3.1 metric. */
#include "overlap.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

/* Go string-to-rune conversion uses RuneError and advances one byte for an
 * invalid encoding. Conversion is local to this metric, never the finding. */
static size_t read_rune(br_slice text, size_t at, uint32_t *value)
{
    unsigned char first = text.data[at];
    if (first < 0x80) { *value = first; return 1; }
    size_t width;
    uint32_t scalar, minimum;
    if (first >= 0xc2 && first <= 0xdf) { width = 2; scalar = first & 0x1f; minimum = 0x80; }
    else if (first >= 0xe0 && first <= 0xef) { width = 3; scalar = first & 0x0f; minimum = 0x800; }
    else if (first >= 0xf0 && first <= 0xf4) { width = 4; scalar = first & 7; minimum = 0x10000; }
    else { *value = 0xfffd; return 1; }
    if (width > text.len - at) { *value = 0xfffd; return 1; }
    for (size_t i = 1; i < width; ++i) {
        unsigned char next = text.data[at + i];
        if ((next & 0xc0) != 0x80) { *value = 0xfffd; return 1; }
        scalar = (scalar << 6) | (next & 0x3f);
    }
    if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) {
        *value = 0xfffd;
        return 1;
    }
    *value = scalar;
    return width;
}

static uint32_t *runes(br_slice text, size_t *length)
{
    if (text.len > SIZE_MAX / sizeof(uint32_t)) return NULL;
    uint32_t *values = malloc(text.len * sizeof(*values));
    if (!values) return NULL;
    *length = 0;
    for (size_t at = 0; at < text.len;)
        at += read_rune(text, at, &values[(*length)++]);
    return values;
}

int br_overlap_similar(br_slice current, br_slice earlier, bool *similar, char **error)
{
    if (error) *error = NULL;
    if (similar) *similar = false;
    if (!similar || (!current.data && current.len) || (!earlier.data && earlier.len))
        return fail(error, "invalid overlap comparison");
    if (current.len > SIZE_MAX / 11 || earlier.len > SIZE_MAX / 10)
        return fail(error, "unsupported: overlap candidate too long");
    if (earlier.len * 10 < current.len * 9 || earlier.len * 10 > current.len * 11) return 0;
    if (current.len == earlier.len && (!current.len || !memcmp(current.data, earlier.data, current.len))) {
        *similar = true;
        return 0;
    }
    /* An empty/nonempty pair cannot pass the byte gate. */
    size_t na = 0, nb = 0;
    uint32_t *a = runes(current, &na), *b = runes(earlier, &nb);
    if (!a || !b || nb == SIZE_MAX || nb + 1 > SIZE_MAX / sizeof(size_t)) {
        free(a); free(b);
        return fail(error, "out of memory comparing overlap candidates");
    }
    size_t *row = malloc((nb + 1) * sizeof(*row));
    if (!row) { free(a); free(b); return fail(error, "out of memory comparing overlap candidates"); }
    for (size_t j = 0; j <= nb; ++j) row[j] = j;
    for (size_t i = 1; i <= na; ++i) {
        size_t diagonal = row[0];
        row[0] = i;
        for (size_t j = 1; j <= nb; ++j) {
            size_t prior = row[j];
            size_t cost = diagonal + (a[i - 1] != b[j - 1]);
            if (row[j] + 1 < cost) cost = row[j] + 1;
            if (row[j - 1] + 1 < cost) cost = row[j - 1] + 1;
            row[j] = cost;
            diagonal = prior;
        }
    }
    *similar = 1.0 - (double)row[nb] / (double)(na > nb ? na : nb) > 0.9;
    free(row);
    free(a);
    free(b);
    return 0;
}
