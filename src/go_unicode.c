/* SPDX-License-Identifier: AGPL-3.0-only */
#include "go_unicode.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct { uint32_t lo, hi, stride; } unicode_range;
typedef struct { uint32_t lo, hi; int32_t delta; } unicode_case_range;
#include "go_unicode_tables.h"

static bool in_ranges(uint32_t rune, const unicode_range *ranges, size_t len)
{
    size_t lo = 0, hi = len;
    while (lo < hi) {
        size_t middle = lo + (hi - lo) / 2;
        const unicode_range *range = &ranges[middle];
        if (rune < range->lo) hi = middle;
        else if (rune > range->hi) lo = middle + 1;
        else return (rune - range->lo) % range->stride == 0;
    }
    return false;
}

uint32_t br_go_unicode_lower(uint32_t rune)
{
    size_t lo = 0, hi = sizeof(go_lower_case) / sizeof(*go_lower_case);
    while (lo < hi) {
        size_t middle = lo + (hi - lo) / 2;
        const unicode_case_range *range = &go_lower_case[middle];
        if (rune < range->lo) hi = middle;
        else if (rune > range->hi) lo = middle + 1;
        else if (range->delta > 0x10ffff)
            return range->lo + (((rune - range->lo) & ~UINT32_C(1)) | 1u);
        else return (uint32_t)((int64_t)rune + range->delta);
    }
    return rune;
}

unsigned br_go_unicode_properties(uint32_t rune)
{
    if (rune > 0x10ffff || (rune >= 0xd800 && rune <= 0xdfff)) return 0;
    /* General categories are disjoint; whitespace is an independent property.
     * Retain source strides rather than expanding alternating-case ranges. */
    unsigned properties = 0;
    if (in_ranges(rune, go_lower, sizeof(go_lower) / sizeof(*go_lower))) properties |= BR_GO_LOWER;
    if (in_ranges(rune, go_upper, sizeof(go_upper) / sizeof(*go_upper))) properties |= BR_GO_UPPER;
    if (in_ranges(rune, go_number, sizeof(go_number) / sizeof(*go_number))) properties |= BR_GO_NUMBER;
    if (in_ranges(rune, go_punct, sizeof(go_punct) / sizeof(*go_punct))) properties |= BR_GO_PUNCT;
    if (in_ranges(rune, go_symbol, sizeof(go_symbol) / sizeof(*go_symbol))) properties |= BR_GO_SYMBOL;
    if (in_ranges(rune, go_space, sizeof(go_space) / sizeof(*go_space))) properties |= BR_GO_SPACE;
    return properties;
}
