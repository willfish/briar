/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from RE2 2024-07-02 Compiler::Add_80_10ffff.
 * Copyright 2007 The RE2 Authors. See LICENSES/BSD-3-Clause-RE2.txt. */
#include "re2_units.h"

size_t br_re2_any_unit_width(br_slice input)
{
    if (!input.data || !input.len) return 0;
    unsigned char first = input.data[0];
    if (first < 0x80) return 1;
    size_t width = first >= 0xc2 && first <= 0xdf ? 2 :
                   first >= 0xe0 && first <= 0xef ? 3 :
                   first >= 0xf0 && first <= 0xf4 ? 4 : 0;
    if (!width || width > input.len) return 0;
    for (size_t i = 1; i < width; ++i)
        if (input.data[i] < 0x80 || input.data[i] > 0xbf) return 0;
    return width;
}
