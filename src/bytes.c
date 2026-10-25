/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <string.h>

size_t br_slice_find(br_slice input, br_slice needle, size_t start)
{
    if (start > input.len || needle.len > input.len - start) return SIZE_MAX;
    for (size_t i = start; i <= input.len - needle.len; ++i)
        if (!needle.len || !memcmp(input.data + i, needle.data, needle.len)) return i;
    return SIZE_MAX;
}
