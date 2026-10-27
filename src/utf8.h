/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_UTF8_H
#define BRIAR_UTF8_H

#include "briar.h"

/* Inspect original bytes without normalization, locale state or allocation. */
bool br_utf8_valid(br_slice input);
/* Decode the first valid scalar; return its byte width, or zero for empty,
 * malformed input or a missing output. Invalid bytes are not replaced. */
size_t br_utf8_rune(br_slice input, uint32_t *rune);

#endif
