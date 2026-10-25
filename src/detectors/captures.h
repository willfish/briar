/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_CAPTURES_H
#define BRIAR_CAPTURES_H

#include "briar.h"

typedef struct { char **items; size_t len, cap; } br_captures;

/* Owned nonempty key strings, in match order. Uniqueness keeps the first value.
 * Zero-initialize collections and clear after either success or failure. */
int br_captures_find(const br_regex *, br_slice, br_captures *, bool unique, char **error);
int br_captures_push(br_captures *, br_slice, bool unique, char **error);
void br_captures_clear(br_captures *);

#endif
