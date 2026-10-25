/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_CAPTURES_H
#define BRIAR_CAPTURES_H

#include "briar.h"

typedef struct { char **items; size_t len, cap; size_t *lengths; } br_captures;

/* Owned nonempty byte captures, in match order; items also have a trailing NUL.
 * Stored lengths preserve embedded NUL and bytewise uniqueness. Zero-initialize
 * collections and clear after either success or failure. */
int br_captures_find(const br_regex *, br_slice, br_captures *, bool unique, char **error);
int br_captures_push(br_captures *, br_slice, bool unique, char **error);
void br_captures_clear(br_captures *);
/* Borrow the complete bytes at an index smaller than len. */
br_slice br_captures_at(const br_captures *, size_t index);

#endif
