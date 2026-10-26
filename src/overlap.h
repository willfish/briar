/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_OVERLAP_H
#define BRIAR_OVERLAP_H

#include "briar.h"

/* Pinned engine's asymmetric byte-length gate and case-sensitive rune
 * Levenshtein similarity > 0.9. Does not normalize credential bytes.
 * Return 0 on success, nonzero with owned error on failure. */
int br_overlap_similar(br_slice current, br_slice earlier, bool *similar, char **error);

#endif
