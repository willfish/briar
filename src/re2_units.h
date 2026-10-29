/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_RE2_UNITS_H
#define BRIAR_RE2_UNITS_H
#include "briar.h"

/* Width0 is a barrier, not an error status. Match only RE2's selected optimized
 * full non-ASCII range, plus ASCII. Some accepted units are NOT Unicode scalars.
 * Callers own ASCII exclusions/repetition/boundaries; never use for Go trimming,
 * JSON, URL decoding, narrower regex classes or empty-match progression. */
size_t br_re2_any_unit_width(br_slice input);
#endif
