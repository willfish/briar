/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_GO_UNICODE_H
#define BRIAR_GO_UNICODE_H

#include <stdint.h>

enum {
    BR_GO_LOWER = 1u << 0, BR_GO_UPPER = 1u << 1,
    BR_GO_NUMBER = 1u << 2, BR_GO_PUNCT = 1u << 3,
    BR_GO_SYMBOL = 1u << 4, BR_GO_SPACE = 1u << 5
};

/* Selected Go 1.26.7 / Unicode 15.0 properties, independent of locale and PCRE
 * table upgrades. Number is all N, not just Nd. Invalid scalars have no flags. */
unsigned br_go_unicode_properties(uint32_t rune);
/* Go's simple ToLower mapping, not locale-sensitive or full case folding. */
uint32_t br_go_unicode_lower(uint32_t rune);

#endif
