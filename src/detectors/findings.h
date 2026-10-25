/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_FINDINGS_H
#define BRIAR_FINDINGS_H

#include "briar.h"

/* Initialise a zeroed finding. Failure clears it. The byte form preserves NUL.
 * Pair findings use captured strings: Raw=key, RawV2=key+secondary, no separator. */
int br_finding_key_bytes(br_result *, int32_t type, br_slice key, const char *part_name);
int br_finding_key(br_result *, int32_t type, const char *key, const char *part_name);
int br_finding_pair(br_result *, int32_t type, const char *key, const char *key_name,
                    const char *secondary, const char *secondary_name);

#endif
