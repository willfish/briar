/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_DECODERS_H
#define BRIAR_DECODERS_H

#include "briar.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Exact pinned Base64 chunk transformation. Input is borrowed and never modified.
 * Zero-initialize decoded; when applied is true, free(decoded->data) after use.
 * No candidate is a successful no-op with applied=false and empty decoded.
 * Errors clear both outputs and return an owned, non-sensitive error string. */
int br_base64_decode(br_slice input, br_bytes *decoded, bool *applied, char **error);

#ifdef __cplusplus
}
#endif
#endif
