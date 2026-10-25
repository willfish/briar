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

/* Pinned UTF16 heuristic extracts printable ASCII, LE matches before BE matches;
 * it is not a general Unicode conversion. Same output ownership as Base64. */
int br_utf16_decode(br_slice input, br_bytes *decoded, bool *applied, char **error);

/* Pinned escape-pattern priority and replacement rules; an invalid scalar still
 * counts as applied when its syntax matched. Same ownership as Base64. */
int br_escaped_unicode_decode(br_slice input, br_bytes *decoded, bool *applied, char **error);

#ifdef __cplusplus
}
#endif
#endif
