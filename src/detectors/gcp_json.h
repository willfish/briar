/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_GCP_JSON_H
#define BRIAR_GCP_JSON_H

#include "briar.h"

/* Selected Go string codecs for the two closed Google credential structs.
 * No schema, generic map codec or SDK is provided. All failures are fatal (-1).
 * Initialize owned outputs to zero; the caller frees them on every return. */

/* Borrow a typed JSON string while its object lives. Allocate repair only when
 * Go decoding would replace invalid UTF8; decoded NUL bytes remain intact. */
int br_gcp_json_text(br_json *, br_slice *out, br_bytes *repair, char **error);

/* Go Marshal's default HTML-safe quoted string, including invalid UTF8 repair.
 * NULL dst measures; otherwise write exactly *written bytes, without a NUL.
 * The same primitive also serves JWT string fields without heap staging. */
int br_gcp_json_string(br_slice, unsigned char *dst, size_t capacity,
                       size_t *written, char **error);

/* Marshal the caller's fixed, ordered string-field struct, not a map. Every
 * field is emitted, including empty values. Owned output has a trailing NUL
 * outside its byte length. Names are fixed source tags, values are Go strings. */
int br_gcp_json_object(const char *const *names, const br_slice *values,
                       size_t count, br_bytes *out, char **error);

#endif
