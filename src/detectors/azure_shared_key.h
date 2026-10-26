/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_AZURE_SHARED_KEY_H
#define BRIAR_AZURE_SHARED_KEY_H

#include "briar.h"

/* Non-strict standard Base64, ignoring only CR/LF. Own prefix even on corruption:
 * 0 complete (bad_offset=SIZE_MAX), 1 corrupt with zero-based Go error offset,
 * -1 resource/argument failure. A padded quantum before trailing garbage emits
 * its bytes; an incomplete or invalid quantum emits none. */
int br_azure_base64_std_decode(br_slice input, br_bytes *prefix, size_t *bad_offset);
/* Opaque binary inputs; output is padded standard Base64 plus NUL. */
int br_azure_hmac_sha256_base64(br_slice key, br_slice message, char out[45]);
/* English HTTP date and literal GMT, independent of locale. No clock access. */
int br_azure_http_date_utc(int64_t epoch_seconds, char out[30]);

#endif
