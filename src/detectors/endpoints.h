/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_ENDPOINTS_H
#define BRIAR_ENDPOINTS_H

#include "captures.h"

typedef struct { char **items; size_t len, cap; } br_endpoint_list;

/* Owned C strings, including empty endpoints. Zero-initialize and clear after
 * use. Exact case-sensitive uniqueness is optional; captures remain nonempty. */
int br_endpoint_list_push(br_endpoint_list *, const char *, bool unique, char **error);
void br_endpoint_list_clear(br_endpoint_list *);

/* NULL settings select engine defaults: found/cloud enabled. A NULL cloud
 * setting inherits default_cloud; an empty string explicitly disables it.
 * Deduplicate configured entries, then append enabled nonempty cloud/found
 * entries without cross-deduplication. Preserve empty configured endpoints.
 * Do not normalize provider URLs or validate an explicit setter call here.
 * Start with an empty output; failure clears it. */
int br_endpoints_collect(const br_endpoints *, const char *default_cloud,
                        const br_captures *found, br_endpoint_list *out, char **error);

/* Model SetConfiguredEndpoints, not a flags-only context: reject zero arguments,
 * accept a single empty string. Call only when applying an explicit list. */
int br_endpoints_validate_configured(const br_endpoints *, char **error);

#endif
