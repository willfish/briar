/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_HOST_CACHE_H
#define BRIAR_HOST_CACHE_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>

typedef struct br_host_cache_entry br_host_cache_entry;
typedef struct { atomic_flag lock; br_host_cache_entry *entries; } br_host_cache;
#define BR_HOST_CACHE_INIT { .lock = ATOMIC_FLAG_INIT, .entries = NULL }

/* Pinned simple-cache presence semantics: twelve hours, case-sensitive keys,
 * expired only AFTER the expiration instant. Each provider owns its instance
 * and decides when to cache or suppress a host. Empty keys are valid.
 * Initialize statically with BR_HOST_CACHE_INIT; do not copy an active cache.
 * Returns -1 on clock/allocation failure, otherwise 0. */
int br_host_cache_contains(br_host_cache *, const char *host, bool *found);
int br_host_cache_add(br_host_cache *, const char *host);

#endif
