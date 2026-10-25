/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_FIFTH_BATCH_H
#define BRIAR_FIFTH_BATCH_H

#include "briar.h"

/* Private batch initialization for the compiled registry, before workers. */
int br_fifth_batch(const br_detector *const **out, size_t *count, char **error);
bool br_fifth_batch_is_default(const br_detector *);

#endif
