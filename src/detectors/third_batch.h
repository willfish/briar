/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_THIRD_BATCH_H
#define BRIAR_THIRD_BATCH_H

#include "briar.h"

/* Private batch initialization for the compiled registry, before workers. */
int br_third_batch(const br_detector *const **out, size_t *count, char **error);
bool br_third_batch_is_default(const br_detector *);

#endif
