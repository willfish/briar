/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_SECOND_BATCH_H
#define BRIAR_SECOND_BATCH_H

#include "briar.h"

/* Private batch initialization for the compiled registry, before workers. */
int br_second_batch(const br_detector *const **out, size_t *count, char **error);
/* Upstream membership, including disabled AdobeIO. */
bool br_second_batch_is_default(const br_detector *);

#endif
