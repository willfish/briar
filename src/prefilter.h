/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_PREFILTER_H
#define BRIAR_PREFILTER_H

#include "briar.h"

/* Internal CLI keyword windows, in registry order. Storage belongs to the
 * prefilter and is reused by the next find. pending belongs to overlap probing. */
typedef struct {
    const br_detector *detector;
    br_span *windows;
    size_t len, capacity;
    bool pending;
} br_detector_windows;

typedef struct br_prefilter br_prefilter;

int br_prefilter_create(const br_detector *const *registry, size_t count,
                        const bool *selected, br_prefilter **out, char **error);
int br_prefilter_find(br_prefilter *filter, br_slice input, const br_scan_ctx *ctx,
                      br_detector_windows **matches, size_t *count, char **error);
void br_prefilter_destroy(br_prefilter *filter);

#endif
