/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_KEY_SCAN_H
#define BRIAR_KEY_SCAN_H

#include "briar.h"

typedef int (*br_key_verifier)(const br_scan_ctx *, const char *, br_result *);

/* For detectors whose single captured key is their complete finding. Keeps
 * match order and duplicates; provider-specific filtering stays in the provider. */
int br_scan_key(const br_detector *, const br_scan_ctx *, bool verify,
                br_slice input, br_results *, const char *secret_part,
                br_key_verifier, char **error);

/* The same finding mechanics for nonempty captured C strings, retaining only
 * each key's first occurrence. Use when upstream collects a unique-key map. */
int br_scan_unique_key(const br_detector *, const br_scan_ctx *, bool verify,
                       br_slice input, br_results *, const char *secret_part,
                       br_key_verifier, char **error);

/* Compile PrefixRegex(keywords) + capture once, before scan workers start. */
int br_key_pattern_init(br_detector *, const char *capture, char **error);

#endif
