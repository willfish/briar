/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_DETECTORS_H
#define BRIAR_DETECTORS_H

#include "briar.h"

/* Named factories initialize private regex state before scan workers start. */
int br_abstract_init(const br_detector **out, char **error);
int br_abuseipdb_init(const br_detector **out, char **error);
int br_abyssale_init(const br_detector **out, char **error);
int br_adafruitio_init(const br_detector **out, char **error);

#endif
