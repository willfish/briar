/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_GO_TIME_H
#define BRIAR_GO_TIME_H

#include "briar.h"

/* Fixed Go1.26.7 time.Unix(seconds,0).String projection for the pinned Linux64
 * reference profile: full signed64 input/wrapping calendar, lazy process-local
 * Local, Nix-patched zone search, TZif/POSIX extensions and STORED ZIP fallback.
 * GOROOT is captured at process startup, like runtime's initial environment;
 * TZ is read only at first Local use. No libc timezone state or Go invocation.
 * NumericDate number conversion/truncation and metadata order are caller policy.
 * Start empty; successful bytes are owned, length-preserving and NUL-terminated.
 * Every nonzero is fatal, never an ordinary credential rejection/UTC fallback.
 * An owned initialization failure remains failed for all later callers. */
int br_go_time_unix_string(int64_t seconds, br_bytes *out, char **fatal);

#endif
