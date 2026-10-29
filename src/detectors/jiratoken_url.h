/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_JIRATOKEN_URL_H
#define BRIAR_JIRATOKEN_URL_H

#include "briar.h"

/* EndpointHost's owned byte result has a sentinel, not a C-string contract.
 * Parse rejection returns the exact trimmed fallback successfully. */
int br_jiratoken_endpoint_host(br_slice endpoint, br_bytes *host, char **error);

typedef struct {
    br_bytes original;
    br_bytes projected;
    const char *url; /* Borrows original or projected until clear. */
    char *cause;    /* Ordinary source constructor rejection, owned. */
    bool error_url_has_no_host;
} br_jiratoken_target;

/* Construct the complete original URL before nil-context handling. Preserve
 * original and any changed URL.String projection through send AND release.
 * A successful constructor has url and no cause. Every nonzero return is fatal,
 * including explicitly unsupported diagnostic representations; output clears.
 * The error-URL flag models the known Client.Do URL wrapper, not a DNS type or
 * verification verdict. Flat backend errors cannot model arbitrary Go chains. */
int br_jiratoken_target_init(br_slice host, bool context_present,
                            br_jiratoken_target *out, char **error);
void br_jiratoken_target_clear(br_jiratoken_target *target);

#endif
