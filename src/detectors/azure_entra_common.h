/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_AZURE_ENTRA_COMMON_H
#define BRIAR_AZURE_ENTRA_COMMON_H

#include "captures.h"

/* Initialize shared patterns before workers, like named detector factories. */
int br_azure_entra_common_init(char **error);
/* Append unique lowercase UUIDs or original-spelling tenant domains to owned
 * captures. Exact source UUID exclusions and entropy apply only to UUIDs. */
int br_azure_entra_find_ids(br_slice input, br_captures *clients,
                            br_captures *tenants, char **error);
/* Cache positive AND negative discovery results for twelve hours. Concurrent
 * requests for the same tenant share only this GET, never a credential POST.
 * Return 0 with exists, or -1 for a resource/synchronization failure. */
int br_azure_entra_tenant_exists(const br_scan_ctx *, int32_t detector_type,
                                 const char *tenant, bool *exists, char **error);

#endif
