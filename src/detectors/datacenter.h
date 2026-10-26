/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_DATACENTER_H
#define BRIAR_DATACENTER_H

#include "endpoints.h"

int br_dc_token_pattern(const char *const *prefixes, size_t n, br_regex **out, char **error);
int br_dc_url_pattern(const char *const *prefixes, size_t n, br_regex **out, char **error);
/* Validate a captured 44-byte, unpadded standard-base64 PAT, not arbitrary tokens. */
bool br_dc_is_structural_pat44(br_slice candidate);
/* Owned resolved URLs, deduplicated after trimming all trailing '/' bytes. */
int br_dc_find_endpoints(br_slice input, const br_regex *url_pattern,
                         const br_endpoints *settings, br_endpoint_list *out, char **error);
/* Replace path/query on the supported absolute HTTP(S) subset. Preserve supported
 * userinfo/fragment and an original empty-query delimiter. No metadata rewriting.
 * Return 0 success, 1 unsupported/invalid with owned cause, -1 resource failure.
 * Escapes, opaque/relative URLs, repeated fragment delimiters and
 * authority-normalizing forms fail closed. */
int br_dc_request_url(const char *base, const char *path, const char *raw_query,
                      char **url, char **cause);
/* GET/Bearer/Accept JSON. 200 verifies even if first-document map decoding fails;
 * 401 is invalid, other statuses/transport errors yield an owned cause. Body is
 * an owned generic JSON object or NULL. Callers perform their own redaction.
 * Return 0 for candidate outcomes, -1 for resource failure. */
int br_dc_verify(const br_scan_ctx *, br_http_profile, int32_t type,
                 const char *url, const char *token, bool *verified, br_json **body, char **cause);

#endif
