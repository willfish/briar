/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_AWS_COMMON_H
#define BRIAR_AWS_COMMON_H

#include "briar.h"

typedef struct {
    const br_json *skip_ids, *allowed_accounts, *denied_accounts;
} br_aws_options;

extern const char br_aws_secret_pattern[];

/* Exactly six source substitutions; output starts zeroed and owns its buffer. */
int br_aws_replace_url_bytes(br_slice input, br_bytes *out, char **error);
/* Input is a validated, NUL-terminated 20-byte AWS ID. */
bool br_aws_account_from_id(const char id[21], char account[14]);
/* Arrays borrow the context's options; prefix is the provider diagnostic. */
int br_aws_read_options(const br_scan_ctx *ctx, const char *error_prefix,
                        br_aws_options *out, char **error);
bool br_aws_list_contains(const br_json *list, const char *text);
/* Input is an extracted 40-byte secret, not an arbitrary string. */
bool br_aws_hash_like(const char secret[41]);
void br_aws_clean(const br_detector *detector, br_results *results, bool verification_enabled);

#endif
