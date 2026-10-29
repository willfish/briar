/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_GO_URL_H
#define BRIAR_GO_URL_H

#include "briar.h"

typedef enum {
    BR_GO_URL_PATH, BR_GO_URL_HOST, BR_GO_URL_ZONE,
    BR_GO_URL_USER, BR_GO_URL_FRAGMENT
} br_go_url_encoding;
typedef enum {
    BR_GO_URL_OK, BR_GO_URL_CONTROL, BR_GO_URL_SCHEME, BR_GO_URL_COLON,
    BR_GO_URL_BAD_USER, BR_GO_URL_ESCAPE, BR_GO_URL_HOST_CHAR, BR_GO_URL_PORT,
    BR_GO_URL_BRACKET, BR_GO_URL_IP_LITERAL, BR_GO_URL_IP_DIAGNOSTIC
} br_go_url_error_kind;
typedef struct { br_go_url_error_kind kind; br_slice detail; } br_go_url_error;
typedef struct {
    br_slice host, raw_user, raw_password, raw_path, raw_query, raw_fragment;
    br_bytes host_storage;
    bool has_user, has_password, force_query;
} br_go_url_parts;

/* Fixed selected Go1.26.7 URL parse projection, urlstrictcolons=0. These are
 * private byte mechanics, not endpoint policy or a transport URL validator.
 * Start empty; clear after EVERY outcome. Host is decoded, other fields remain
 * encoded views. Input and rejection.detail borrow bytes through clear; host
 * may also borrow host_storage. Rejection is separate from fatal status.
 * No DNS, IDNA conversion, port-range validation or environment discovery. */
int br_go_url_parse(br_slice, br_go_url_parts *, br_go_url_error *, char **fatal);
void br_go_url_clear(br_go_url_parts *);
/* Ordinary bad escapes use valid=false, never a nonzero status. */
int br_go_url_decode(br_slice, bool query_component, br_bytes *, bool *valid, char **fatal);
/* URL.Query().Get: exact first valid value, malformed pairs skipped, default
 * 10000-segment limit yields an entirely empty map. Empty/absent both empty. */
int br_go_url_query_get(br_slice query, br_slice key, br_bytes *, char **fatal);
bool br_go_url_byte_allowed(unsigned char, br_go_url_encoding);

#endif
