/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_GITHUB_OAUTH2_PRIVATE_H
#define BRIAR_GITHUB_OAUTH2_PRIVATE_H

#include "briar.h"

/* SDK request bytes, not SANE HTTP preparation or an authenticated transport.
 * The source sets no explicit User-Agent or client timeout. Native SDK I/O is
 * unsupported; install these callbacks only in a caller-owned state clone. */
typedef struct { const char *name; br_slice value; } br_github_oauth2_header;
typedef struct {
    const char *method;
    br_slice url, body;
    const br_github_oauth2_header *headers;
    size_t nheaders;
} br_github_oauth2_request;

typedef struct {
    int status;
    br_slice status_text, content_type; /* First source Header.Get value. */
    void *reader;
} br_github_oauth2_response;

/* Zero means success, positive means an ordinary SDK error, negative means a
 * fatal/resource failure. Error bytes are owned on every return and may contain
 * NUL; send supplies complete Client.Do text, read supplies reader error text.
 * read may return final bytes with an error; zero bytes with success means EOF.
 * Release once after every send, including failure, before retrying. Request
 * values survive release; response slices are borrowed until then. All calls
 * are synchronous. The clone owner retains io/user for the entire scan. No
 * tokens, parsed OAuth results or verification booleans cross this boundary. */
typedef struct {
    int (*send)(void *, const br_scan_ctx *, const br_github_oauth2_request *,
                br_github_oauth2_response *, br_bytes *error);
    int (*read)(void *, br_github_oauth2_response *, unsigned char *, size_t,
                size_t *n, br_bytes *error);
    void (*release)(void *, br_github_oauth2_response *);
} br_github_oauth2_io;

typedef struct {
    br_regex *id_pattern, *secret_pattern;
    const br_github_oauth2_io *io;
    void *user;
} br_github_oauth2_state;

#endif
