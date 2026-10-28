/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_GCP_OAUTH_H
#define BRIAR_GCP_OAUTH_H

#include "briar.h"

/* Private HTTP-byte boundary for the reachable Google OAuth flows, NOT an SDK
 * mock returning tokens/verified booleans and NOT a public HTTP profile. */
typedef enum {
    BR_GCP_JWT_POST,          /* Default client, background request, no timeout/UA. */
    BR_GCP_REFRESH_POST,      /* Default client, scan context, no timeout/UA. */
    BR_GCP_ADC_IAM,           /* OAuth DefaultTransport, scan context, client timeout. */
    BR_GCP_ADC_FAKE_IAM       /* Exact source FakeTransport sentinel; no auth layer. */
} br_gcp_oauth_role;

typedef struct { const char *name; br_slice value; } br_gcp_oauth_header;
typedef struct {
    br_gcp_oauth_role role;
    const char *method;
    br_slice url, body;
    const br_gcp_oauth_header *headers;
    size_t nheaders;
    int64_t timeout_ns;       /* Zero means the source has no client timeout. */
} br_gcp_oauth_request;

typedef struct {
    int status;
    br_slice status_text;     /* Complete Go Response.Status, not guessed from code. */
    br_slice content_type;    /* First Content-Type value, borrowed until release. */
    void *reader;             /* Owned transport state; release accepts an empty response. */
} br_gcp_oauth_response;

/* Both complete Do error text and its structured single-Unwrap leaf are needed:
 * JWT's %v envelope retains the former; the result setter may require the latter.
 * No stage/type is ever inferred from diagnostic text. All byte values are owned,
 * including on partial/fatal callback returns. has_leaf distinguishes empty leaf. */
typedef struct { br_bytes text, leaf; bool has_leaf; } br_gcp_oauth_error;

typedef struct {
    int (*send)(void *user, const br_scan_ctx *client_context,
                const br_gcp_oauth_request *, br_gcp_oauth_response *, br_gcp_oauth_error *);
    int (*read)(void *user, br_gcp_oauth_response *, unsigned char *, size_t capacity,
                size_t *n, br_gcp_oauth_error *);
    void (*release)(void *user, br_gcp_oauth_response *);
} br_gcp_oauth_io;

/* All callbacks are required: 0 success, +1 ordinary non-EOF error, -1 fatal.
 * Read preserves partial bytes; 0 with n==0 means EOF. All calls are synchronous.
 * Release once after EVERY send, including failed/empty responses, before any
 * borrowed request value expires. No callback borrows beyond its call/release.
 * JWT role uses client_context only for source client selection, NOT attachment
 * to the background request. Other roles attach it. Native I/O is unsupported
 * when io==NULL: never borrow HTTP userdata, fall back to curl or bypass guards. */

typedef struct { br_regex *regex; const br_gcp_oauth_io *io; void *user; } br_gcp_state;
typedef struct {
    br_regex *regex;
    const br_gcp_oauth_io *io;
    void *user;
    bool fake_transport;      /* Only exact source value sentinel, not any fake I/O. */
    bool custom_client;
    int64_t timeout_ns;       /* Custom client timeout; otherwise SANE's five seconds. */
} br_gcp_adc_state;

/* Only narrow mechanics genuinely shared by the two closed credential flows. */
typedef struct { const char *name; br_slice value; } br_gcp_oauth_pair;
/* Caller supplies the fixed source fields in lexical key order; Go QueryEscape
 * applies to every original byte. Owned result has an extra terminal NUL. */
int br_gcp_oauth_form(const br_gcp_oauth_pair *, size_t count, br_bytes *, char **fatal);
/* Exact source io.LimitReader limit is one MiB. Stop without a further read at
 * that limit; retain partial owned body/error on every return. */
int br_gcp_oauth_read(const br_gcp_oauth_io *, void *user, br_gcp_oauth_response *,
                      br_bytes *body, br_gcp_oauth_error *, char **fatal);
/* Go ASCII %q string, also needed by the shared unknown-credential constructor
 * cause. NULL dst measures; output is not NUL terminated. Non-ASCII diagnostics
 * are explicit unsupported boundaries, only after determinate source decisions. */
int br_gcp_oauth_quote(br_slice, unsigned char *dst, size_t capacity,
                       size_t *written, char **fatal);
/* Source RetrieveError formatting only; caller retains typed provenance/status.
 * Nonempty code uses Go quoting; otherwise use original status text and body.
 * Call only when diagnostic text is needed, after earlier determinate decisions
 * (ADC non-Temporary suppression, GCP's Token-stage invalid_grant predicate).
 * In particular do not move a diagnostic-only quoting guard before them. */
int br_gcp_oauth_retrieve_error(br_slice status, br_slice body, br_slice code,
                                br_slice description, br_slice uri,
                                br_gcp_oauth_error *, char **fatal);
void br_gcp_oauth_error_clear(br_gcp_oauth_error *);

#endif
