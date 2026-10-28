/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_FTP_PRIVATE_H
#define BRIAR_FTP_PRIVATE_H

#include "briar.h"

/* FTP control I/O only. Tests clone the descriptor and this opaque state; no
 * global setter, HTTP transport or public ABI extension is involved. */
typedef struct { void *handle; bool tcp; } br_ftp_conn;

typedef struct {
    int (*dial)(void *user, br_slice address, int64_t timeout_ns,
                br_ftp_conn *out, br_bytes *cause);
    int (*deadline_after)(void *user, br_ftp_conn, int64_t timeout_ns,
                          br_bytes *cause);
    int (*read)(void *user, br_ftp_conn, unsigned char *out, size_t capacity,
                size_t *n, br_bytes *cause);
    int (*write)(void *user, br_ftp_conn, br_slice, size_t *n, br_bytes *cause);
    void (*close)(void *user, br_ftp_conn);
} br_ftp_io;

/* Callbacks return 0 success, +1 ordinary I/O error, -1 resource/fatal error.
 * On EVERY return the scanner owns cause and any non-NULL handle, including
 * partial failures. It closes each handle once. Read preserves partial bytes
 * before an ordinary pending error; successful zero-byte read means EOF.
 * Write reports progress; a short success becomes a sticky "short write".
 * No callback borrows arguments beyond its call. All five are required.
 * deadline_after installs a fresh now+timeout deadline after dialing, not the
 * remainder of a total dial/session budget. close releases without allocation.
 * NULL io preserves the explicit unsupported native-FTP verification guard. */
typedef struct {
    br_regex *regex;
    const br_ftp_io *io;
    void *user;
    int64_t timeout_ns; /* Positive source override; otherwise derive/default. */
} br_ftp_state;

#endif
