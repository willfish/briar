/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_LDAP_PRIVATE_H
#define BRIAR_LDAP_PRIVATE_H

#include "briar.h"

/* Selected Go1.26.7 Parse/String projection for LDAP's regex-reachable authority
 * URLs, urlstrictcolons=0. Ordinary parse rejection is accepted=false/status0;
 * EVERY nonzero is fatal. Start empty; free out->data after every outcome.
 * Own the successful NUL-terminated bytes, preserving lengths and empty ports.
 * Scheme routing uses "ldap:"/"ldaps:", NOT "://": empty authorities can
 * serialize as "ldap:?query". No dial-time port defaults enter this value. */
int br_ldap_url_string(br_slice, br_bytes *out, bool *accepted, char **fatal);

typedef enum { BR_LDAP_ERR_NONE, BR_LDAP_ERR_OTHER } br_ldap_err_tag;
typedef struct {
    br_ldap_err_tag presence;
    bool has_op_error, is_deadline, is_canceled;
    br_bytes innermost;
} br_ldap_error;

/* Presence is independent of diagnostic length. OTHER may have empty bytes and
 * all facts false. NONE requires all facts false and empty innermost. Facts
 * project errors.As(*net.OpError) / errors.Is(context deadline/canceled), never
 * diagnostic text, LDAP result codes or verification/determinate verdicts.
 * innermost is the owned unwrapToLast Error() projection on EVERY return. */
void br_ldap_error_clear(br_ldap_error *);

typedef struct {
    int (*dial)(void *user, br_slice url, bool tls, bool insecure_skip_verify,
                const br_scan_ctx *, int64_t timeout_ns,
                void **handle, br_ldap_error *ordinary, char **fatal);
    int (*bind)(void *user, void *handle, const br_scan_ctx *,
                br_slice username, br_slice password,
                br_ldap_error *ordinary, char **fatal);
    int (*starttls)(void *user, void *handle, bool insecure_skip_verify,
                    br_ldap_error *ordinary, char **fatal);
    void (*close)(void *user, void *handle);
} br_ldap_io;

/* Whole DialURL / BindContext / StartTLS / Close library calls, not a protocol
 * engine or permission for native LDAP/DNS/authentication. Zero means completed
 * with success or ordinary error; EVERY nonzero is fatal, including +1. All
 * published ordinary/fatal bytes are owned even on nonzero returns. Dial only
 * publishes a non-NULL handle on success; callback cleans unpublished partial
 * handles. Close consumes each transferred handle once, including after fatal
 * bind/StartTLS. Library-internal idempotent closes do not consume the handle.
 * Dial's timeout is 5000000000ns, NOT a new blanket bind/StartTLS deadline.
 * StartTLS uses the connection context established by dial, not a new context.
 * Borrow arguments only through each call; caller owns user lifetime and
 * thread safety/quiescence. No globals, HTTP userdata or native fallback. */
typedef struct {
    br_regex *uri, *username, *password, *iad;
    const br_ldap_io *io;
    void *io_user;
} br_ldap_state;

typedef struct br_ldap_binding br_ldap_binding;
/* Clone initialized LDAP type901/v0 descriptor/state and copy the vtable.
 * Base regex/descriptor storage stays borrowed and lifetime-valid. NULL base
 * io means verification is explicitly unsupported, not successful. */
int br_ldap_binding_init(const br_detector *base, const br_ldap_io *, void *user,
                         br_ldap_binding **out, char **fatal);
const br_detector *br_ldap_binding_detector(const br_ldap_binding *);
void br_ldap_binding_destroy(br_ldap_binding *);

#endif
