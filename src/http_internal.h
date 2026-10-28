/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_HTTP_INTERNAL_H
#define BRIAR_HTTP_INTERNAL_H

#include "briar.h"

/* Private owned client, not a public ABI1 layout or profile extension. One
 * instance represents one upstream client transport's singleflight namespace. */
typedef struct br_http_client br_http_client;
typedef struct {
    br_transport transport;
    /* Release backend.user and its transitive dependencies after drain. A NULL
     * destructor is valid only for a genuinely process-lifetime/null backend. */
    void (*destroy)(void *user);
} br_http_owned_backend;

/* Success transfers backend ownership; failure leaves it with the caller.
 * The backend must be thread-safe, honor deadlines, and never synchronously
 * re-enter an owned client. Ordinary borrowed ABI1 transports do not qualify.
 * Initially support only the represented SANE/LOCAL client policies. */
int br_http_client_init(br_http_client **out, br_http_owned_backend backend,
                        br_http_profile profile, char **error);
const br_transport *br_http_client_transport(br_http_client *client);
/* Close admission and wait for active sends and workers, including work whose
 * callers all cancelled. Do not abort shared work when the last waiter leaves.
 * Replays may still be released after drain, while the client remains alive. */
int br_http_client_drain(br_http_client *client, char **error);
/* Requires external send/release quiescence and all outward responses released.
 * Drain before destroying the backend, never before every waiter can finish. */
void br_http_client_destroy(br_http_client *client);

/* Recognize exact private callbacks before interpreting transport.user. This
 * identifies this implementation, not an arbitrary transport capability claim. */
bool br_http_client_is_owned(const br_transport *transport);

/* Parent-owned raw backend path: ordinary structural/header/UA/timeout setup,
 * but no singleflight admission or key stripping. Owned clients call it with a
 * retained raw backend and a fully owned cancellation-detached context/request;
 * ordinary br_http_send calls it only after rejecting unsupported keyed I/O. */
int br_http_backend_send(const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error);

#endif
