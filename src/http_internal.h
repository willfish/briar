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

/* Private native runtime. Initialize before concurrent use, destroy after all
 * scan callers and response releases are quiescent. Source clients remain
 * distinct; drain all detached work before ending the curl initialization.
 * Binding changes only this runtime's raw context, never an injected/explicit
 * client, and recognizes built-in descriptor identities rather than types. */
typedef struct br_native_http br_native_http;
int br_native_http_init(br_native_http **out, char **error);
const br_transport *br_native_http_raw(const br_native_http *runtime);
void br_native_http_bind(const br_native_http *runtime, const br_detector *detector,
                         br_scan_ctx *context);
void br_native_http_destroy(br_native_http *runtime);
/* Legacy raw users must balance a successful initialization with curl cleanup. */
const br_transport *br_curl_transport_init(char **error);

/* Bounded byte-injection boundary for common.SaneHttpClientTimeOut(5s), whose
 * source wraps Go DefaultTransport rather than saneTransport. SANE/5000 here
 * projects request preparation ONLY, not transport-policy equivalence. Require
 * an explicitly installed backend that knowingly serves this contract. Reject
 * known native curl and all owned SANE/LOCAL clients before I/O, even copies.
 * Arbitrary forwarding wrappers cannot be detected/certified. No coalescing;
 * ordinary prepared storage still lasts only through send return. */
int br_http_default_transport_5s_send(const br_scan_ctx *ctx, const br_http_request *request,
                                     br_http_response *response, char **error);

/* Zero-initialize. Own only the synthesized array/UA; other pointers borrow
 * the caller's stable request snapshot. Keep this exact request address and
 * storage alive through raw backend send AND release, then clear it. */
typedef struct {
    br_http_request request;
    br_header *headers;
    char *user_agent;
} br_http_prepared_request;
int br_http_request_prepare(const br_scan_ctx *ctx, const br_http_request *request,
                            br_http_prepared_request *prepared, char **error);
void br_http_request_clear(br_http_prepared_request *prepared);
/* Send already-prepared values on the retained raw backend. No preparation,
 * timeout restart, key stripping, response release or request cleanup here. */
int br_http_backend_send(const br_scan_ctx *ctx, const br_http_prepared_request *prepared,
                         br_http_response *response, char **error);

#endif
