/* SPDX-License-Identifier: AGPL-3.0-only
 * Singleflight ordering follows golang.org/x/sync v0.21.0 singleflight:
 * Copyright 2013 The Go Authors. BSD-3-Clause, LICENSES/BSD-3-Clause-Go.txt.
 * Response/cancellation policy follows pinned pkg/detectors/http.go.
 */
#include "http_internal.h"

#include <json-c/json.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct br_http_flight br_http_flight;
struct br_http_client {
    br_transport transport;
    br_http_owned_backend backend;
    br_http_profile profile;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    pthread_attr_t worker_attr;
    bool closed;
    size_t active, workers;
    br_http_flight *flights;
};
struct br_http_flight {
    br_http_client *client;
    br_http_flight *next;
    size_t refs;
    bool ready;
    int rc;
    char *error;
    br_http_response response;
    br_http_request request;
    br_http_prepared_request prepared;
    br_slice key; /* Immutable lookup bytes through worker cleanup. */
    br_scan_ctx ctx;
    br_endpoints endpoints;
};

/* Reject cross-client callback cycles too, not merely same-key recursion. */
static _Thread_local bool in_backend;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

static int64_t now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void response_clear(br_http_response *r)
{
    for (size_t i = 0; i < r->nheaders; ++i) {
        free((void *)r->headers[i].name);
        free((void *)r->headers[i].value);
    }
    free((void *)r->headers);
    free((void *)r->body.data);
    free((void *)r->body_error);
    memset(r, 0, sizeof(*r));
}

static int copy_string(const char *src, const char **dst)
{
    *dst = src ? strdup(src) : NULL;
    return src && !*dst;
}

static int copy_bytes(br_slice src, br_slice *dst)
{
    *dst = (br_slice){0};
    if (!src.data) return src.len != 0;
    unsigned char *p = malloc(src.len ? src.len : 1);
    if (!p) return 1;
    if (src.len) memcpy(p, src.data, src.len);
    *dst = (br_slice){p, src.len};
    return 0;
}

static int copy_headers(const br_header *src, size_t n, const br_header **dst)
{
    *dst = NULL;
    if (!n) return 0;
    if (!src || n > SIZE_MAX / sizeof(br_header)) return 1;
    br_header *h = calloc(n, sizeof(*h));
    if (!h) return 1;
    for (size_t i = 0; i < n; ++i) {
        if (copy_string(src[i].name, &h[i].name) ||
            copy_string(src[i].value, &h[i].value)) {
            br_http_response partial = {.headers = h, .nheaders = n};
            response_clear(&partial);
            return 1;
        }
    }
    *dst = h;
    return 0;
}

static int response_copy(const br_http_response *src, br_http_response *dst)
{
    *dst = (br_http_response){0};
    if (copy_headers(src->headers, src->nheaders, &dst->headers)) return 1;
    dst->nheaders = src->nheaders;
    if (copy_bytes(src->body, &dst->body) ||
        copy_string(src->body_error, &dst->body_error)) {
        response_clear(dst);
        return 1;
    }
    dst->status = src->status;
    return 0;
}

static void snapshot_clear(br_http_flight *f)
{
    free((void *)f->request.method);
    free((void *)f->request.url);
    br_http_response headers = {.headers = f->request.headers,
                               .nheaders = f->request.nheaders};
    response_clear(&headers);
    free((void *)f->request.body.data);
    free((void *)f->request.dedup_key.data);
    free((void *)f->ctx.user_agent);
    for (size_t i = 0; i < f->endpoints.nconfigured; ++i)
        free((void *)f->endpoints.configured[i]);
    free((void *)f->endpoints.configured);
    free((void *)f->endpoints.cloud);
    if (f->ctx.options) json_object_put((br_json *)f->ctx.options);
    f->request = (br_http_request){0};
    f->ctx = (br_scan_ctx){0};
    f->endpoints = (br_endpoints){0};
}

static int snapshot(br_http_flight *f, const br_scan_ctx *ctx,
                    const br_http_request *r, int64_t deadline, char **error)
{
    f->request.profile = r->profile;
    f->request.timeout_ms = r->timeout_ms;
    f->request.detector_type = r->detector_type;
    f->ctx.transport = &f->client->backend.transport;
    f->ctx.deadline_monotonic_ms = deadline;
    if (copy_string(r->method, &f->request.method) ||
        copy_string(r->url, &f->request.url) ||
        copy_headers(r->headers, r->nheaders, &f->request.headers)) return 1;
    f->request.nheaders = r->nheaders;
    if (copy_bytes(r->body, &f->request.body) ||
        copy_bytes(r->dedup_key, &f->request.dedup_key) ||
        copy_string(ctx->user_agent, &f->ctx.user_agent)) return 1;
    if (ctx->options) {
        /* json-c refcounts need not be atomic. Never retain the caller's tree
         * across detached work; standard deep copy rejects unsupported state. */
        br_json *options = NULL;
        int rc = json_object_deep_copy((br_json *)ctx->options, &options, NULL);
        f->ctx.options = options; /* Also clean a partial clone on failure. */
        if (rc) return fail(error, "unsupported or uncopyable HTTP options snapshot");
    }
    if (!ctx->endpoints) return 0;
    const br_endpoints *e = ctx->endpoints;
    f->ctx.endpoints = &f->endpoints;
    f->endpoints.use_cloud = e->use_cloud;
    f->endpoints.use_found = e->use_found;
    if (copy_string(e->cloud, &f->endpoints.cloud)) return 1;
    if (e->nconfigured) {
        if (!e->configured || e->nconfigured > SIZE_MAX / sizeof(char *)) return 1;
        const char **a = calloc(e->nconfigured, sizeof(*a));
        if (!a) return 1;
        f->endpoints.configured = a;
        f->endpoints.nconfigured = e->nconfigured;
        for (size_t i = 0; i < e->nconfigured; ++i)
            if (copy_string(e->configured[i], &a[i])) return 1;
    }
    return 0;
}

/* All references are protected by the client mutex. Snapshot state is cleaned
 * separately, before publishing completion or allowing drain to finish. */
static void flight_put(br_http_flight *f)
{
    if (--f->refs) return;
    response_clear(&f->response);
    free(f->error);
    free(f);
}

static void unlink_flight(br_http_client *c, br_http_flight *f)
{
    br_http_flight **p = &c->flights;
    while (*p != f) p = &(*p)->next;
    *p = f->next;
}

static void *worker(void *user)
{
    br_http_flight *f = user;
    br_http_client *c = f->client;
    br_http_response raw = {0};
    in_backend = true;
    f->rc = br_http_request_prepare(&f->ctx, &f->request, &f->prepared, &f->error);
    if (!f->rc) {
        f->rc = br_http_backend_send(&f->ctx, &f->prepared, &raw, &f->error);
        if (!f->rc && raw.body_error) {
            f->rc = fail(&f->error, raw.body_error);
        } else if (!f->rc && response_copy(&raw, &f->response)) {
            f->rc = fail(&f->error, "out of memory buffering HTTP response");
        }
        c->backend.transport.release(c->backend.transport.user, &raw);
    }
    br_http_request_clear(&f->prepared);
    /* Keep the key for lookup until it is removed, but destroy all other owned
     * context values outside the lock (JSON may have a custom destructor). */
    br_slice key = f->request.dedup_key;
    f->request.dedup_key = (br_slice){0};
    snapshot_clear(f);
    pthread_mutex_lock(&c->mutex);
    /* Remove under lock before publishing readiness, not at replay release. */
    unlink_flight(c, f);
    free((void *)key.data);
    f->ready = true;
    flight_put(f);
    --c->workers;
    pthread_cond_broadcast(&c->changed);
    pthread_mutex_unlock(&c->mutex);
    in_backend = false;
    return NULL;
}

static void owned_release(void *user, br_http_response *response)
{
    (void)user;
    response_clear(response);
}

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *r,
                       br_http_response *out, char **error)
{
    br_http_client *c = user;
    if (in_backend) return fail(error, "unsupported: owned HTTP client backend re-entry");
    int64_t entry = now_ms();
    if (entry < 0) return fail(error, "monotonic clock unavailable");
    if (r->profile != c->profile) return fail(error, "owned HTTP client profile mismatch");
    if (!r->method || !*r->method || !r->url ||
        (r->nheaders && !r->headers) || (!r->body.data && r->body.len) ||
        (!r->dedup_key.data && r->dedup_key.len))
        return fail(error, "invalid HTTP request");
    uint32_t timeout = r->timeout_ms ? r->timeout_ms :
                       c->profile == BR_HTTP_SANE ? 5000 : 10000;
    int64_t deadline = entry + timeout;
    if (ctx->deadline_monotonic_ms && ctx->deadline_monotonic_ms < deadline)
        deadline = ctx->deadline_monotonic_ms;
    pthread_mutex_lock(&c->mutex);
    if (c->closed) {
        pthread_mutex_unlock(&c->mutex);
        return fail(error, "owned HTTP client is drained");
    }
    ++c->active;
    if (!r->dedup_key.len) {
        pthread_mutex_unlock(&c->mutex);
        br_scan_ctx local = *ctx;
        local.transport = &c->backend.transport;
        local.deadline_monotonic_ms = deadline;
        br_http_response raw = {0};
        br_http_prepared_request prepared = {0};
        in_backend = true;
        int rc = br_http_request_prepare(&local, r, &prepared, error);
        if (!rc) {
            rc = br_http_backend_send(&local, &prepared, &raw, error);
            if (!rc && response_copy(&raw, out))
                rc = fail(error, "out of memory copying HTTP response");
            c->backend.transport.release(c->backend.transport.user, &raw);
        }
        br_http_request_clear(&prepared);
        in_backend = false;
        pthread_mutex_lock(&c->mutex);
        --c->active;
        pthread_cond_broadcast(&c->changed);
        pthread_mutex_unlock(&c->mutex);
        return rc;
    }
    br_http_flight *f;
    for (f = c->flights; f; f = f->next)
        if (f->key.len == r->dedup_key.len &&
            !memcmp(f->key.data, r->dedup_key.data, r->dedup_key.len)) break;
    if (f) {
        ++f->refs;
    } else {
        f = calloc(1, sizeof(*f));
        if (!f) goto allocation_failed;
        f->client = c;
        if (snapshot(f, ctx, r, deadline, error)) {
            pthread_mutex_unlock(&c->mutex);
            snapshot_clear(f);
            free(f);
            pthread_mutex_lock(&c->mutex);
            goto allocation_failed;
        }
        f->key = f->request.dedup_key;
        f->refs = 2; /* Worker and first waiter; register before launch/select. */
        f->next = c->flights;
        c->flights = f;
        ++c->workers;
        pthread_t thread;
        if (pthread_create(&thread, &c->worker_attr, worker, f)) {
            unlink_flight(c, f);
            pthread_mutex_unlock(&c->mutex);
            snapshot_clear(f);
            free(f);
            pthread_mutex_lock(&c->mutex);
            --c->workers;
            goto allocation_failed;
        }
    }
    int rc;
    for (;;) {
        if (f->ready) {
            rc = f->rc;
            if (rc) {
                if (error) *error = strdup(f->error ? f->error : "HTTP transport failed");
            } else if (response_copy(&f->response, out)) {
                rc = fail(error, "out of memory replaying HTTP response");
            }
            break;
        }
        /* ABI1 exposes only a polling cancellation callback. Never call it
         * with our mutex held; each waiter keeps its own context/deadline. */
        pthread_mutex_unlock(&c->mutex);
        const char *stop = ctx->cancelled && ctx->cancelled(ctx->cancel_user) ?
                           "context canceled" : NULL;
        int64_t now = now_ms();
        if (!stop && (now < 0 || now >= deadline))
            stop = now < 0 ? "monotonic clock unavailable" : "context deadline exceeded";
        pthread_mutex_lock(&c->mutex);
        if (stop) { rc = fail(error, stop); break; }
        int64_t until = now + 5;
        if (until > deadline) until = deadline;
#ifdef __APPLE__
        /* Darwin lacks pthread_condattr_setclock. Relative waits avoid mixing
         * a monotonic deadline with the condition variable's realtime clock. */
        int64_t remaining = until - now;
        struct timespec wake = {.tv_sec = (time_t)(remaining / 1000),
                                .tv_nsec = (long)(remaining % 1000) * 1000000};
        pthread_cond_timedwait_relative_np(&c->changed, &c->mutex, &wake);
#else
        struct timespec wake = {.tv_sec = (time_t)(until / 1000),
                                .tv_nsec = (long)(until % 1000) * 1000000};
        pthread_cond_timedwait(&c->changed, &c->mutex, &wake);
#endif
    }
    flight_put(f);
    --c->active;
    pthread_cond_broadcast(&c->changed);
    pthread_mutex_unlock(&c->mutex);
    return rc;

allocation_failed:
    --c->active;
    pthread_cond_broadcast(&c->changed);
    pthread_mutex_unlock(&c->mutex);
    return error && *error ? 1 : fail(error, "unable to allocate or launch HTTP flight");
}

bool br_http_client_is_owned(const br_transport *transport)
{
    return transport && transport->send == owned_send && transport->release == owned_release;
}

int br_http_client_init(br_http_client **out, br_http_owned_backend backend,
                        br_http_profile profile, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!out || !backend.transport.send || !backend.transport.release ||
        br_http_client_is_owned(&backend.transport) ||
        (profile != BR_HTTP_SANE && profile != BR_HTTP_DETECTOR_LOCAL &&
         profile != BR_HTTP_DETECTOR_PUBLIC))
        return fail(error, "invalid owned HTTP backend or profile");
    br_http_client *c = calloc(1, sizeof(*c));
    if (!c) return fail(error, "out of memory creating HTTP client");
    if (pthread_mutex_init(&c->mutex, NULL)) goto failed;
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr)) goto mutex_failed;
    int rc = 0;
#ifndef __APPLE__
    rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    if (!rc) rc = pthread_cond_init(&c->changed, &attr);
    pthread_condattr_destroy(&attr);
    if (rc) goto mutex_failed;
    if (pthread_attr_init(&c->worker_attr)) goto cond_failed;
    if (pthread_attr_setdetachstate(&c->worker_attr, PTHREAD_CREATE_DETACHED)) {
        pthread_attr_destroy(&c->worker_attr);
        goto cond_failed;
    }
    c->backend = backend;
    c->profile = profile;
    c->transport = (br_transport){c, owned_send, owned_release};
    *out = c;
    return 0;
cond_failed:
    pthread_cond_destroy(&c->changed);
mutex_failed:
    pthread_mutex_destroy(&c->mutex);
failed:
    free(c);
    return fail(error, "unable to initialize HTTP client synchronization");
}

const br_transport *br_http_client_transport(br_http_client *client)
{
    return client ? &client->transport : NULL;
}

int br_http_client_drain(br_http_client *c, char **error)
{
    if (error) *error = NULL;
    if (!c) return fail(error, "invalid owned HTTP client");
    if (in_backend) return fail(error, "unsupported: owned HTTP client backend re-entry");
    pthread_mutex_lock(&c->mutex);
    c->closed = true;
    while (c->active || c->workers) pthread_cond_wait(&c->changed, &c->mutex);
    pthread_mutex_unlock(&c->mutex);
    return 0;
}

void br_http_client_destroy(br_http_client *c)
{
    if (!c || br_http_client_drain(c, NULL)) return;
    if (c->backend.destroy) c->backend.destroy(c->backend.transport.user);
    pthread_attr_destroy(&c->worker_attr);
    pthread_cond_destroy(&c->changed);
    pthread_mutex_destroy(&c->mutex);
    free(c);
}
