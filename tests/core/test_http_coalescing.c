/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/http_internal.h"

#include <json-c/json.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static atomic_uint assertions;
#define CHECK(x) do { atomic_fetch_add(&assertions, 1); if (!(x)) { \
    fprintf(stderr, "FAIL HTTP coalescing:%d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static int64_t now_ms(void)
{
    struct timespec t;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void pause_ms(void)
{
    struct timespec t = {.tv_nsec = 1000000};
    nanosleep(&t, NULL);
}
typedef struct { atomic_bool cancelled, seen; } probe;
static bool cancelled(void *user)
{
    probe *p = user;
    atomic_store(&p->seen, true);
    return atomic_load(&p->cancelled);
}
static void seen(probe *p)
{
    int64_t end = now_ms() + 2000;
    while (!atomic_load(&p->seen) && now_ms() < end) pause_ms();
    CHECK(atomic_load(&p->seen));
}

typedef struct held_request {
    struct held_request *next;
    br_http_response *response;
    const br_http_request *request;
    const br_scan_ctx *ctx;
    br_http_request fields;
    int64_t deadline;
    char *method, *url, *user_agent;
    bool inspect;
} held_request;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    held_request *held;
    unsigned calls, releases;
    bool open, inspect, fail_send;
    const char *body_error;
    int64_t deadline;
    uint32_t timeout;
    br_http_profile profile;
    br_bytes last_key;
    const br_transport *reenter;
    atomic_uint *destroyed;
} backend;

static void free_response(br_http_response *r)
{
    for (size_t i = 0; i < r->nheaders; ++i) {
        free((void *)r->headers[i].name);
        free((void *)r->headers[i].value);
    }
    free((void *)r->headers);
    free((void *)r->body.data);
    free((void *)r->body_error);
    *r = (br_http_response){0};
}
static void backend_release(void *user, br_http_response *r)
{
    backend *b = user;
    pthread_mutex_lock(&b->mutex);
    held_request **p = &b->held;
    while (*p && (*p)->response != r) p = &(*p)->next;
    held_request *h = *p;
    if (h) *p = h->next;
    ++b->releases;
    pthread_cond_broadcast(&b->changed);
    pthread_mutex_unlock(&b->mutex);
    if (h) {
        /* Retain the exact request pointer handed to send, not merely its
         * strings: prepared object, synthesized array and UA must all survive
         * through release, including failed sends and abandoned first callers. */
        const br_http_request *q = h->request;
        CHECK(q->headers == h->fields.headers && q->nheaders == h->fields.nheaders);
        CHECK(q->method == h->fields.method && !strcmp(q->method, h->method));
        CHECK(q->url == h->fields.url && !strcmp(q->url, h->url));
        CHECK(q->body.data == h->fields.body.data && q->body.len == h->fields.body.len);
        CHECK(q->dedup_key.data == h->fields.dedup_key.data && q->dedup_key.len == h->fields.dedup_key.len);
        CHECK(q->timeout_ms == h->fields.timeout_ms && q->profile == h->fields.profile);
        const br_header *ua = &q->headers[q->nheaders - 1];
        CHECK(!strcmp(ua->name, "User-Agent") && !strcmp(ua->value, h->user_agent));
        CHECK(h->ctx->deadline_monotonic_ms == h->deadline);
        if (h->inspect) {
            CHECK(q->nheaders == 2 && !strcmp(q->headers[0].name, "X-Owned"));
            CHECK(!strcmp(q->headers[0].value, "winner"));
            CHECK(!strcmp(h->ctx->user_agent, "snapshot"));
        }
        free(h->method); free(h->url); free(h->user_agent); free(h);
    }
    free_response(r);
}
static int backend_send(void *user, const br_scan_ctx *ctx, const br_http_request *r,
                        br_http_response *out, char **error)
{
    backend *b = user;
    CHECK(ctx->deadline_monotonic_ms > 0 && r->timeout_ms > 0);
    if (r->dedup_key.len) CHECK(!ctx->cancelled && !ctx->cancel_user);
    CHECK(r->nheaders && r->headers);
    held_request *h = calloc(1, sizeof(*h)); CHECK(h);
    h->response = out; h->request = r; h->ctx = ctx; h->fields = *r;
    h->deadline = ctx->deadline_monotonic_ms;
    h->method = strdup(r->method); h->url = strdup(r->url);
    h->user_agent = strdup(r->headers[r->nheaders - 1].value);
    CHECK(h->method && h->url && h->user_agent);
    pthread_mutex_lock(&b->mutex);
    h->inspect = b->inspect;
    h->next = b->held; b->held = h;
    ++b->calls;
    b->deadline = ctx->deadline_monotonic_ms;
    b->timeout = r->timeout_ms;
    b->profile = r->profile;
    free(b->last_key.data);
    b->last_key = (br_bytes){0};
    if (r->dedup_key.len) {
        b->last_key.data = malloc(r->dedup_key.len);
        CHECK(b->last_key.data);
        memcpy(b->last_key.data, r->dedup_key.data, r->dedup_key.len);
        b->last_key.len = r->dedup_key.len;
    }
    pthread_cond_broadcast(&b->changed);
    while (!b->open && now_ms() < ctx->deadline_monotonic_ms) {
        int64_t until = ctx->deadline_monotonic_ms;
        struct timespec t = {.tv_sec = (time_t)(until / 1000),
                             .tv_nsec = (long)(until % 1000) * 1000000};
        pthread_cond_timedwait(&b->changed, &b->mutex, &t);
    }
    bool expired = now_ms() >= ctx->deadline_monotonic_ms;
    bool inspect = b->inspect, failed = b->fail_send;
    const char *body_error = b->body_error;
    const br_transport *reenter = b->reenter;
    pthread_mutex_unlock(&b->mutex);
    if (inspect) {
        static const unsigned char expected_body[] = {'a', 0, 'z'};
        CHECK(!strcmp(r->method, "POST") && !strcmp(r->url, "https://synthetic.invalid/owned"));
        CHECK(r->body.len == sizeof(expected_body) && !memcmp(r->body.data, expected_body, sizeof(expected_body)));
        CHECK(r->nheaders == 2 && !strcmp(r->headers[0].name, "X-Owned"));
        CHECK(!strcmp(r->headers[0].value, "winner"));
        CHECK(!strcmp(r->headers[1].value, "TruffleHog snapshot"));
        CHECK(ctx->user_agent && !strcmp(ctx->user_agent, "snapshot"));
        CHECK(ctx->endpoints && ctx->endpoints->nconfigured == 1);
        CHECK(!strcmp(ctx->endpoints->configured[0], "https://endpoint.invalid"));
        CHECK(!strcmp(ctx->endpoints->cloud, "https://cloud.invalid"));
        CHECK(ctx->endpoints->use_cloud && ctx->endpoints->use_found);
        br_json *v = NULL;
        CHECK(json_object_object_get_ex(ctx->options, "owned", &v));
        CHECK(!strcmp(json_object_get_string(v), "value"));
        br_json *nested = NULL, *values = NULL;
        CHECK(json_object_object_get_ex(ctx->options, "nested", &nested));
        CHECK(json_object_object_get_ex(nested, "values", &values));
        CHECK(json_object_array_length(values) == 1);
        CHECK(!strcmp(json_object_get_string(json_object_array_get_idx(values, 0)), "nested-value"));
    }
    if (reenter) {
        br_scan_ctx nested = {.transport = reenter};
        br_http_request req = {.method = "GET", .url = "https://synthetic.invalid", .profile = BR_HTTP_SANE};
        br_http_response res = {0};
        char *e = NULL;
        CHECK(br_http_send(&nested, &req, &res, &e) != 0);
        CHECK(e && strstr(e, "re-entry"));
        free(e);
        br_http_release(&nested, &res);
    }
    if (expired) { *error = strdup("context deadline exceeded"); return 1; }
    br_header *headers = calloc(2, sizeof(*headers));
    CHECK(headers);
    headers[0] = (br_header){strdup("X-Replay"), strdup("first")};
    headers[1] = (br_header){strdup("X-Replay"), strdup("second")};
    unsigned char *body = malloc(3);
    CHECK(body && headers[0].name && headers[0].value && headers[1].name && headers[1].value);
    memcpy(body, "r\0p", 3);
    *out = (br_http_response){.status = 201, .headers = headers, .nheaders = 2,
                             .body = {body, 3}, .body_error = body_error ? strdup(body_error) : NULL};
    if (failed) { *error = strdup("synthetic send failure"); return 1; }
    return 0;
}
static void backend_destroy(void *user)
{
    backend *b = user;
    CHECK(b->calls == b->releases && !b->held);
    if (b->destroyed) atomic_fetch_add(b->destroyed, 1);
    free(b->last_key.data);
    pthread_cond_destroy(&b->changed);
    pthread_mutex_destroy(&b->mutex);
    free(b);
}
static backend *new_backend(void)
{
    backend *b = calloc(1, sizeof(*b));
    CHECK(b && !pthread_mutex_init(&b->mutex, NULL));
    pthread_condattr_t a;
    CHECK(!pthread_condattr_init(&a));
    CHECK(!pthread_condattr_setclock(&a, CLOCK_MONOTONIC));
    CHECK(!pthread_cond_init(&b->changed, &a));
    CHECK(!pthread_condattr_destroy(&a));
    return b;
}
static br_http_client *new_client(backend *b, br_http_profile profile)
{
    br_http_client *c = NULL;
    char *error = NULL;
    br_http_owned_backend owned = {{b, backend_send, backend_release}, backend_destroy};
    CHECK(!br_http_client_init(&c, owned, profile, &error));
    CHECK(c && !error && br_http_client_is_owned(br_http_client_transport(c)));
    return c;
}
static unsigned count(backend *b)
{
    pthread_mutex_lock(&b->mutex);
    unsigned n = b->calls;
    pthread_mutex_unlock(&b->mutex);
    return n;
}
static void started(backend *b, unsigned n)
{
    int64_t end = now_ms() + 2000;
    while (count(b) < n && now_ms() < end) pause_ms();
    CHECK(count(b) == n);
}
static void open_backend(backend *b)
{
    pthread_mutex_lock(&b->mutex);
    b->open = true;
    pthread_cond_broadcast(&b->changed);
    pthread_mutex_unlock(&b->mutex);
}
typedef struct {
    br_scan_ctx *ctx;
    br_http_request *request;
    br_http_response response;
    char *error;
    int rc;
    pthread_t thread;
} call;
static void *send_call(void *user)
{
    call *c = user;
    c->rc = br_http_send(c->ctx, c->request, &c->response, &c->error);
    return NULL;
}
static void launch(call *c) { CHECK(!pthread_create(&c->thread, NULL, send_call, c)); }
static void join(call *c) { CHECK(!pthread_join(c->thread, NULL)); }
static void release_call(const br_transport *t, call *c)
{
    br_scan_ctx ctx = {.transport = t};
    br_http_release(&ctx, &c->response);
    CHECK(!c->response.status && !c->response.body.data);
    free(c->error);
    c->error = NULL;
}
static br_http_request request(br_slice key)
{
    return (br_http_request){.method = "GET", .url = "https://synthetic.invalid", .profile = BR_HTTP_SANE,
                             .detector_type = 384, .dedup_key = key};
}
static br_slice key(void)
{
    static const unsigned char k[] = {'3','8','4',':','s',0,'x'};
    return (br_slice){k, sizeof(k)};
}

static void replay_and_namespaces(void)
{
    backend *b = new_backend(), *other = new_backend();
    br_http_client *c = new_client(b, BR_HTTP_SANE), *d = new_client(other, BR_HTTP_SANE);
    probe p[5] = {0};
    br_scan_ctx ctx[5];
    br_http_request req[5];
    call calls[5] = {0};
    for (size_t i = 0; i < 5; ++i) {
        ctx[i] = (br_scan_ctx){.transport = br_http_client_transport(i == 4 ? d : c),
                               .cancelled = cancelled, .cancel_user = &p[i]};
        req[i] = request(key());
        calls[i].ctx = &ctx[i]; calls[i].request = &req[i];
    }
    req[1].url = "https://different.invalid/waiter"; /* Key, not URL/method/type. */
    req[1].method = "POST"; req[1].detector_type = 999;
    launch(&calls[0]); started(b, 1);
    launch(&calls[1]); seen(&p[1]);
    CHECK(count(b) == 1);
    req[2].dedup_key.len--; /* Embedded NUL plus length matter. */
    launch(&calls[2]); started(b, 2);
    static const unsigned char distinct[] = {'3','8','4',':','s',0,'y'};
    req[3].dedup_key = (br_slice){distinct, sizeof(distinct)};
    launch(&calls[3]); started(b, 3);
    launch(&calls[4]); started(other, 1);
    open_backend(b); open_backend(other);
    for (size_t i = 0; i < 5; ++i) {
        join(&calls[i]); CHECK(!calls[i].rc && !calls[i].error);
        CHECK(calls[i].response.status == 201 && calls[i].response.nheaders == 2);
        CHECK(calls[i].response.body.len == 3 && !memcmp(calls[i].response.body.data, "r\0p", 3));
    }
    CHECK(calls[0].response.body.data != calls[1].response.body.data);
    CHECK(calls[0].response.headers != calls[1].response.headers);
    CHECK(calls[0].response.headers[0].value != calls[1].response.headers[0].value);
    ((unsigned char *)calls[0].response.body.data)[0] = 'z';
    ((char *)calls[0].response.headers[0].value)[0] = 'z';
    CHECK(calls[1].response.body.data[0] == 'r' && calls[1].response.headers[0].value[0] == 'f');
    /* Completed keys disappear even while all old replay objects are held. */
    call fresh = {.ctx = &ctx[0], .request = &req[0]};
    send_call(&fresh); CHECK(!fresh.rc && count(b) == 4);
    CHECK(b->last_key.len == key().len && !memcmp(b->last_key.data, key().data, key().len));
    CHECK(!br_http_client_drain(c, NULL));
    for (size_t i = 0; i < 5; ++i) release_call(ctx[i].transport, &calls[i]);
    release_call(ctx[0].transport, &fresh);
    br_http_client_destroy(c); br_http_client_destroy(d);
}

static void cancellation_and_owned_snapshot(void)
{
    backend *b = new_backend(); b->inspect = true;
    br_http_client *c = new_client(b, BR_HTTP_SANE);
    const br_transport *t = br_http_client_transport(c);
    probe *p = calloc(1, sizeof(*p));
    br_scan_ctx *ctx = calloc(1, sizeof(*ctx));
    br_http_request *r = malloc(sizeof(*r));
    br_endpoints *ep = calloc(1, sizeof(*ep));
    br_header *h = malloc(sizeof(*h));
    CHECK(p && ctx && r && ep && h);
    *r = request(key());
    r->method = strdup("POST"); r->url = strdup("https://synthetic.invalid/owned");
    unsigned char *body = malloc(3), *k = malloc(key().len);
    CHECK(body && k); memcpy(body, "a\0z", 3); memcpy(k, key().data, key().len);
    r->body = (br_slice){body, 3}; r->dedup_key = (br_slice){k, key().len};
    *h = (br_header){strdup("X-Owned"), strdup("winner")}; r->headers = h; r->nheaders = 1;
    const char **configured = malloc(sizeof(*configured)); CHECK(configured);
    configured[0] = strdup("https://endpoint.invalid");
    *ep = (br_endpoints){configured, 1, strdup("https://cloud.invalid"), true, true};
    br_json *options = json_object_new_object();
    json_object_object_add(options, "owned", json_object_new_string("value"));
    br_json *nested = json_object_new_object(), *values = json_object_new_array();
    br_json *leaf = json_object_new_string("nested-value");
    CHECK(nested && values && leaf);
    CHECK(!json_object_array_add(values, leaf));
    CHECK(!json_object_object_add(nested, "values", values));
    CHECK(!json_object_object_add(options, "nested", nested));
    *ctx = (br_scan_ctx){.transport = t, .cancelled = cancelled, .cancel_user = p,
                         .user_agent = strdup("snapshot"), .endpoints = ep, .options = options};
    call first = {.ctx = ctx, .request = r}; launch(&first); started(b, 1);
    atomic_store(&p->cancelled, true); join(&first);
    CHECK(first.rc && first.error && !strcmp(first.error, "context canceled"));
    release_call(t, &first);
    /* The backend is held at its barrier. Check identity while the original
     * tree still exists, then mutate and destroy it before continuation. */
    pthread_mutex_lock(&b->mutex);
    CHECK(b->held && b->held->ctx->options != options);
    br_json *copy_nested = NULL, *copy_values = NULL;
    CHECK(json_object_object_get_ex(b->held->ctx->options, "nested", &copy_nested));
    CHECK(json_object_object_get_ex(copy_nested, "values", &copy_values));
    CHECK(copy_nested != nested && copy_values != values);
    CHECK(json_object_array_get_idx(copy_values, 0) != leaf);
    CHECK(json_object_equal((br_json *)b->held->ctx->options, options));
    pthread_mutex_unlock(&b->mutex);
    CHECK(!json_object_object_add(options, "owned", json_object_new_string("mutated")));
    CHECK(!json_object_array_put_idx(values, 0, json_object_new_string("changed")));
    free((void *)r->method); free((void *)r->url); free(body); free(k);
    free((void *)h->name); free((void *)h->value); free(h); free(r);
    free((void *)configured[0]); free(configured); free((void *)ep->cloud); free(ep);
    free((void *)ctx->user_agent); json_object_put(options); free(ctx); free(p);
    probe waiter_probe = {0}, survivor_probe = {0};
    br_scan_ctx waiter_ctx = {.transport = t, .cancelled = cancelled, .cancel_user = &waiter_probe};
    br_scan_ctx survivor_ctx = {.transport = t, .cancelled = cancelled, .cancel_user = &survivor_probe};
    br_http_request req = request(key());
    call waiter = {.ctx = &waiter_ctx, .request = &req}, survivor = {.ctx = &survivor_ctx, .request = &req};
    launch(&waiter); seen(&waiter_probe);
    launch(&survivor); seen(&survivor_probe);
    atomic_store(&waiter_probe.cancelled, true); join(&waiter);
    CHECK(waiter.rc && !strcmp(waiter.error, "context canceled"));
    release_call(t, &waiter);
    CHECK(count(b) == 1);
    open_backend(b); join(&survivor); CHECK(!survivor.rc && !survivor.error);
    release_call(t, &survivor); br_http_client_destroy(c);
}

static void deadlines(void)
{
    backend *b = new_backend(); br_http_client *c = new_client(b, BR_HTTP_SANE);
    probe p[3] = {0}; br_scan_ctx ctx[3]; br_http_request req[3]; call calls[3] = {0};
    int64_t deadline = now_ms() + 250;
    for (size_t i = 0; i < 3; ++i) {
        ctx[i] = (br_scan_ctx){.transport = br_http_client_transport(c), .cancelled = cancelled, .cancel_user = &p[i]};
        req[i] = request(key()); calls[i].ctx = &ctx[i]; calls[i].request = &req[i];
    }
    ctx[0].deadline_monotonic_ms = deadline;
    launch(&calls[0]); started(b, 1);
    CHECK(b->deadline == deadline && b->timeout <= 250);
    req[1].timeout_ms = 25;
    launch(&calls[1]); seen(&p[1]); join(&calls[1]);
    CHECK(calls[1].rc && strstr(calls[1].error, "deadline"));
    launch(&calls[2]); seen(&p[2]);
    join(&calls[0]); join(&calls[2]);
    CHECK(calls[0].rc && calls[2].rc && strstr(calls[2].error, "deadline"));
    CHECK(count(b) == 1 && b->deadline == deadline);
    for (size_t i = 0; i < 3; ++i) release_call(ctx[i].transport, &calls[i]);
    br_http_client_destroy(c);
    /* Effective LOCAL client timeout starts at entry, not worker launch. */
    b = new_backend(); c = new_client(b, BR_HTTP_DETECTOR_LOCAL);
    br_scan_ctx local = {.transport = br_http_client_transport(c)};
    br_http_request r = request(key()); r.profile = BR_HTTP_DETECTOR_LOCAL; r.timeout_ms = 35;
    int64_t start = now_ms();
    call timeout = {.ctx = &local, .request = &r}; send_call(&timeout);
    CHECK(timeout.rc && b->deadline >= start + 35 && b->deadline <= start + 50);
    release_call(local.transport, &timeout); br_http_client_destroy(c);
}

static void errors_and_unkeyed(void)
{
    backend *b = new_backend(); b->body_error = "";
    br_http_client *c = new_client(b, BR_HTTP_SANE);
    probe p[2] = {0}; br_scan_ctx ctx[2]; call calls[2] = {0}; br_http_request r = request(key());
    for (size_t i = 0; i < 2; ++i) {
        ctx[i] = (br_scan_ctx){.transport = br_http_client_transport(c), .cancelled = cancelled, .cancel_user = &p[i]};
        calls[i].ctx = &ctx[i]; calls[i].request = &r;
    }
    launch(&calls[0]); started(b, 1); launch(&calls[1]); seen(&p[1]); open_backend(b);
    for (size_t i = 0; i < 2; ++i) {
        join(&calls[i]); CHECK(calls[i].rc && calls[i].error && !*calls[i].error);
        CHECK(!calls[i].response.status && !calls[i].response.headers && !calls[i].response.body.data);
    }
    CHECK(calls[0].error != calls[1].error);
    CHECK(b->releases == 1); calls[0].error[0] = '\0';
    for (size_t i = 0; i < 2; ++i) release_call(ctx[i].transport, &calls[i]);
    b->body_error = "partial body"; b->open = false;
    for (size_t i = 0; i < 2; ++i) atomic_store(&p[i].seen, false);
    launch(&calls[0]); started(b, 2); launch(&calls[1]); seen(&p[1]); open_backend(b);
    for (size_t i = 0; i < 2; ++i) {
        join(&calls[i]); CHECK(calls[i].rc && !strcmp(calls[i].error, "partial body"));
        CHECK(!calls[i].response.status && !calls[i].response.body.data);
    }
    CHECK(calls[0].error != calls[1].error);
    calls[0].error[0] = 'X'; CHECK(calls[1].error[0] == 'p');
    CHECK(b->releases == 2);
    for (size_t i = 0; i < 2; ++i) release_call(ctx[i].transport, &calls[i]);
    r.dedup_key = (br_slice){0};
    call plain = {.ctx = &ctx[0], .request = &r}; send_call(&plain);
    CHECK(!plain.rc && plain.response.status == 201 && !strcmp(plain.response.body_error, "partial body"));
    CHECK(b->releases == 3); release_call(ctx[0].transport, &plain);
    b->fail_send = true; r.dedup_key = key();
    send_call(&plain); CHECK(plain.rc && !strcmp(plain.error, "synthetic send failure"));
    CHECK(!plain.response.status && b->releases == 4); release_call(ctx[0].transport, &plain);
    r.dedup_key = (br_slice){0};
    send_call(&plain); CHECK(plain.rc && !strcmp(plain.error, "synthetic send failure"));
    CHECK(!plain.response.status && b->releases == 5); release_call(ctx[0].transport, &plain);
    br_http_client_destroy(c);
}

typedef struct { br_http_client *client; atomic_bool done; } drain_call;
static void *drain_thread(void *user)
{
    drain_call *d = user; CHECK(!br_http_client_drain(d->client, NULL));
    atomic_store(&d->done, true); return NULL;
}
static void options_cleanup(br_json *object, void *user)
{
    (void)object;
    atomic_fetch_add((atomic_uint *)user, 1);
}
static void unsupported_options(void)
{
    atomic_uint cleaned = 0;
    backend *b = new_backend(); b->open = true;
    br_http_client *c = new_client(b, BR_HTTP_SANE);
    br_json *options = json_object_new_object(), *custom = json_object_new_object();
    CHECK(options && custom);
    CHECK(!json_object_object_add(options, "plain", json_object_new_string("partial-copy")));
    json_object_set_userdata(custom, &cleaned, options_cleanup);
    CHECK(!json_object_object_add(options, "custom", custom));
    br_scan_ctx ctx = {.transport = br_http_client_transport(c), .options = options};
    br_http_request r = request(key()); call attempt = {.ctx = &ctx, .request = &r};
    send_call(&attempt);
    CHECK(attempt.rc && attempt.error && strstr(attempt.error, "options snapshot"));
    CHECK(count(b) == 0 && b->releases == 0 && atomic_load(&cleaned) == 0);
    CHECK(!attempt.response.status && !attempt.response.body.data);
    release_call(ctx.transport, &attempt);
    json_object_put(options); ctx.options = NULL;
    CHECK(atomic_load(&cleaned) == 1);
    CHECK(!br_http_client_drain(c, NULL));
    br_http_client_destroy(c);
}
static void drain_and_guards(void)
{
    atomic_uint destroyed = 0;
    backend *b = new_backend(); b->destroyed = &destroyed;
    br_http_client *c = new_client(b, BR_HTTP_SANE);
    backend *other = new_backend(); br_http_client *d = new_client(other, BR_HTTP_SANE);
    b->reenter = br_http_client_transport(d); /* Reject even unkeyed cross-client re-entry. */
    probe p = {0}; atomic_store(&p.cancelled, true);
    br_scan_ctx ctx = {.transport = br_http_client_transport(c), .cancelled = cancelled, .cancel_user = &p};
    br_json *options = json_object_new_object(); CHECK(options);
    CHECK(!json_object_object_add(options, "drain", json_object_new_string("abandoned")));
    ctx.options = options;
    br_http_request r = request(key()); call first = {.ctx = &ctx, .request = &r};
    send_call(&first); CHECK(first.rc && !strcmp(first.error, "context canceled"));
    started(b, 1); release_call(ctx.transport, &first);
    pthread_mutex_lock(&b->mutex);
    CHECK(b->held && b->held->ctx->options != options);
    pthread_mutex_unlock(&b->mutex);
    json_object_put(options); ctx.options = NULL;
    pthread_mutex_lock(&b->mutex);
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(b->held->ctx->options, "drain", &value));
    CHECK(!strcmp(json_object_get_string(value), "abandoned"));
    pthread_mutex_unlock(&b->mutex);
    drain_call drain = {.client = c}; pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, drain_thread, &drain));
    /* Admission polling observes closure, independent of scheduler timing. */
    int64_t end = now_ms() + 1000;
    do {
        send_call(&first);
        bool closed = first.error && strstr(first.error, "drained");
        release_call(ctx.transport, &first);
        if (closed) break;
        CHECK(now_ms() < end); pause_ms();
    } while (true);
    CHECK(!atomic_load(&drain.done) && !atomic_load(&destroyed));
    open_backend(b); CHECK(!pthread_join(thread, NULL)); CHECK(atomic_load(&drain.done));
    CHECK(count(other) == 0 && b->releases == 1);
    br_http_client_destroy(c); CHECK(atomic_load(&destroyed) == 1);
    br_http_owned_backend stacked = {*br_http_client_transport(d), NULL};
    br_http_client *bad = NULL; char *error = NULL;
    CHECK(br_http_client_init(&bad, stacked, BR_HTTP_SANE, &error) != 0 && !bad && error);
    free(error); error = NULL;
    br_http_request wrong = request(key()); wrong.profile = BR_HTTP_DETECTOR_LOCAL;
    br_scan_ctx dctx = {.transport = br_http_client_transport(d)}; br_http_response res = {0};
    CHECK(br_http_send(&dctx, &wrong, &res, &error) != 0 && strstr(error, "profile mismatch"));
    free(error); br_http_release(&dctx, &res);
    br_http_client_destroy(d);
    /* The real public guard still rejects keys on ordinary borrowed transports. */
    b = new_backend(); b->open = true;
    br_transport raw = {b, backend_send, backend_release};
    br_scan_ctx rawctx = {.transport = &raw}; error = NULL;
    CHECK(br_http_send(&rawctx, &r, &res, &error) != 0);
    CHECK(error && strstr(error, "unsupported HTTP request coalescing") && count(b) == 0);
    free(error); br_http_release(&rawctx, &res);
    /* The guard was before actual I/O; its required empty release is separate. */
    CHECK(b->releases == 1); b->releases = 0; backend_destroy(b);
}

static void public_owned_policy(void)
{
    backend *b = new_backend(), *other = new_backend();
    br_http_client *c = new_client(b, BR_HTTP_DETECTOR_PUBLIC);
    br_http_client *d = new_client(other, BR_HTTP_DETECTOR_PUBLIC);
    probe p[3] = {0}; br_scan_ctx ctx[3]; br_http_request req[3]; call calls[3] = {0};
    int64_t start = now_ms();
    for (size_t i = 0; i < 3; ++i) {
        ctx[i] = (br_scan_ctx){.transport = br_http_client_transport(i == 2 ? d : c),
                              .cancelled = cancelled, .cancel_user = &p[i]};
        req[i] = request(key()); req[i].profile = BR_HTTP_DETECTOR_PUBLIC;
        calls[i].ctx = &ctx[i]; calls[i].request = &req[i];
    }
    launch(&calls[0]); started(b, 1);
    launch(&calls[1]); seen(&p[1]);
    launch(&calls[2]); started(other, 1);
    CHECK(count(b) == 1 && count(other) == 1);
    CHECK(b->profile == BR_HTTP_DETECTOR_PUBLIC && other->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(b->timeout == 10000 && other->timeout == 10000);
    CHECK(b->deadline >= start + 10000 && b->deadline <= now_ms() + 10000);
    CHECK(b->last_key.len == key().len && !memcmp(b->last_key.data, key().data, key().len));
    atomic_store(&p[0].cancelled, true); join(&calls[0]);
    CHECK(calls[0].rc && calls[0].error && strstr(calls[0].error, "canceled"));
    CHECK(!calls[0].response.body.data && b->releases == 0);
    release_call(ctx[0].transport, &calls[0]);
    open_backend(b); open_backend(other);
    join(&calls[1]); join(&calls[2]);
    CHECK(!calls[1].rc && !calls[1].error && !calls[2].rc && !calls[2].error);
    CHECK(calls[1].response.status == 201 && calls[2].response.status == 201);
    CHECK(calls[1].response.body.len == 3 && !memcmp(calls[1].response.body.data, "r\0p", 3));
    release_call(ctx[1].transport, &calls[1]); release_call(ctx[2].transport, &calls[2]);

    br_http_response response = {0}; char *error = NULL;
    br_http_request wrong = request(key());
    CHECK(br_http_send(&ctx[1], &wrong, &response, &error) != 0 && error && strstr(error, "profile mismatch"));
    CHECK(count(b) == 1); free(error); error = NULL; br_http_release(&ctx[1], &response);
    /* An owned PUBLIC client is still not the source's DefaultTransport. */
    wrong.dedup_key = (br_slice){0}; wrong.timeout_ms = 5000; wrong.detector_type = 326;
    CHECK(br_http_default_transport_5s_send(&ctx[1], &wrong, &response, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported: default-transport HTTP client policy") && count(b) == 1);
    free(error); br_http_release(&ctx[1], &response);
    br_http_client_destroy(c); br_http_client_destroy(d);
}

int main(void)
{
    public_owned_policy();
    replay_and_namespaces();
    cancellation_and_owned_snapshot();
    deadlines();
    errors_and_unkeyed();
    unsupported_options();
    drain_and_guards();
    printf("HTTP coalescing: %u assertions, 0 failures\n", atomic_load(&assertions));
    return 0;
}
