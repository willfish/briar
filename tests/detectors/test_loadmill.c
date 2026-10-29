/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <pthread.h>
#include <time.h>

int br_loadmill_init(const br_detector **out, char **error);

/* Established named-test seams observe provider originals and outward releases
 * without replacing transport callbacks, stripping keys or bypassing guards. */
#define br_http_send loadmill_real_send
#define br_http_release loadmill_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release
#define br_results_push loadmill_real_push
#define br_result_set_verification_error loadmill_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "Aa01234567Bb89cdef01Cc23456789Ddabcdef01";
static const char other[] = "Zz98765432Yy10fedcbaXx87654321Wwfedcba98";
static const char labels_url[] = "https://app.loadmill.com/api/v1/labels?filter=CI_enable";
static size_t fail_size, fail_after, fail_part_after, fail_push_after, fail_request_after, setter_calls, destroyed_backends;
static bool fail_next_malloc;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && size == fail_size && --fail_after == 0)) {
        fail_next_malloc = false; return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "key") && fail_request_after && --fail_request_after == 0) fail_next_malloc = true;
    return rc;
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return loadmill_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls; return loadmill_real_setter(result, cause, secrets, count);
}

static int64_t monotonic_ms(void)
{
    struct timespec ts; CHECK(!clock_gettime(CLOCK_MONOTONIC, &ts));
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void request_is(const br_http_request *r, const char *expected, bool effective, const br_scan_ctx *ctx)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, labels_url));
    CHECK(r->profile == BR_HTTP_SANE && r->detector_type == 758);
    CHECK(effective ? r->timeout_ms > 0 && r->timeout_ms <= 5000 : !r->timeout_ms);
    CHECK(!r->body.data && !r->body.len);
    CHECK(r->dedup_key.len == 44 && !memcmp(r->dedup_key.data, "758:", 4) && !memcmp(r->dedup_key.data + 4, expected, 40));
    CHECK(r->nheaders == (effective ? 3u : 2u));
    CHECK(!strcmp(r->headers[0].name, "Accept") && !strcmp(r->headers[0].value, "application/vnd.loadmill+json; version=3"));
    CHECK(!strcmp(r->headers[1].name, "Authorization") && !strncmp(r->headers[1].value, "Bearer ", 7));
    CHECK(!strcmp(r->headers[1].value + 7, expected));
    if (effective) {
        CHECK(ctx && !strcmp(r->headers[2].name, "User-Agent"));
        CHECK(!strcmp(r->headers[2].value, ctx->user_agent ? "TruffleHog loadmill-test" : "TruffleHog"));
    }
}

typedef struct {
    pthread_mutex_t mutex;
    size_t calls, releases, case_start, nkeys, pending_index;
    char keys[3][41];
    int statuses[3], codes[3];
    unsigned char bodies[3][3];
    char *send_error, *body_error;
    const br_http_request *pending;
    const br_scan_ctx *pending_ctx;
} owned_backend;

static void raw_request_is(const owned_backend *b)
{
    CHECK(b->pending && b->pending_ctx && b->pending_ctx->transport->user == b);
    CHECK(!b->pending_ctx->cancelled && !b->pending_ctx->cancel_user && b->pending_ctx->deadline_monotonic_ms > 0);
    request_is(b->pending, b->keys[b->pending_index], true, b->pending_ctx);
}

static int raw_send(void *user, const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    owned_backend *b = user;
    /* Serialize raw byte operations through release. State and response bytes
     * are heap-owned, deadline-aware, and never re-enter any owned client. */
    CHECK(!pthread_mutex_lock(&b->mutex)); CHECK(!b->pending);
    size_t i = b->calls - b->case_start; CHECK(i < b->nkeys);
    b->pending = r; b->pending_ctx = ctx; b->pending_index = i; ++b->calls; raw_request_is(b);
    b->bodies[i][0] = (unsigned char)i; b->bodies[i][1] = 0xff; b->bodies[i][2] = 0;
    *response = (br_http_response){.status = b->statuses[i], .body = {b->bodies[i], 3}, .body_error = b->body_error};
    if (monotonic_ms() >= ctx->deadline_monotonic_ms) { *error = strdup("context deadline exceeded"); CHECK(*error); return 1; }
    *error = b->codes[i] && b->send_error ? strdup(b->send_error) : NULL;
    CHECK(!b->codes[i] || !b->send_error || *error);
    return b->codes[i];
}

static void raw_release(void *user, br_http_response *response)
{
    owned_backend *b = user; raw_request_is(b);
    CHECK(response && b->releases + 1 == b->calls);
    /* Buffering must precede raw close; outward replays keep the old bytes. */
    memset(b->bodies[b->pending_index], 0xee, 3);
    ++b->releases; b->pending = NULL; b->pending_ctx = NULL;
    CHECK(!pthread_mutex_unlock(&b->mutex));
}

static void raw_destroy(void *user)
{
    owned_backend *b = user; CHECK(!pthread_mutex_lock(&b->mutex));
    CHECK(!b->pending && b->calls == b->releases);
    free(b->send_error); free(b->body_error);
    CHECK(!pthread_mutex_unlock(&b->mutex)); CHECK(!pthread_mutex_destroy(&b->mutex));
    free(b); ++destroyed_backends;
}

static br_http_client *owned_client(owned_backend **backend)
{
    owned_backend *b = calloc(1, sizeof(*b)); CHECK(b && !pthread_mutex_init(&b->mutex, NULL));
    br_http_owned_backend raw = {.transport = {b, raw_send, raw_release}, .destroy = raw_destroy};
    br_http_client *client = NULL; char *error = NULL;
    CHECK(br_http_client_init(&client, raw, BR_HTTP_SANE, &error) == 0 && client && !error);
    CHECK(br_http_client_is_owned(br_http_client_transport(client))); *backend = b; return client;
}

static void configure(owned_backend *b, const char *const *keys, size_t count, int status, int code,
                       const char *send_error, const char *body_error, const int *codes)
{
    CHECK(count > 0 && count <= 3 && !pthread_mutex_lock(&b->mutex)); CHECK(!b->pending);
    b->case_start = b->calls; b->nkeys = count;
    free(b->send_error); free(b->body_error);
    b->send_error = send_error ? strdup(send_error) : NULL; b->body_error = body_error ? strdup(body_error) : NULL;
    CHECK(!send_error || b->send_error); CHECK(!body_error || b->body_error);
    for (size_t i = 0; i < count; ++i) { memcpy(b->keys[i], keys[i], 41); b->statuses[i] = status; b->codes[i] = codes ? codes[i] : code; }
    CHECK(!pthread_mutex_unlock(&b->mutex));
}

static size_t raw_completed(owned_backend *b)
{
    CHECK(!pthread_mutex_lock(&b->mutex)); CHECK(!b->pending && b->calls == b->releases);
    size_t calls = b->calls; CHECK(!pthread_mutex_unlock(&b->mutex)); return calls;
}

static struct {
    const br_scan_ctx *ctx;
    br_results *out;
    owned_backend *backend;
    const char *const *keys;
    size_t count, initial_len, release_len, sends, releases, next_deferred;
    bool closing, ok[3], released[3];
    const br_http_request *requests[3];
    br_http_response *responses[3];
} observed;

static void observe(const br_scan_ctx *ctx, br_results *out, owned_backend *b, const char *const *keys,
                     size_t count, size_t release_len)
{
    memset(&observed, 0, sizeof(observed)); observed.ctx = ctx; observed.out = out; observed.backend = b;
    observed.keys = keys; observed.count = count; observed.initial_len = out->len; observed.release_len = release_len;
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    size_t i = observed.sends; CHECK(ctx == observed.ctx && i < observed.count && !observed.closing);
    CHECK(observed.out->len == observed.initial_len + i); request_is(r, observed.keys[i], false, ctx);
    observed.requests[i] = r; observed.responses[i] = response; ++observed.sends;
    int rc = loadmill_real_send(ctx, r, response, error);
    if (observed.backend) (void)raw_completed(observed.backend); /* Raw release is BEFORE Do returns. */
    observed.ok[i] = rc == 0;
    if (!rc) {
        CHECK(!response->body_error && response->body.len == 3);
        CHECK(response->body.data[0] == i && response->body.data[1] == 0xff && response->body.data[2] == 0);
    }
    request_is(r, observed.keys[i], false, ctx); return rc;
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    size_t i = 0;
    while (i < observed.sends && (observed.responses[i] != response || observed.released[i])) ++i;
    CHECK(ctx == observed.ctx && i < observed.sends); request_is(observed.requests[i], observed.keys[i], false, ctx);
    if (observed.ok[i]) {
        if (!observed.closing) { observed.closing = true; observed.next_deferred = observed.sends; }
        while (observed.next_deferred && !observed.ok[observed.next_deferred - 1]) --observed.next_deferred;
        CHECK(observed.next_deferred && --observed.next_deferred == i && observed.out->len == observed.release_len);
    } else CHECK(!observed.closing && observed.out->len == observed.initial_len + i);
    loadmill_real_release(ctx, response);
    request_is(observed.requests[i], observed.keys[i], false, ctx); observed.released[i] = true; ++observed.releases;
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(other) == 40);
    CHECK(br_loadmill_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Loadmill detector output")); free(error); error = NULL;
    CHECK(br_loadmill_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:loadmill)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_loadmill_init(&d, &error) == -1 && !d && error && !fail_after); free(error); error = NULL;
    CHECK(br_loadmill_init(&d, &error) == 0 && d && !error);
    CHECK(br_loadmill_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 758 && d->version == 0 && !strcmp(d->name, "Loadmill") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Loadmill is a testing service for APIs and web applications. Loadmill API keys can be used to access and manage test scenarios and results."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "loadmill"));
    CHECK(d->state && d->scan && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint); return d;
}

static void result_is(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 758, expected, "key"); CHECK(r->raw.len == 40 && r->verified == verified && !r->verification_error);
}

static void extraction_case(const br_detector *d, const void *data, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results r = test_scan(d, &ctx, false, data, len);
    CHECK(r.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result_is(&r.items[0], expected, false);
    br_results_clear(&r);
}

static void extraction(const br_detector *d)
{
    char input[320], changed[41];
    snprintf(input, sizeof(input), "loadmill '%s'", key); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "preLoAdMiLlsuffix:\r\n%s", other); extraction_case(d, input, strlen(input), other);
    extraction_case(d, key, strlen(key), NULL);
    memcpy(changed, key, 41); changed[12] = '-'; snprintf(input, sizeof(input), "loadmill %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 41); changed[39] = '\0'; snprintf(input, sizeof(input), "loadmill %s", changed); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loadmill _%s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loadmill %s_", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "loadmill %s0", key); extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'A', 40); changed[40] = '\0'; snprintf(input, sizeof(input), "loadmill %s", changed); extraction_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "loadmill \xc3\xa9%s\xc3\xa9", key); extraction_case(d, input, strlen(input), key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = 8; memcpy(input, "loadmill", at); memset(input + at, ':', gap); at += gap;
        memcpy(input + at, key, 41); extraction_case(d, input, at + 40, gap == 40 ? key : NULL);
        at = 8; for (size_t i = 0; i < gap; ++i) { memcpy(input + at, "\xe2\x98\x83", 3); at += 3; }
        memcpy(input + at, key, 41); extraction_case(d, input, at + 40, gap == 40 ? key : NULL);
    }
    memcpy(input, "loadmill", 8); input[8] = '\0'; input[9] = '\r'; input[10] = '\n'; memcpy(input + 11, key, 41);
    extraction_case(d, input, 51, key); extraction_case(d, NULL, 0, NULL);
    snprintf(input, sizeof(input), "loadmill %s\nloadmill %s\nloadmill %s", key, other, key);
    const char *keys[] = {key, other, key}; br_results r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], false);
    br_results_clear(&r);
    fail_request_after = 1; snprintf(input, sizeof(input), "loadmill %s", key);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len && !fail_request_after && fail_next_malloc);
    fail_next_malloc = false; br_results_clear(&r);
}

static void scan_into(const br_detector *d, const br_scan_ctx *ctx, const char *input, br_results *r)
{
    char *error = NULL;
    CHECK(d->scan(d, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, r, &error) == 0 && !error);
    CHECK(observed.releases == observed.sends);
}

static void owned_verification(const br_detector *d, br_http_client *client, owned_backend *b)
{
    char input[80]; snprintf(input, sizeof(input), "loadmill %s", key); const char *keys[] = {key};
    const struct { int status, code; const char *cause, *read_error; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {201, 0, NULL, NULL, true}, {299, 0, NULL, NULL, true},
        {300, 0, NULL, NULL, false}, {401, 0, NULL, NULL, false}, {500, 0, NULL, NULL, false},
        {200, 1, "synthetic Do failure", NULL, false}, {299, -1, "out of memory in shared Do", NULL, false},
        {200, 1, NULL, NULL, false}, {200, 0, NULL, "synthetic read failure", false}, {299, 0, NULL, "", false},
    };
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "loadmill-test"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        configure(b, keys, 1, cases[i].status, cases[i].code, cases[i].cause, cases[i].read_error, NULL);
        br_results r = {0}; observe(&ctx, &r, b, keys, 1, 1); scan_into(d, &ctx, input, &r);
        CHECK(r.len == 1 && observed.sends == 1 && raw_completed(b) == i + 1); result_is(&r.items[0], key, cases[i].verified); br_results_clear(&r);
    }
    const char *multiple[] = {key, other, key}; const int mixed[] = {0, 1, 0};
    char repeated[192]; snprintf(repeated, sizeof(repeated), "loadmill %s\nloadmill %s\nloadmill %s", key, other, key);
    for (int mode = 0; mode < 3; ++mode) {
        configure(b, multiple, 3, 204, mode == 1, "synthetic shared error", NULL, mode == 2 ? mixed : NULL);
        size_t before = raw_completed(b); br_results r = {0}; observe(&ctx, &r, b, multiple, 3, 3); scan_into(d, &ctx, repeated, &r);
        CHECK(r.len == 3 && observed.sends == 3 && raw_completed(b) == before + 3); /* Completed keys are not a cache. */
        for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], multiple[i], mode == 0 || (mode == 2 && !mixed[i]));
        br_results_clear(&r);
    }
    for (int mode = 0; mode < 2; ++mode) {
        configure(b, keys, 1, 200, 0, NULL, NULL, NULL); size_t before = raw_completed(b);
        br_scan_ctx guard = ctx; guard.user_agent = mode == 0 ? "invalid\r\nagent" : NULL; guard.deadline_monotonic_ms = mode == 1 ? 1 : 0;
        br_results r = {0}; observe(&guard, &r, b, keys, 1, 1); scan_into(d, &guard, input, &r);
        CHECK(r.len == 1 && observed.sends == 1 && raw_completed(b) == before); result_is(&r.items[0], key, false); br_results_clear(&r);
    }
}

static void borrowed_guards(const br_detector *d)
{
    const char *keys[] = {key}; char input[80]; snprintf(input, sizeof(input), "loadmill %s", key);
    for (int mode = 0; mode < 2; ++mode) {
        test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode ? NULL : &transport}; br_results r = {0}; observe(&ctx, &r, NULL, keys, 1, 1);
        scan_into(d, &ctx, input, &r); CHECK(r.len == 1 && observed.sends == 1 && !http.calls && http.releases == (mode ? 0u : 1u));
        result_is(&r.items[0], key, false); br_results_clear(&r);
    }
}

static void owned_failures(const br_detector *d, br_http_client *client, owned_backend *b)
{
    const char *keys[] = {key, other}; char input[128]; snprintf(input, sizeof(input), "loadmill %s\nloadmill %s", key, other);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client)};
    for (int mode = 0; mode < 7; ++mode) {
        configure(b, keys, 2, 200, 0, NULL, NULL, NULL);
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *prior_raw = sentinel.raw.data; char *prior_error = sentinel.verification_error;
        br_results r = {0}; CHECK(!br_results_push(&r, &sentinel)); observe(&ctx, &r, b, keys, 2, 2); const char *expected;
        if (mode == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; expected = "out of memory iterating regex"; }
        else if (mode == 1 || mode == 2 || mode == 6) { fail_part_after = mode == 2 ? 1 : 2; expected = "out of memory creating Loadmill result"; }
        else if (mode == 3) { fail_push_after = 2; expected = "out of memory appending Loadmill result"; }
        else { fail_request_after = mode == 4 ? 1 : 2; expected = "out of memory creating Loadmill request"; }
        char *error = NULL;
        int rc = d->scan(d, mode == 2 ? NULL : &ctx, mode != 6, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error);
        CHECK(rc == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_request_after && !fail_next_malloc);
        CHECK(r.len == 1 && r.items[0].detector_type == 12345 && r.items[0].verified);
        CHECK(r.items[0].raw.data == prior_raw && r.items[0].raw.len == 4 && !memcmp(prior_raw, "keep", 4));
        CHECK(r.items[0].verification_error == prior_error && !strcmp(prior_error, "caller-owned"));
        CHECK(observed.sends == (mode == 1 || mode == 5 ? 1u : mode == 3 ? 2u : 0u) && observed.releases == observed.sends);
        free(error); br_results_clear(&r);
    }
}

int main(void)
{
    const br_detector *d = descriptor(); extraction(d); borrowed_guards(d);
    owned_backend *b = NULL; br_http_client *client = owned_client(&b);
    owned_verification(d, client, b); owned_failures(d, client, b);
    char *error = NULL; CHECK(br_http_client_drain(client, &error) == 0 && !error);
    size_t destroyed = destroyed_backends; br_http_client_destroy(client); CHECK(destroyed_backends == destroyed + 1 && !setter_calls);
    return test_finish("Loadmill full keyed owned-client buffering, release order and rollback");
}
