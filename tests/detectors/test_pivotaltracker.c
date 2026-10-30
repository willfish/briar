/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>

int br_pivotaltracker_init(const br_detector **out, char **error);

#define br_http_send pivotal_real_send
#define br_http_release pivotal_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release
#define br_results_push pivotal_real_push
#define br_result_set_verification_error pivotal_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char key[33], other[33];
static const char endpoint[] = "https://www.pivotaltracker.com/services/v5/me";
static size_t fail_after, failed_allocations, fail_part_after, fail_request_after, fail_push_after, setter_calls;
static bool fail_next_malloc;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && --fail_after == 0)) {
        fail_next_malloc = false;
        ++failed_allocations;
        return NULL;
    }
    (void)size;
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
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
    return pivotal_real_push(out, owned);
}
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return pivotal_real_setter(result, cause, secrets, count);
}

static const br_detector *descriptor(void)
{
    test_secret(key, 32, 0);
    key[4] = '9';
    test_secret(other, 32, 6);
    other[11] = '0';
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32 && strcmp(key, other));
    CHECK(br_pivotaltracker_init(NULL, &error) == -1 && error && !strcmp(error, "invalid PivotalTracker detector output"));
    free(error);
    error = NULL;
    CHECK(br_pivotaltracker_init(NULL, NULL) == -1);
    fail_next_malloc = true;
    CHECK(br_pivotaltracker_init(&d, &error) == -1 && !d && error && !fail_next_malloc);
    free(error);
    error = NULL;
    CHECK(br_pivotaltracker_init(&d, &error) == 0 && d && !error);
    CHECK(br_pivotaltracker_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 23 && d->version == 0 && !strcmp(d->name, "PivotalTracker") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "PivotalTracker is a project management tool. PivotalTracker tokens can be used to access and manage projects and data within PivotalTracker."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "pivotal"));
    CHECK(d->state && d->scan && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 23, expected, "key");
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
}

static void extraction_case(const br_detector *d, const void *input, size_t length, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    size_t before = setter_calls;
    br_results out = test_scan(d, &ctx, false, input, length);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && setter_calls == before);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[220], changed[40];
    snprintf(input, sizeof(input), "PiVoTaL '%s'", key);
    extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "pivotaltracker %s", other);
    extraction_case(d, input, strlen(input), other);
    snprintf(input, sizeof(input), "tracker %s", key);
    extraction_case(d, input, strlen(input), NULL);
    extraction_case(d, key, strlen(key), NULL);
    extraction_case(d, NULL, 0, NULL);
    memcpy(changed, key, 32);
    changed[31] = '\0';
    snprintf(input, sizeof(input), "pivotal %s", changed);
    extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'A', 32);
    changed[32] = '\0';
    snprintf(input, sizeof(input), "pivotal %s", changed);
    extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 32);
    changed[8] = '?';
    changed[32] = '\0';
    snprintf(input, sizeof(input), "pivotal %s", changed);
    extraction_case(d, input, strlen(input), NULL);
    /* No word boundaries: neighbors that would defeat \\b still capture. */
    snprintf(input, sizeof(input), "pivotal_%s", key);
    extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "pivotal %s_", key);
    extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "pivotal-%s-", key);
    extraction_case(d, input, strlen(input), key);
    memcpy(changed, key, 32);
    changed[32] = 'z';
    changed[33] = '\0';
    snprintf(input, sizeof(input), "pivotal %s", changed);
    extraction_case(d, input, strlen(input), key);
    memcpy(input, "pivotalx", 8);
    memcpy(input + 8, key, 32);
    input[40] = '\0';
    changed[0] = 'x';
    memcpy(changed + 1, key, 31);
    changed[32] = '\0';
    extraction_case(d, input, 40, changed);
    char run[80];
    memcpy(run, "pivotal", 7);
    memset(run + 7, 'a', 64);
    run[71] = '\0';
    memset(changed, 'a', 32);
    changed[32] = '\0';
    extraction_case(d, run, 71, changed); /* First 32 only; a trailing boundary would reject this run. */
    /* The resumed search sees the second pivotal. Its capture starts 39 units after the first keyword. */
    memcpy(run, "pivotal", 7);
    memcpy(run + 7, key, 32);
    memcpy(run + 39, "pivotal", 7);
    memcpy(run + 46, other, 32);
    run[78] = '\0';
    br_results out = test_scan(d, NULL, false, run, 78);
    CHECK(out.len == 2);
    finding(&out.items[0], key, false);
    finding(&out.items[1], other, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "pivotal%s pivotal%s", key, other);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    finding(&out.items[0], key, false);
    finding(&out.items[1], other, false);
    br_results_clear(&out);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "pivotal", 7);
        memset(input + 7, '.', gap);
        memcpy(input + 7 + gap, key, 32);
        extraction_case(d, input, 7 + gap + 32, gap == 40 ? key : NULL);
        size_t at = 7;
        for (size_t i = 0; i < gap; ++i) {
            memcpy(input + at, "\xe2\x98\x83", 3);
            at += 3;
        }
        memcpy(input + at, key, 32);
        extraction_case(d, input, at + 32, gap == 40 ? key : NULL);
    }
    memcpy(input, "pivotal", 7);
    input[7] = '\r';
    input[8] = '\n';
    memcpy(input + 9, key, 32);
    extraction_case(d, input, 41, key);
    snprintf(input, sizeof(input), "pivotal %s\npivotal %s\npivotal %s", key, other, key);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    finding(&out.items[0], key, false);
    finding(&out.items[1], other, false);
    finding(&out.items[2], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "pivotal %s\npivotal %s", key, other);
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "pivotal %s", key);
    fail_request_after = 1;
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && !fail_request_after && fail_next_malloc);
    fail_next_malloc = false;
    br_results_clear(&out);
}

static struct {
    bool active;
    const br_scan_ctx *ctx;
    br_results *out;
    const char *const *keys;
    size_t count, base, sends, releases;
    size_t release_len[4];
    const br_http_request *requests[4];
    br_http_response *responses[4];
    bool released[4];
} observed;

static void request_is(const br_http_request *r, const char *token, bool prepared, const br_scan_ctx *ctx)
{
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, endpoint));
    CHECK(r->detector_type == 23 && r->profile == BR_HTTP_SANE);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == (prepared ? 3u : 2u) && r->timeout_ms == (prepared ? 5000u : 0u) && r->timeout_ms != 15000);
    CHECK(!strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/json; charset=utf-8"));
    CHECK(!strcmp(r->headers[1].name, "X-Trackertoken") && !strcmp(r->headers[1].value, token) && strlen(token) == 32);
    if (prepared) {
        const char *agent = ctx && ctx->user_agent ? "TruffleHog pivotal-test" : "TruffleHog";
        CHECK(!strcmp(r->headers[2].name, "User-Agent") && !strcmp(r->headers[2].value, agent));
    }
}

static void originals_live(size_t i)
{
    if (!observed.released[i]) request_is(observed.requests[i], observed.keys[i], false, observed.ctx);
}

static void observe(const br_scan_ctx *ctx, br_results *out, const char *const *keys, size_t count)
{
    memset(&observed, 0, sizeof(observed));
    observed.active = true;
    observed.ctx = ctx;
    observed.out = out;
    observed.keys = keys;
    observed.count = count;
    observed.base = out->len;
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    size_t i = observed.sends;
    CHECK(observed.active && ctx == observed.ctx && i < observed.count && observed.count <= 4);
    CHECK(observed.out->len == observed.base + i);
    request_is(request, observed.keys[i], false, ctx);
    observed.requests[i] = request;
    observed.responses[i] = response;
    ++observed.sends;
    int rc = pivotal_real_send(ctx, request, response, error);
    originals_live(i);
    return rc;
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    size_t i = 0;
    while (i < observed.sends && (observed.responses[i] != response || observed.released[i])) ++i;
    CHECK(observed.active && ctx == observed.ctx && i < observed.sends && i == observed.releases);
    CHECK(observed.out->len == observed.base + observed.releases);
    observed.release_len[observed.releases] = observed.out->len;
    originals_live(i);
    response->status = 500; /* Decision must already hold the pre-close snapshot. */
    pivotal_real_release(ctx, response);
    originals_live(i);
    observed.released[i] = true;
    ++observed.releases;
}

typedef struct { test_http http; const int *codes; } wire;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    wire *w = http->user;
    size_t i = http->calls - 1;
    CHECK(ctx == observed.ctx && i < observed.count);
    request_is(request, observed.keys[i], true, ctx);
    if (w->codes) http->send_rc = w->codes[i];
}

static void release_reply(void *user, br_http_response *response) { test_http_release(user, response); }

static int scan_into(const br_detector *d, const br_scan_ctx *ctx, bool verify, const char *input, br_results *out, char **error)
{
    int rc = d->scan(d, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, out, error);
    CHECK(observed.sends == observed.releases);
    observed.active = false;
    return rc;
}

static void verification(const br_detector *d)
{
    const char *keys[] = {key};
    char input[80];
    snprintf(input, sizeof(input), "pivotal %s", key);
    const int statuses[] = {INT_MIN, -1, 0, 199, 200, 201, 204, 250, 299, 300, 401, 500, INT_MAX};
    static const unsigned char body[] = "\0\xff not JSON";
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        wire w = {.http = {.response = {.status = statuses[i], .body = {body, sizeof(body) - 1},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored read error"}}};
        w.http.inspect = inspect;
        w.http.user = &w;
        br_transport transport = {&w.http, test_http_send, release_reply};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "pivotal-test"};
        br_results out = {0};
        char *error = NULL;
        observe(&ctx, &out, keys, 1);
        CHECK(!scan_into(d, &ctx, true, input, &out, &error) && !error);
        CHECK(out.len == 1 && observed.sends == 1 && w.http.calls == 1 && w.http.releases == 1);
        CHECK(observed.release_len[0] == 0);
        finding(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const char *causes[] = {"synthetic Do failure", "out of memory constructing HTTP headers", "cannot create PivotalTracker request", key, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        wire w = {.http = {.send_rc = i % 2 ? 1 : -7, .send_error = causes[i], .response = {.status = 200, .body_error = "ignored"}}};
        w.http.inspect = inspect;
        w.http.user = &w;
        br_transport transport = {&w.http, test_http_send, release_reply};
        br_scan_ctx ctx = {.transport = &transport};
        br_results out = {0};
        char *error = NULL;
        observe(&ctx, &out, keys, 1);
        CHECK(!scan_into(d, &ctx, true, input, &out, &error) && !error);
        CHECK(out.len == 1 && w.http.calls == 1 && w.http.releases == 1 && observed.release_len[0] == 0);
        finding(&out.items[0], key, false);
        br_results_clear(&out);
    }
    const char *many[] = {key, other, key};
    const int mixed[] = {0, 1, 0};
    char repeated[180];
    snprintf(repeated, sizeof(repeated), "pivotal %s\npivotal %s\npivotal %s", key, other, key);
    wire w = {.codes = mixed, .http = {.response = {.status = 204, .body_error = ""}}};
    w.http.inspect = inspect;
    w.http.user = &w;
    br_transport transport = {&w.http, test_http_send, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "pivotal-test"};
    br_results out = {0};
    char *error = NULL;
    observe(&ctx, &out, many, 3);
    CHECK(!scan_into(d, &ctx, true, repeated, &out, &error) && !error);
    CHECK(out.len == 3 && w.http.calls == 3 && w.http.releases == 3);
    CHECK(observed.release_len[0] == 0 && observed.release_len[1] == 1 && observed.release_len[2] == 2);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], many[i], !mixed[i]);
    br_results_clear(&out);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_next_malloc = true; return false; }

static void preparation(const br_detector *d)
{
    const char *keys[] = {key};
    char input[80];
    snprintf(input, sizeof(input), "pivotal %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0};
        br_transport transport = {&http, test_http_send, test_http_release};
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_headers : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "bad\r\nagent" : NULL};
        br_results out = {0};
        char *error = NULL;
        size_t failures = failed_allocations;
        observe(&ctx, &out, keys, 1);
        CHECK(!scan_into(d, &ctx, true, input, &out, &error) && !error && out.len == 1);
        CHECK(!http.calls && observed.releases == 1 && !fail_next_malloc);
        CHECK(failed_allocations == failures + (mode == 4));
        finding(&out.items[0], key, false);
        br_results_clear(&out);
    }
}

static br_results caller_owned(void)
{
    br_results out = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 17, "keep", "key"));
    prior.verified = true;
    prior.verification_error = strdup("caller diagnostic");
    CHECK(prior.verification_error && !br_results_push(&out, &prior));
    return out;
}

static void preserved(br_results *out, unsigned char *raw, br_json *parts, char *cause, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1);
    test_key_result(&out->items[0], 17, "keep", "key");
    CHECK(out->items[0].verified && out->items[0].raw.data == raw && out->items[0].secret_parts == parts);
    CHECK(out->items[0].verification_error == cause && !strcmp(cause, "caller diagnostic"));
    free(error);
    br_results_clear(out);
}

static void owned_failures(const br_detector *d)
{
    const char *keys[] = {key, other};
    char input[120];
    snprintf(input, sizeof(input), "pivotal %s\npivotal %s", key, other);
    for (int mode = 0; mode < 7; ++mode) {
        wire w = {.http = {.response = {.status = 200}}};
        w.http.inspect = inspect;
        w.http.user = &w;
        br_transport transport = {&w.http, test_http_send, release_reply};
        br_scan_ctx ctx = {.transport = &transport};
        br_results out = caller_owned();
        unsigned char *raw = out.items[0].raw.data;
        br_json *parts = out.items[0].secret_parts;
        char *cause = out.items[0].verification_error, *error = NULL;
        if (mode == 0) fail_next_malloc = true;
        else if (mode == 1 || mode == 2) fail_part_after = mode == 1 ? 1u : 2u;
        else if (mode == 3 || mode == 4) fail_request_after = mode == 3 ? 1u : 2u;
        else fail_push_after = mode == 5 ? 1u : 2u;
        const br_scan_ctx *scan_ctx = mode == 2 ? NULL : &ctx;
        observe(scan_ctx, &out, keys, 2);
        int rc = scan_into(d, scan_ctx, true, input, &out, &error);
        CHECK(!fail_next_malloc && !fail_after && !fail_part_after && !fail_request_after && !fail_push_after);
        CHECK(observed.sends == (mode == 4 || mode == 5 ? 1u : mode == 6 ? 2u : 0u));
        preserved(&out, raw, parts, cause, rc, error);
    }
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    preparation(d);
    owned_failures(d);
    CHECK(!setter_calls && !observed.active && !fail_after && !fail_part_after && !fail_request_after && !fail_push_after && !fail_next_malloc);
    return test_finish("PivotalTracker unbound 32-char window, immediate close and owned rollback");
}
