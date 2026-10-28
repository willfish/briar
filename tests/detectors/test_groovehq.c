/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[65], b[65];
static size_t fail_size, fail_after, fail_part;
static const char *borrowed_auth, *expected_key;

/* Fail actual owned allocations/additions, without production seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (!strcmp(name, "key") && fail_part && --fail_part == 0) return 7;
    return json_object_object_add_ex(o, name, v, 0);
}
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static void result_is(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 206, key, "key");
    CHECK(r->raw.len == 64 && r->verified == verified && !r->verification_error);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_groovehq_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_groovehq_init(NULL, NULL) != 0);
    CHECK(!br_groovehq_init(&d, &error) && d && !error);
    CHECK(!br_groovehq_init(&again, NULL) && again == d);
    CHECK(d->type == 206 && !d->version && !strcmp(d->name, "Groovehq") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "GrooveHQ is a simple help desk software. GrooveHQ API keys can be used to access and manage support tickets and customer interactions."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "groovehq"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Default/registry integration is parent-owned. */
}
static void extract_case(const br_detector *d, const void *input, size_t len, const char *capture)
{
    test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    br_results r = test_scan(d, &ctx, false, input, len);
    CHECK(r.len == (capture ? 1u : 0u) && !http.calls && !http.releases);
    if (capture) result_is(&r.items[0], capture, false);
    br_results_clear(&r);
}
static void extraction(const br_detector *d)
{
    char input[320], changed[65];
    const struct { const char *format; bool match; } cases[] = {
        {"groove '%s'", true}, {"GrOoVeHq:%s", true}, {"pregroovesuffix\r\n%s", true},
        {"groove\r%s", true}, {"groove\n%s", true}, {"%s", false}, {"%s groovehq", false},
        {"groove%s", false}, {"groove _%s", false}, {"groove %s_", true},
        {"groove %s9", true}, {"groove %.63s", false}, {"groove -%s", true},
        {"groove %s %s", true}, {"groove %sEXTRA", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a, b);
        extract_case(d, input, strlen(input), cases[i].match ? a : NULL);
    }
    memcpy(changed, a, sizeof(changed)); changed[12] = '_';
    snprintf(input, sizeof(input), "groove %s", changed); extract_case(d, input, strlen(input), NULL);
    memset(changed, 'A', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "groove %s", changed); extract_case(d, input, strlen(input), changed);
    /* The extraction prefix is groove, not the dispatch keyword groovehq. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "groove", 6); memset(input + 6, '.', gap); memcpy(input + 6 + gap, a, 64);
        extract_case(d, input, 70 + gap, gap == 40 ? a : NULL);
    }
    for (size_t gap = 38; gap <= 39; ++gap) {
        memcpy(input, "groovehq", 8); memset(input + 8, '.', gap); memcpy(input + 8 + gap, a, 64);
        extract_case(d, input, 72 + gap, gap == 38 ? a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "groove", 6);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 6 + 2 * gap, a, 64);
        extract_case(d, input, 70 + 2 * gap, gap == 40 ? a : NULL);
    }
    int n = snprintf(input, sizeof(input), "groove%c%s", 0, a);
    extract_case(d, input, (size_t)n, a); extract_case(d, NULL, 0, NULL);
}
typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void check_auth(const char *auth, const char *key)
{
    CHECK(strlen(auth) == 71 && !memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, key, 64));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_auth);
    CHECK(!strcmp(r->method, "GET") && !strcmp(r->url, "https://api.groovehq.com/v1/me"));
    CHECK(r->profile == BR_HTTP_SANE && r->timeout_ms == 5000 && r->detector_type == 206);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == 2 && !strcmp(r->headers[0].name, "Authorization"));
    check_auth(r->headers[0].value, e->keys[at]);
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, e->agent));
    /* Borrow only original provider Authorization, not prepared headers or UA. */
    borrowed_auth = r->headers[0].value; expected_key = e->keys[at];
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_auth); check_auth(borrowed_auth, expected_key);
    borrowed_auth = expected_key = NULL; test_http_release(user, response);
}
static void occurrences(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "groove %s\nGROOVEHQ %s\ngroove %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog groovehq-offline"};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport t = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &t, .user_agent = "groovehq-offline"}; e.ctx = &ctx;
    br_results r = test_scan(d, &ctx, false, input, strlen(input)); CHECK(r.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], false);
    CHECK(r.items[0].raw.data != r.items[2].raw.data && r.items[0].secret_parts != r.items[2].secret_parts); br_results_clear(&r);
    r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&r.items[i], keys[i], true);
    br_results_clear(&r);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(!r.len); br_results_clear(&r);
    r = test_scan(d, NULL, false, input, strlen(input)); CHECK(r.len == 3); br_results_clear(&r);
}
static void verification(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "groovehq %s", a);
    const char *keys[] = {a}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e}; br_transport t = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &t}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char body[] = {0, 0xff, '!', '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i % 2 ? "ignored read failure" : NULL};
        br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&r);
    }
    const struct { int rc; const char *message; } failures[] = {{1, "context canceled"}, {-7, "cannot create Groovehq result"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {7, a}};
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].message;
        http.response = i ? (br_http_response){.status = 200} : (br_http_response){0};
        br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], a, false); br_results_clear(&r);
    }
}
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void shared_setup(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "groovehq %s", a);
    test_http http = {0}; br_transport t = test_transport(&http); size_t calls = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &t, .cancelled = fail_headers}, {.transport = &t, .cancelled = cancelled, .cancel_user = &calls}, {.transport = &t, .deadline_monotonic_ms = 1}, {.transport = &t, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0;
        br_results r = test_scan(d, &contexts[i], true, input, strlen(input)); CHECK(r.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_after);
        result_is(&r.items[0], a, false); br_results_clear(&r);
    }
    CHECK(calls == 1);
}
static void resources(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "groove %s\ngroove %s", a, b);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results r = {0}; CHECK(!br_results_push(&r, &prior)); prior = r.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 65; fail_after = 2; }
        /* Two 8-entry capture arrays also allocate 64 bytes before Raw. */
        if (failure == 1) { fail_size = 64; fail_after = 4; }
        if (failure >= 2) fail_part = 2;
        http.calls = http.releases = 0; http.send_rc = failure == 4 ? 7 : 0;
        CHECK(d->scan(d, failure == 3 ? NULL : &ctx, true, text(input), &r, &error) != 0 && error && !fail_after && !fail_part);
        CHECK(r.len == 1 && r.items[0].raw.data == prior.raw.data && r.items[0].secret_parts == prior.secret_parts);
        CHECK(r.items[0].verified && r.items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
        CHECK(http.calls == (failure == 0 || failure == 3 ? 0u : 1u) && http.releases == http.calls);
        free(error); error = NULL;
    }
    size_t cap = r.cap; r.cap = 0; /* Actual positive push-validation failure. */
    CHECK(d->scan(d, &ctx, false, text(input), &r, &error) != 0 && error); r.cap = cap;
    CHECK(r.len == 1 && r.items[0].raw.data == prior.raw.data); free(error); br_results_clear(&r);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
}
int main(void)
{
    test_secret(a, 64, 0); a[13] = 'Q'; test_secret(b, 64, 7); b[18] = 'Z';
    const br_detector *d = descriptor(); extraction(d); occurrences(d); verification(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part && !borrowed_auth && !expected_key);
    return test_finish("Groovehq grammar/case/prefix-dispatch/duplicates/metadata/nil/request/status/read/send/resources/rollback");
}
