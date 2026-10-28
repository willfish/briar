/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[44], b[44];
static const char prefix[] = "https://api.gyazo.com/api/images?access_token=";
static size_t fail_size, fail_after, fail_part;
static const char *borrowed_url, *expected_key;

/* Fail actual owned operations; no production failure seams. */
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
    test_key_result(r, 467, key, "key");
    CHECK(r->raw.len == 43 && r->verified == verified && !r->verification_error);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_gyazo_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_gyazo_init(NULL, NULL) != 0);
    CHECK(!br_gyazo_init(&d, &error) && d && !error);
    CHECK(!br_gyazo_init(&again, NULL) && again == d);
    CHECK(d->type == 467 && !d->version && !strcmp(d->name, "Gyazo") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Gyazo is an image sharing service. Gyazo access tokens can be used to access and manage images stored in a Gyazo account."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "gyazo"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/default membership is parent-owned. */
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
    char input[256], changed[44];
    const struct { const char *format; bool match; } cases[] = {
        {"gyazo '%s'", true}, {"gYaZo:%s", true}, {"pregYAZOsuffix\r\n%s", true},
        {"gyazo\r%s", true}, {"gyazo\n%s", true}, {"gyazo -%s-", true},
        {"%s", false}, {"%s gyazo", false}, {"gya zo %s", false}, {"gyazo%s", false},
        {"gyazo _%s", false}, {"gyazo %s_", false}, {"gyazo %s9", false},
        {"gyazo %.42s", false}, {"gyazo %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a, b);
        extract_case(d, input, strlen(input), cases[i].match ? a : NULL);
    }
    snprintf(input, sizeof(input), "gyazo %s", b); extract_case(d, input, strlen(input), b);
    for (size_t i = 0; i < 2; ++i) {
        memcpy(changed, a, sizeof(changed)); changed[i ? 42 : 0] = '-';
        snprintf(input, sizeof(input), "gyazo %s", changed); extract_case(d, input, strlen(input), NULL);
        snprintf(input, sizeof(input), i ? "gyazo %sx" : "gyazo x%s", changed);
        extract_case(d, input, strlen(input), changed); /* Word-to-hyphen boundaries. */
    }
    memset(changed, '-', 43); changed[43] = 0;
    snprintf(input, sizeof(input), "gyazo x%sx", changed); extract_case(d, input, strlen(input), changed);
    memcpy(changed, a, sizeof(changed)); changed[15] = '-';
    snprintf(input, sizeof(input), "gyazo %s", changed); extract_case(d, input, strlen(input), changed);
    const char invalid[] = {'_', '+', '/', '='};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        changed[15] = invalid[i]; snprintf(input, sizeof(input), "gyazo %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "gyazo", 5); memset(input + 5, '.', gap); memcpy(input + 5 + gap, a, 43);
        extract_case(d, input, 48 + gap, gap == 40 ? a : NULL);
        for (size_t j = 0; j < gap; ++j) memcpy(input + 5 + 2 * j, "\xc3\xa9", 2);
        memcpy(input + 5 + 2 * gap, a, 43);
        extract_case(d, input, 48 + 2 * gap, gap == 40 ? a : NULL);
    }
    int n = snprintf(input, sizeof(input), "gyazo%c%s", 0, a);
    extract_case(d, input, (size_t)n, a); extract_case(d, NULL, 0, NULL);
}
typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void check_url(const char *url, const char *key)
{
    CHECK(strlen(url) == sizeof(prefix) - 1 + 43);
    CHECK(!memcmp(url, prefix, sizeof(prefix) - 1));
    CHECK(!strcmp(url + sizeof(prefix) - 1, key));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_url);
    CHECK(!strcmp(r->method, "GET")); check_url(r->url, e->keys[at]);
    CHECK(r->profile == BR_HTTP_SANE && r->timeout_ms == 5000 && r->detector_type == 467);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == 1 && !strcmp(r->headers[0].name, "User-Agent") && !strcmp(r->headers[0].value, e->agent));
    /* Never retain the effective request, header array or synthesized UA. */
    borrowed_url = r->url; expected_key = e->keys[at];
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_url); check_url(borrowed_url, expected_key);
    borrowed_url = expected_key = NULL; test_http_release(user, response);
}
static void occurrences(const br_detector *d)
{
    char input[200]; snprintf(input, sizeof(input), "gyazo %s\nGYAZO %s\ngyazo %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog gyazo-offline"};
    test_http http = {.inspect = inspect, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport t = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &t, .user_agent = "gyazo-offline"}; e.ctx = &ctx;
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
    char input[64]; snprintf(input, sizeof(input), "gyazo %s", a);
    const char *keys[] = {a}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &e}; br_transport t = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &t}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0, 0xff, '!', '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read failure"};
        br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&r);
    }
    const struct { int rc; const char *message; } failures[] = {{1, "net/http: nil Context"}, {-7, "cannot create Gyazo result"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {7, a}};
    http.response.status = 200;
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].message;
        br_results r = test_scan(d, &ctx, true, input, strlen(input)); CHECK(r.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&r.items[0], a, false); br_results_clear(&r);
    }
}
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void shared_setup(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "gyazo %s", a);
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
    char input[128]; snprintf(input, sizeof(input), "gyazo %s\ngyazo %s", a, b);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results r = {0}; CHECK(!br_results_push(&r, &prior)); prior = r.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport = &t};
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 44; fail_after = 2; }
        if (failure == 1) { fail_size = 43; fail_after = 2; }
        if (failure >= 2) fail_part = 2;
        http.calls = http.releases = 0; http.send_rc = failure == 4 ? 7 : 0;
        CHECK(d->scan(d, failure == 3 ? NULL : &ctx, true, text(input), &r, &error) != 0 && error && !fail_after && !fail_part);
        CHECK(r.len == 1 && r.items[0].raw.data == prior.raw.data && r.items[0].secret_parts == prior.secret_parts);
        CHECK(r.items[0].verified && r.items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
        CHECK(http.calls == (failure == 0 || failure == 3 ? 0u : 1u) && http.releases == http.calls);
        free(error); error = NULL;
    }
    size_t cap = r.cap; r.cap = 0; /* Actual positive br_results_push failure. */
    CHECK(d->scan(d, &ctx, false, text(input), &r, &error) != 0 && error); r.cap = cap;
    CHECK(r.len == 1 && r.items[0].raw.data == prior.raw.data); free(error); br_results_clear(&r);
    CHECK(d->scan(NULL, NULL, false, text(""), NULL, NULL) != 0);
}
int main(void)
{
    test_secret(a, 43, 0); a[0] = 'Z'; a[20] = '-';
    memset(b, 'A', 43); b[43] = 0; /* No entropy, UUID or token validation. */
    const br_detector *d = descriptor(); extraction(d); occurrences(d); verification(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part && !borrowed_url && !expected_key);
    return test_finish("Gyazo grammar/hyphens/case/prefix/duplicates/metadata/nil/URL/headers/status/read/send/resources/rollback");
}
