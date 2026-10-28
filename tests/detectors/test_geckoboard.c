/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[45], b[45];
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static const char *borrowed_auth, *expected_key;

/* Exercise existing allocation/insertion boundaries, including positive errors. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_geckoboard_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_geckoboard_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:geckoboard)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_geckoboard_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_geckoboard_init(&d, &error) == 0 && d && !error);
    CHECK(br_geckoboard_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 696 && d->version == 0 && !strcmp(d->name, "Geckoboard") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Geckoboard is a data visualization tool that allows users to create real-time dashboards. Geckoboard API keys can be used to access and modify these dashboards."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "geckoboard"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 696, key, "key");
    CHECK(r->raw.len == 44 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 44);
}
static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) result(&out.items[0], key, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[300], changed[46];
    const struct { const char *format; bool matches; } cases[] = {
        {"geckoboard '%s'", true}, {"GeCkObOaRd=%s", true}, {"preGECKOBOARDsuffix:%s", true}, {"geckoboard\r\n%s", true},
        {"%s", false}, {"%s geckoboard", false}, {"gecko board %s", false}, {"geckoboard%s", false},
        {"geckoboard x%s", false}, {"geckoboard _%s", false}, {"geckoboard %s_", false}, {"geckoboard %s9", false},
        {"geckoboard %.43s", false}, {"geckoboard +%s=", true}, {"geckoboard \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a);
        extract_case(d, input, strlen(input), cases[i].matches ? a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "geckoboard", 10); memset(input + 10, ':', gap); memcpy(input + 10 + gap, a, 44);
        extract_case(d, input, 54 + gap, gap == 40 ? a : NULL);
    }
    const char invalid[] = "_-/+.=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, a, sizeof(a)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "geckoboard %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    memset(changed, 'A', 44); changed[44] = '\0';
    snprintf(input, sizeof(input), "geckoboard %s", changed); extract_case(d, input, strlen(input), changed); /* No entropy/filter. */
    snprintf(input, sizeof(input), "geckoboard %s %s", a, b); extract_case(d, input, strlen(input), a); /* Nonoverlapping full matches. */
    int n = snprintf(input, sizeof(input), "\xff\ngeckoboard%c%s", 0, a); extract_case(d, input, (size_t)n, a);
    extract_case(d, NULL, 0, NULL);
}

typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_auth);
    CHECK(request->detector_type == 696 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.geckoboard.com/"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 50 && !memcmp(request->headers[0].value, "Basic ", 6));
    CHECK(!memcmp(request->headers[0].value + 6, e->keys[at], 45)); /* Literal TOKEN, no Base64 or colon. */
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    borrowed_auth = request->headers[0].value; expected_key = e->keys[at];
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_auth && strlen(borrowed_auth) == 50 && !memcmp(borrowed_auth, "Basic ", 6));
    CHECK(!memcmp(borrowed_auth + 6, expected_key, 45));
    borrowed_auth = expected_key = NULL; test_http_release(user, response);
}
static void occurrences(const br_detector *d)
{
    char input[240]; snprintf(input, sizeof(input), "geckoboard %s\nGECKOBOARD %s\ngeckoboard %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog geckoboard-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "geckoboard-offline"}; e.ctx = &ctx;
    br_results out = test_scan(d, &ctx, false, input, strlen(input)); CHECK(out.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts); br_results_clear(&out);
    for (size_t pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], keys[i], true);
        br_results_clear(&out);
    }
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3); br_results_clear(&out);
}
static void statuses_and_send(const br_detector *d)
{
    char input[60]; snprintf(input, sizeof(input), "geckoboard %s", a);
    const char *keys[] = {a}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char ignored[] = {0, 0xff, '{', '!'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {ignored, sizeof(ignored)}, .body_error = i % 2 ? "ignored" : ""};
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *error; } failures[] = {{1, "net/http: nil Context"}, {-7, "cannot create Geckoboard result"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, a}};
    http.response.status = 200;
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].error;
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], a, false); br_results_clear(&out);
    }
}
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void shared_setup(const br_detector *d)
{
    char input[60]; snprintf(input, sizeof(input), "geckoboard %s", a);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && failed_allocations == before + (i == 1 ? 1u : 0u));
        result(&out.items[0], a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == prior->raw.data && out->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(out->items[0].secret_parts == prior->secret_parts && out->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
}
static void resources(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "geckoboard %s\ngeckoboard %s", a, b); br_slice data = text(input);
    const char *keys[] = {a, b}; expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 45; fail_after = 2; }
        if (failure == 2) { fail_size = 44; fail_after = 2; }
        if (failure == 3) fail_part_after = 2;
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : "cannot create Geckoboard result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !borrowed_auth);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create Geckoboard result") && !fail_part_after);
    check_prior(&out, &prior); free(error); error = NULL; /* Finding failure precedes constructor skip. */
    size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Geckoboard result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior); free(error); br_results_clear(&out);
}
int main(void)
{
    test_secret(a, 44, 0); test_secret(b, 44, 11); a[0] = 'Z'; b[13] = 'Q';
    const br_detector *d = descriptor(); extraction(d); occurrences(d); statuses_and_send(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !borrowed_auth && !expected_key);
    return test_finish("Geckoboard");
}
