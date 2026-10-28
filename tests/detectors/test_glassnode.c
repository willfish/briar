/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[28], b[28];
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static bool fail_agent;
static const char *borrowed_url, *borrowed_name, *borrowed_value, *expected_key;
static const char prefix[] = "https://api.glassnode.com/v1/metrics/indicators/sopr?a=btc&api_key=";

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed_allocations; return NULL; }
    size_t n = strlen(s) + 1; char *p = malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_glassnode_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_glassnode_init(NULL, NULL) != 0);
    CHECK(br_glassnode_init(&d, &error) == 0 && d && !error);
    CHECK(br_glassnode_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 569 && !d->version && !strcmp(d->name, "Glassnode") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Glassnode is an on-chain market intelligence platform providing data and insights on blockchain and cryptocurrency markets. Glassnode API keys can be used to access various blockchain metrics and data points."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "glassnode"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 569, key, "key");
    CHECK(r->raw.len == 27 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 27);
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
    char input[240], changed[28];
    const struct { const char *format; bool matches; } cases[] = {
        {"glassnode '%s'", true}, {"GlAsSnOdE=%s", true}, {"preGLASSNODEsuffix:%s", true}, {"glassnode\r\n%s", true},
        {"%s", false}, {"%s glassnode", false}, {"glass node %s", false}, {"glassnode%s", false},
        {"glassnode x%s", false}, {"glassnode _%s", false}, {"glassnode %s_", false}, {"glassnode %s9", false},
        {"glassnode %.26s", false}, {"glassnode +%s=", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a);
        extract_case(d, input, strlen(input), cases[i].matches ? a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "glassnode", 9); memset(input + 9, ':', gap); memcpy(input + 9 + gap, a, 27);
        extract_case(d, input, 36 + gap, gap == 40 ? a : NULL);
    }
    const char invalid[] = "_-/+.=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, a, sizeof(a)); changed[13] = invalid[i];
        snprintf(input, sizeof(input), "glassnode %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    memset(changed, 'A', 27); changed[27] = '\0';
    snprintf(input, sizeof(input), "glassnode %s", changed); extract_case(d, input, strlen(input), changed); /* No entropy/filter. */
    memset(changed, 'f', 27);
    snprintf(input, sizeof(input), "glassnode %s", changed); extract_case(d, input, strlen(input), changed); /* No hex special case. */
    snprintf(input, sizeof(input), "glassnode %s %s", a, b); extract_case(d, input, strlen(input), a); /* Whole matches do not overlap. */
    int n = snprintf(input, sizeof(input), "glassnode%c%s", 0, a); extract_case(d, input, (size_t)n, a);
    extract_case(d, NULL, 0, NULL);
}

typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_url);
    CHECK(request->detector_type == 569 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(strlen(request->url) == sizeof(prefix) - 1 + 27 && !memcmp(request->url, prefix, sizeof(prefix) - 1));
    CHECK(!memcmp(request->url + sizeof(prefix) - 1, e->keys[at], 28)); /* Complete literal URL and query order. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    /* Retain only original values, never effective request/header array/UA. */
    borrowed_url = request->url; borrowed_name = request->headers[0].name;
    borrowed_value = request->headers[0].value; expected_key = e->keys[at];
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_url && strlen(borrowed_url) == sizeof(prefix) - 1 + 27);
    CHECK(!memcmp(borrowed_url, prefix, sizeof(prefix) - 1) && !memcmp(borrowed_url + sizeof(prefix) - 1, expected_key, 28));
    CHECK(!strcmp(borrowed_name, "Content-Type") && !strcmp(borrowed_value, "application/json"));
    borrowed_url = borrowed_name = borrowed_value = expected_key = NULL;
    test_http_release(user, response);
}
static void occurrences(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "glassnode %s\nGLASSNODE %s\nglassnode %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog glassnode-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "glassnode-offline"}; e.ctx = &ctx;
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
    char input[48]; snprintf(input, sizeof(input), "glassnode %s", a);
    const char *keys[] = {a}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 500};
    static const unsigned char ignored[] = {0, 0xff, '{', '!'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {ignored, sizeof(ignored)}, .body_error = i % 2 ? "ignored" : NULL};
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *error; } failures[] = {{1, "net/http: nil Context"}, {-7, "cannot create Glassnode result"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, a}};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].error;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], a, false); br_results_clear(&out);
    }
}
static bool fail_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void shared_setup(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "glassnode %s", a);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = arm_agent}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 1 || i == 2 ? 1u : 0u));
        result(&out.items[0], a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(out->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}
static void resources(const br_detector *d)
{
    char input[100]; snprintf(input, sizeof(input), "glassnode %s\nglassnode %s", a, b); br_slice data = text(input);
    const char *keys[] = {a, b}; expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 28; fail_after = 2; }
        if (failure == 2) { fail_size = 27; fail_after = 2; }
        if (failure == 3) fail_part_after = 2;
        CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0);
        CHECK(error && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !borrowed_url);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Own failures remain fatal before the nil-context constructor skip. */
    for (size_t failure = 0; failure < 3; ++failure) {
        if (failure == 0) { fail_size = 28; fail_after = 1; }
        if (failure == 1) { fail_size = 27; fail_after = 1; }
        if (failure == 2) fail_part_after = 2;
        CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !fail_after && !fail_part_after);
        check_prior(&out, &prior); free(error); error = NULL;
    }
    size_t cap = out.cap; out.cap = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot append Glassnode result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior); free(error); br_results_clear(&out);
}
int main(void)
{
    test_secret(a, 27, 0); test_secret(b, 27, 11); a[0] = 'Z'; b[13] = 'Q';
    const br_detector *d = descriptor(); extraction(d); occurrences(d); statuses_and_send(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !borrowed_url && !expected_key);
    return test_finish("Glassnode");
}
