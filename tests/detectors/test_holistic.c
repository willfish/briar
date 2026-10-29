/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <malloc.h>

static const char a[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char b[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static size_t fail_size, fail_after, fail_part_after, fail_realloc_size, failed;

/* Exercise actual owned operations, using the existing named-test pattern. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed; return NULL; }
    return calloc(1, size);
}

void *realloc(void *p, size_t size)
{
    if (fail_realloc_size && size == fail_realloc_size) {
        fail_realloc_size = 0; ++failed; return NULL;
    }
    if (!size) { free(p); return NULL; }
    size_t previous = p ? malloc_usable_size(p) : 0;
    void *copy = malloc(size);
    if (copy) {
        if (p) memcpy(copy, p, previous < size ? previous : size);
        free(p);
    }
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) { ++failed; return 7; }
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_holistic_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_holistic_init(NULL, NULL) != 0);
    CHECK(br_holistic_init(&d, &error) == 0 && d && !error);
    CHECK(br_holistic_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 764 && !d->version && !strcmp(d->name, "Holistic") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Holistic is a service that provides comprehensive project management solutions. Holistic API keys can be used to access and manage project data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "holistic"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/default membership is parent-owned. */
}

static void result_is(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 764, key, "key");
    CHECK(r->raw.len == 64 && r->verified == verified && !r->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 64);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) result_is(&out.items[0], key, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[320], changed[65];
    const struct { const char *format; bool matches; } cases[] = {
        {"holistic '%s'", true}, {"HoLiStIc=%s", true}, {"preHOLISTICsuffix:%s", true},
        {"holistic\r\n%s", true}, {"holistic\r%s", true}, {"holistic\n%s", true},
        {"holistic -%s-not-a-whole-token", true}, {"holistic /%s/", true},
        {"%s", false}, {"%s holistic", false}, {"hol istic %s", false}, {"holistic%s", false},
        {"holistic x%s", false}, {"holistic _%s", false}, {"holistic 0%s", false},
        {"holistic %s_", false}, {"holistic %s0", false}, {"holistic %.63s", false},
        {"holistic %s %s", true}, /* A second key without its own prefix is not another match. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a, b);
        extract_case(d, input, strlen(input), cases[i].matches ? a : NULL);
    }
    const char invalid[] = "AFg_-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, a, sizeof(a)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "holistic %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "holistic", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, a, 64);
        extract_case(d, input, 8 + gap + 64, gap == 40 ? a : NULL);
    }
    int n = snprintf(input, sizeof(input), "holistic%c%s", 0, a);
    extract_case(d, input, (size_t)n, a);
    snprintf(input, sizeof(input), "holistic %s", b);
    extract_case(d, input, strlen(input), b); /* No local entropy/default-FP filtering. */
    memset(changed, '0', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "holistic %s", changed);
    extract_case(d, input, strlen(input), changed);
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count, drop_at;
    const br_scan_ctx *ctx;
    const char *agent, *borrowed_url, *borrowed_name, *borrowed_key;
} expected;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at);
    CHECK(!e->borrowed_url && !e->borrowed_name && !e->borrowed_key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.holistic.dev/api/v1/project"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 764);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(strlen(request->headers[0].value) == 64 && !memcmp(request->headers[0].value, e->keys[at], 65));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    /* Retain original values only, never prepared request/header array/UA. */
    e->borrowed_url = request->url; e->borrowed_name = request->headers[0].name;
    e->borrowed_key = request->headers[0].value;
    if (e->drop_at) http->response.body_error = e->drop_at == at + 1 ? "partial read" : NULL;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && http->releases == at);
    CHECK(e->borrowed_url && !strcmp(e->borrowed_url, "https://api.holistic.dev/api/v1/project"));
    CHECK(e->borrowed_name && !strcmp(e->borrowed_name, "X-Api-Key"));
    CHECK(e->borrowed_key && !memcmp(e->borrowed_key, e->keys[at], 65));
    CHECK(response->status == http->response.status && response->body.data == http->response.body.data);
    CHECK(response->body.len == http->response.body.len && response->body_error == http->response.body_error);
    e->borrowed_url = e->borrowed_name = e->borrowed_key = NULL;
    test_http_release(user, response);
}

static void occurrences(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "holistic %s\nHOLISTIC %s\nholistic %s", a, b, a);
    const char *keys[] = {a, b, a};
    expected e = {.keys = keys, .count = 3, .agent = "TruffleHog holistic-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 204}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "holistic-offline"}; e.ctx = &ctx;
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], keys[i], true);
    br_results_clear(&out);
    http.calls = http.releases = 0; e.drop_at = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 3 && http.releases == 3);
    result_is(&out.items[0], b, true); result_is(&out.items[1], a, true); br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(!out.len); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3); br_results_clear(&out);
    CHECK(!e.borrowed_url && !e.borrowed_key && !e.borrowed_name);
}

static void verification(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "holistic %s", a);
    const char *keys[] = {a}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {199, 200, 201, 204, 206, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = statuses[i]};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    static const unsigned char after_nul[] = "\xff\0garbage\"data\":[]trailing";
    static const unsigned char binary[] = {0xff, 0, '{', '!'};
    const struct { br_slice body; bool verifies; } bodies[] = {
        {text("\"data\":[]"), false}, {text("malformed \"data\":[] trailing"), false},
        {{after_nul, sizeof(after_nul) - 1}, false}, {{binary, sizeof(binary)}, true},
        {text("{\"data\": []}"), true}, {text("{\"data\":[ ]}"), true},
        {text("{\"Data\":[]}"), true}, {text("\"data\":\n[]"), true},
        {text("\"data\":["), true}, {text("{\"data\":[{}]}"), true},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(*bodies); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = 200, .body = bodies[i].body};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], a, bodies[i].verifies); br_results_clear(&out);
    }
    const struct { int status; br_slice body; const char *cause; } reads[] = {
        {200, text("body without marker"), "read failed"}, {299, text("\"data\":[]"), ""},
        {199, {0}, "read failed"}, {401, text("\"data\":[]"), "read failed"},
        {500, {NULL, 9}, ""}, /* Error takes precedence even over unusable partial bytes. */
    };
    for (size_t i = 0; i < sizeof(reads) / sizeof(*reads); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = reads[i].status, .body = reads[i].body, .body_error = reads[i].cause};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(!out.len && http.calls == 1 && http.releases == 1); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } sends[] = {
        {7, "cannot create Holistic result"}, {-7, "out of memory constructing HTTP headers"},
        {1, "net/http: nil Context"}, {-1, NULL}, {1, a},
    };
    for (size_t i = 0; i < sizeof(sends) / sizeof(*sends); ++i) {
        http.calls = http.releases = 0; http.send_rc = sends[i].rc; http.send_error = sends[i].cause;
        http.response = (br_http_response){.status = 200, .body = text("\"data\":[]"), .body_error = ""};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], a, false); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}
static bool fail_agent(void *user)
{
    (void)user; fail_size = sizeof("TruffleHog ") + strlen("holistic-offline"); fail_after = 1; return false;
}

static void shared_setup(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "holistic %s", a);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    br_transport incomplete = {&http, NULL, test_http_release}; size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &incomplete}, {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = fail_agent, .user_agent = "holistic-offline"},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0; size_t before = failed;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && failed == before + (i == 2 || i == 3 ? 1u : 0u));
        result_is(&out.items[0], a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void expect_fatal(const br_detector *d, const br_scan_ctx *ctx, br_slice input,
                         br_results *out, const br_result *prior)
{
    char *error = NULL;
    CHECK(d->scan(d, ctx, true, input, out, &error) != 0 && error);
    CHECK(!fail_after && !fail_part_after && !fail_realloc_size);
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data && out->items[0].secret_parts == prior->secret_parts);
    CHECK(out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
    CHECK(out->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    free(error);
}

static void resources(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "holistic %s\nholistic %s\nholistic %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];

    size_t before = failed;
    fail_size = 65; fail_after = 2; /* FindAll must finish before any verification. */
    expect_fatal(d, &ctx, text(input), &out, &prior); CHECK(!http.calls && !http.releases && failed == ++before);
    fail_part_after = 1; /* Positive finding failure precedes nil-constructor drop. */
    expect_fatal(d, NULL, text(input), &out, &prior); CHECK(failed == ++before);
    fail_part_after = 2; /* Also fatal after an earlier nil-constructor drop. */
    expect_fatal(d, NULL, text(input), &out, &prior); CHECK(failed == ++before);
    fail_part_after = 2; /* Roll back an appended verified finding, not caller data. */
    expect_fatal(d, &ctx, text(input), &out, &prior);
    CHECK(http.calls == 1 && http.releases == 1 && failed == ++before);
    http.calls = http.releases = 0; http.send_rc = -7; http.send_error = "synthetic Do failure";
    fail_part_after = 2; /* Whole-Do suppression cannot suppress a later owned failure. */
    expect_fatal(d, &ctx, text(input), &out, &prior);
    CHECK(http.calls == 1 && http.releases == 1 && failed == ++before);
    http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL; e.drop_at = 1;
    fail_part_after = 3; /* First read drops, second appends, third fails: invocation-only rollback. */
    expect_fatal(d, &ctx, text(input), &out, &prior);
    CHECK(http.calls == 2 && http.releases == 2 && failed == ++before);
    http.calls = http.releases = 0; e.drop_at = 0; http.response.body_error = NULL;
    out.cap = 2; fail_realloc_size = 4 * sizeof(br_result); /* Real positive second-push failure. */
    expect_fatal(d, &ctx, text(input), &out, &prior);
    CHECK(http.calls == 2 && http.releases == 2 && failed == ++before);
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 401, .body = {NULL, 9}};
    expect_fatal(d, &ctx, text(input), &out, &prior); /* Invalid ABI body projection is fatal before status. */
    CHECK(http.calls == 1 && http.releases == 1 && failed == before);
    CHECK(!e.borrowed_url && !e.borrowed_name && !e.borrowed_key);
    br_results_clear(&out);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) != 0);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d); occurrences(d); verification(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !fail_realloc_size);
    return test_finish("Holistic extraction/occurrences/metadata/requests/status/binary-body/read-errors/Do/setup/lifetime/rollback");
}
