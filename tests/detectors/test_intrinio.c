/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define br_result_set_verification_error intrinio_real_setter
#define br_results_push intrinio_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

#define KEY_A "Ab3Cd5Ef7Gh9Jk1Lm3Np5Qr7St9Uv1Wx3Yz5Ab7Cd9Ef"
#define KEY_B "9zY8xW7vU6tS5rQ4pO3nM2lK1jI0hG9fE8dC7bA6Z5y4"
#define URL_PREFIX "https://api-v2.intrinio.com/securities?api_key="
static size_t fail_size, fail_after, fail_part_after, fail_push_after;
static size_t failed_allocations, url_allocations, setter_calls;
static bool fail_agent;

/* Reuse the named-test allocation/JSON seams with the actual shared helpers. */
void *malloc(size_t size)
{
    if (size == sizeof(URL_PREFIX) + 44) ++url_allocations;
    if (fail_after && size == fail_size && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent && !strcmp(text, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return intrinio_real_setter(result, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return intrinio_real_push(out, owned);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(KEY_A) == 44 && strlen(KEY_B) == 44);
    CHECK(br_intrinio_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Intrinio detector output")); free(error); error = NULL;
    CHECK(br_intrinio_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:intrinio)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_intrinio_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_intrinio_init(&d, &error) == 0 && d && !error);
    CHECK(br_intrinio_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 579 && d->version == 0 && !strcmp(d->name, "Intrinio") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Intrinio provides financial data APIs. Intrinio API keys can be used to access various financial datasets and services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "intrinio"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void result_is(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 579, expected, "key");
    CHECK(result->raw.len == 44 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 44);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    size_t before = url_allocations;
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases && url_allocations == before);
    if (expected) result_is(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    const struct { const char *input, *expected; } cases[] = {
        {"intrinio '" KEY_A "'", KEY_A}, {"InTrInIo\r\n" KEY_B, KEY_B},
        {"myINTRINIOsuffix:" KEY_A, KEY_A}, {"intrinio-" KEY_A "-", KEY_A},
        {"intrinio \t" KEY_A "\r\n", KEY_A}, {"intrinio " KEY_A " " KEY_B, KEY_A},
        {KEY_A, NULL}, {KEY_A " intrinio", NULL}, {"intrin-io " KEY_A, NULL},
        {"intrinio" KEY_A, NULL}, {"intrinio X" KEY_A, NULL}, {"intrinio " KEY_A "X", NULL},
        {"intrinio _" KEY_A, NULL}, {"intrinio " KEY_A "_", NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
        extract_case(d, cases[i].input, strlen(cases[i].input), cases[i].expected);
    char input[256], changed[45];
    memcpy(changed, KEY_A, sizeof(changed)); changed[43] = '\0';
    snprintf(input, sizeof(input), "intrinio %s", changed); extract_case(d, input, strlen(input), NULL);
    const char disallowed[] = "_+-/=. ";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, KEY_A, sizeof(changed)); changed[20] = disallowed[i];
        snprintf(input, sizeof(input), "intrinio %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    const char allowed[] = "aZ0";
    for (size_t i = 0; i < sizeof(allowed) - 1; ++i) {
        memset(changed, allowed[i], 44); changed[44] = '\0';
        snprintf(input, sizeof(input), "intrinio %s", changed); extract_case(d, input, strlen(input), changed);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "intrinio", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, KEY_A, 44);
        extract_case(d, input, 8 + gap + 44, gap == 40 ? KEY_A : NULL);
        input[9] = '\r'; input[10] = '\n'; input[11] = '\0';
        extract_case(d, input, 8 + gap + 44, gap == 40 ? KEY_A : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 8 + 2 * gap, KEY_A, 44);
        extract_case(d, input, 8 + 2 * gap + 44, gap == 40 ? KEY_A : NULL);
    }
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *keys[3], *agent;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_url;
    char saved_url[sizeof(URL_PREFIX) + 44];
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && at < 3 && ctx == s->ctx && http->releases == at && !s->borrowed_url);
    CHECK(request->detector_type == 579 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(strlen(request->url) == sizeof(URL_PREFIX) - 1 + 44);
    CHECK(!memcmp(request->url, URL_PREFIX, sizeof(URL_PREFIX) - 1));
    CHECK(!strcmp(request->url + sizeof(URL_PREFIX) - 1, s->keys[at]));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, s->agent));
    /* Retain only the provider-owned URL, not effective request/header/UA storage. */
    s->borrowed_url = request->url;
    memcpy(s->saved_url, request->url, sizeof(s->saved_url));
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_url) {
        CHECK(http->calls == http->releases + 1);
        CHECK(!memcmp(s->borrowed_url, s->saved_url, sizeof(s->saved_url)));
        s->borrowed_url = NULL;
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static void occurrences_and_constructor(const br_detector *d)
{
    const char input[] = "intrinio " KEY_A "\nintrinio " KEY_B "\nintrinio " KEY_A;
    script s = {.keys = {KEY_A, KEY_B, KEY_A}, .agent = "TruffleHog intrinio-offline", .count = 3};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "intrinio-offline"}; s.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        size_t before = url_allocations;
        br_results out = test_scan(d, &ctx, pass != 0, input, sizeof(input) - 1);
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        CHECK(url_allocations == before + (pass ? 3u : 0u));
        for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], s.keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    size_t before = url_allocations;
    br_results out = test_scan(d, NULL, true, input, sizeof(input) - 1);
    CHECK(!out.len && url_allocations == before + 3 && http.calls == 3 && http.releases == 3); br_results_clear(&out);
    before = url_allocations;
    out = test_scan(d, NULL, false, input, sizeof(input) - 1);
    CHECK(out.len == 3 && url_allocations == before && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) result_is(&out.items[i], s.keys[i], false);
    br_results_clear(&out);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }

static void verification_and_shared_errors(const br_detector *d)
{
    const char input[] = "intrinio " KEY_A;
    script s = {.keys = {KEY_A}, .agent = "TruffleHog", .count = 1};
    test_http http = {.user = &s, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored partial read"};
        br_results out = test_scan(d, &ctx, true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], KEY_A, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    /* No body validation or ReadAll is reached, even for an unreadable slice. */
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 200, .body = {NULL, 3}, .body_error = "read failed"};
    br_results out = test_scan(d, &ctx, true, input, sizeof(input) - 1);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], KEY_A, true); br_results_clear(&out);
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "net/http: nil Context"},
        {1, "out of memory copying detector capture"}, {-1, "cannot allocate Intrinio verification URL"},
        {1, "out of memory constructing HTTP headers"}, {-1, KEY_A}, {1, ""}, {1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i % 2 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        out = test_scan(d, &ctx, true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], KEY_A, false); br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_transport missing_send = {&http, NULL, release_response};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport, .cancelled = fail_headers}, {.transport = &transport, .cancelled = arm_agent},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        out = test_scan(d, &contexts[i], true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i >= 5 ? 1u : 0u));
        result_is(&out.items[0], KEY_A, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1 && !setter_calls && !s.borrowed_url);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    const char input[] = "intrinio " KEY_A "\nintrinio " KEY_B;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    script s = {.keys = {KEY_A, KEY_B}, .agent = "TruffleHog", .count = 2};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    char *error = NULL;
    const struct { const char *cause; size_t calls; } cases[] = {
        {"out of memory copying detector capture", 0}, {"out of memory iterating regex", 0},
        {"cannot create Intrinio finding", 0}, {"cannot create Intrinio finding", 1},
        {"cannot create Intrinio finding", 1}, {"cannot allocate Intrinio verification URL", 0},
        {"cannot allocate Intrinio verification URL", 1}, {"cannot append Intrinio finding", 2},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        http.calls = http.releases = 0;
        if (i == 0) { fail_size = 45; fail_after = 2; }
        if (i == 1) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (i == 2) fail_part_after = 1;
        if (i == 3) fail_part_after = 2;
        if (i == 4) { fail_size = 44; fail_after = 2; }
        if (i == 5) { fail_size = sizeof(URL_PREFIX) + 44; fail_after = 1; }
        if (i == 6) { fail_size = sizeof(URL_PREFIX) + 44; fail_after = 2; }
        if (i == 7) { fail_push_after = 2; http.send_rc = 1; http.send_error = "cannot allocate Intrinio verification URL"; }
        /* Owned failures precede nil-constructor drops, success and suppressed Do errors. */
        const br_scan_ctx *scan_ctx = i <= 2 || i == 5 ? NULL : &ctx;
        CHECK(d->scan(d, scan_ctx, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, &error) == -1);
        CHECK(error && !strcmp(error, cases[i].cause)); free(error); error = NULL;
        CHECK(!fail_after && !fail_part_after && !fail_push_after);
        CHECK(http.calls == cases[i].calls && http.releases == http.calls && !s.borrowed_url);
        prior_unchanged(&out, &prior);
    }
    http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL; fail_push_after = 2;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Intrinio finding") && !fail_push_after); free(error); error = NULL;
    CHECK(http.calls == 2 && http.releases == 2); prior_unchanged(&out, &prior);
    http.calls = http.releases = 0; fail_push_after = 2;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Intrinio finding") && !fail_push_after); free(error); error = NULL;
    CHECK(!http.calls && !http.releases); prior_unchanged(&out, &prior);
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, NULL) == -1);
    CHECK(!fail_part_after); prior_unchanged(&out, &prior);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases); prior_unchanged(&out, &prior);
    br_results_clear(&out);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    occurrences_and_constructor(d);
    verification_and_shared_errors(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_push_after && !fail_agent && !setter_calls);
    return test_finish("Intrinio grammar/occurrences/metadata/URL/status/errors/release/rollback");
}
