/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[33], b[33];
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static const char *borrowed_url;
static char expected_url[128];

/* Use existing allocation and insertion boundaries, including positive errors. */
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
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_geoapify_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_geoapify_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:geoapify)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_geoapify_init(&d, &error) != 0 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_geoapify_init(&d, &error) == 0 && d && !error);
    CHECK(br_geoapify_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 529 && d->version == 0 && !strcmp(d->name, "Geoapify") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Geoapify provides APIs for geolocation services, including geocoding, routing, and places. Geoapify API keys can be used to access these services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "geoapify"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 529, key, "key");
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32);
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
    char input[240], changed[34];
    const struct { const char *format; bool matches; } cases[] = {
        {"geoapify '%s'", true}, {"GeOaPiFy=%s", true}, {"preGEOAPIFYsuffix:%s", true}, {"geoapify\r\n%s", true},
        {"%s", false}, {"%s geoapify", false}, {"geo apify %s", false}, {"geoapify%s", false},
        {"geoapify x%s", false}, {"geoapify _%s", false}, {"geoapify %s_", false}, {"geoapify %s9", false},
        {"geoapify %.31s", false}, {"geoapify +%s=", true}, {"geoapify \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, a);
        extract_case(d, input, strlen(input), cases[i].matches ? a : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "geoapify", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, a, 32);
        extract_case(d, input, 40 + gap, gap == 40 ? a : NULL);
    }
    const char invalid[] = "AZ_-/+.=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, a, sizeof(a)); changed[20] = invalid[i];
        snprintf(input, sizeof(input), "geoapify %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    memset(changed, 'a', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "geoapify %s", changed); extract_case(d, input, strlen(input), changed); /* No local FP/entropy filter. */
    memset(changed, '0', 32);
    snprintf(input, sizeof(input), "geoapify %s", changed); extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "geoapify %s %s", a, b); extract_case(d, input, strlen(input), a);
    int n = snprintf(input, sizeof(input), "\xff\ngeoapify%c%s", 0, a); extract_case(d, input, (size_t)n, a);
    extract_case(d, NULL, 0, NULL);
}

typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_url);
    CHECK(request->detector_type == 529 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    snprintf(expected_url, sizeof(expected_url), "https://api.geoapify.com/v1/geocode/search?text=California&apiKey=%s", e->keys[at]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, expected_url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, e->agent));
    borrowed_url = request->url;
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_url && !strcmp(borrowed_url, expected_url));
    borrowed_url = NULL; test_http_release(user, response);
}
static void occurrences(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "geoapify %s\nGEOAPIFY %s\ngeoapify %s", a, b, a);
    const char *keys[] = {a, b, a}; expected e = {.keys = keys, .count = 3, .agent = "TruffleHog geoapify-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "geoapify-offline"}; e.ctx = &ctx;
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
    char input[50]; snprintf(input, sizeof(input), "geoapify %s", a);
    const char *keys[] = {a}; expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 250, 299, 300, 301, 400, 401, 403, 429, 500};
    static const unsigned char ignored[] = {0, 0xff, '{', '!'};
    const char *read_errors[] = {NULL, "", "ignored read failure"};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        for (size_t j = 0; j < sizeof(read_errors) / sizeof(read_errors[0]); ++j) {
            http.calls = http.releases = 0;
            http.response = (br_http_response){.status = statuses[i], .body = {ignored, sizeof(ignored)}, .body_error = read_errors[j]};
            br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
            result(&out.items[0], a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
        }
    }
    const struct { int rc; const char *error; } failures[] = {
        {1, "net/http: nil Context"}, {-7, "cannot create Geoapify result"}, {1, "out of memory constructing HTTP headers"},
        {-1, NULL}, {1, a}, {1, "context canceled"}, {1, "context deadline exceeded"},
    };
    http.response.status = 200;
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].error;
        br_results out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], a, false); br_results_clear(&out);
    }
}
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void shared_setup(const br_detector *d)
{
    char input[50]; snprintf(input, sizeof(input), "geoapify %s", a);
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
    char input[100]; snprintf(input, sizeof(input), "geoapify %s\ngeoapify %s", a, b); br_slice data = {(const unsigned char *)input, strlen(input)};
    const char *keys[] = {a, b}; expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 4; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; }
        if (failure == 1) { fail_size = 33; fail_after = 2; }
        /* 32-byte regex spans precede the two 32-byte Raw allocations. */
        if (failure == 2) { fail_size = 32; fail_after = 3; }
        if (failure == 3) fail_part_after = 2;
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) != 0);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure == 1 ? "out of memory copying detector capture" : "cannot create Geoapify result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after);
        CHECK(http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls && !borrowed_url);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot create Geoapify result") && !fail_part_after);
    check_prior(&out, &prior); free(error); error = NULL; /* Finding failure precedes constructor skip. */
    http.send_rc = 1; http.send_error = "out of memory in shared send"; fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot create Geoapify result") && !fail_part_after);
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior); free(error); error = NULL;
    http.calls = http.releases = 0;
    size_t cap = out.cap; out.cap = 0; /* Existing positive push-failure boundary. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) != 0 && error && !strcmp(error, "cannot append Geoapify result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior); free(error); br_results_clear(&out);
}
int main(void)
{
    test_secret(a, 32, 0); test_secret(b, 32, 11);
    const br_detector *d = descriptor(); extraction(d); occurrences(d); statuses_and_send(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part_after && !borrowed_url);
    return test_finish("Geoapify");
}
