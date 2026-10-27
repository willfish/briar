/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[33], key2[33];
static const char host1[] = "synthetic1.as.deputy.com", host2[] = "synthetic2.as.deputy.com";
static const char path[] = "/api/v1/me";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, url_size, url_allocations;
static bool fail_agent_copy;

/* Actual resource paths only; no provider auth/URL seam or shared edits. */
void *malloc(size_t size)
{
    if (url_size && size == url_size) ++url_allocations;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_deputy_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Deputy detector output"));
    free(error); error = NULL;
    CHECK(br_deputy_init(NULL, NULL) == -1);
    CHECK(br_deputy_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_deputy_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 683 && detector->version == 0 && !strcmp(detector->name, "Deputy"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Deputy is a workforce management software that provides various tools for scheduling, time tracking, and communication. Deputy API keys can be used to access and modify data within the Deputy platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "deputy"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 683, key, "key"); /* Host REQUIRED but never a part, RawV2, ExtraData or primary secret. */
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, br_slice input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[34];
    const struct { const char *format; bool match; } cases[] = {
        {"deputy %s", true}, {"DePuTy:'%s'", true}, {"preDEPUTYsuffix\r\n%s", true},
        {"%s deputy", false}, {"%s", false}, {"deputy%s", false},
        {"deputy x%s", false}, {"deputy _%s", false}, {"deputy %sx", false}, {"deputy %s_", false},
        {"deputy .%s!", true}, {"deputy \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t at = (size_t)snprintf(input, sizeof(input), cases[i].format, key1);
        snprintf(input + at, sizeof(input) - at, "\n%s", host1);
        extraction_case(detector, text(input), cases[i].match ? key1 : NULL);
    }
    memcpy(changed, key1, sizeof(key1)); changed[8] = 'A';
    snprintf(input, sizeof(input), "deputy %s\n%s", changed, host1); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "deputy %.31s\n%s", key1, host1); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "deputy %sa\n%s", key1, host1); extraction_case(detector, text(input), NULL);
    memset(changed, 'z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "deputy %s\n%s", changed, host1); extraction_case(detector, text(input), changed); /* Lower alnum, not hex or local entropy-filtered. */
    snprintf(input, sizeof(input), "deputy %s", key1); extraction_case(detector, text(input), NULL); /* Host required. */
    extraction_case(detector, text(host1), NULL); extraction_case(detector, (br_slice){0}, NULL);
    const struct { const char *host; bool match; } hosts[] = {
        {"a.as.deputy.com", true}, {"a19.as.deputy.com", true}, {"foo-bar.as.deputy.com", true},
        {"a.as.deputy.com.evil", true}, {"http://a.as.deputy.com:443/path", true},
        {"A.as.deputy.com", false}, {"a.as.Deputy.com", false}, {"a.AS.deputy.com", false},
        {"a.as.deputy.COM", false}, {"foo_bar.as.deputy.com", false}, {"_a.as.deputy.com", false},
        {"a.as.deputy.com_", false}, {"a.as.deputy.comx", false}, {"as.deputy.com", false},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        snprintf(input, sizeof(input), "deputy %s\n%s", key1, hosts[i].host);
        extraction_case(detector, text(input), hosts[i].match ? key1 : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "deputy", 6); size_t at = 6;
            for (size_t r = 0; r < gap; ++r) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            at += (size_t)snprintf(input + at, sizeof(input) - at, "%s\n%s", key1, host1);
            extraction_case(detector, (br_slice){(const unsigned char *)input, at}, gap == 40 ? key1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "\xff\ndeputy %s\n%s\n\xff", key1, host1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, key1);
}

typedef struct {
    const char *const *keys, *const *hosts; size_t nkeys, nhosts;
    const char *agent, *borrowed_url, *borrowed_auth, *current_key, *current_host;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; size_t pair = http->calls - 1;
    CHECK(ctx && ctx == expected->original && pair < expected->nkeys * expected->nhosts);
    const char *key = expected->keys[pair / expected->nhosts], *host = expected->hosts[pair % expected->nhosts];
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000 && request->detector_type == 683);
    CHECK(strlen(request->url) == 8 + strlen(host) + strlen(path));
    CHECK(!memcmp(request->url, "https://", 8) && !memcmp(request->url + 8, host, strlen(host)));
    CHECK(!strcmp(request->url + 8 + strlen(host), "/api/v1/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    const char *auth = request->headers[1].value;
    CHECK(strlen(auth) == 38 && auth[38] == '\0' && !memcmp(auth, "OAuth ", 6) && !memcmp(auth + 6, key, 32));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    expected->borrowed_url = request->url; expected->borrowed_auth = auth;
    expected->current_key = key; expected->current_host = host;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(!memcmp(expected->borrowed_url + 8, expected->current_host, strlen(expected->current_host)));
        CHECK(!strcmp(expected->borrowed_url + 8 + strlen(expected->current_host), path));
        CHECK(!memcmp(expected->borrowed_auth, "OAuth ", 6) && !memcmp(expected->borrowed_auth + 6, expected->current_key, 32));
        CHECK(expected->borrowed_auth[38] == '\0'); /* Owned URL and stack auth survive release. */
        expected->borrowed_url = expected->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void products(const br_detector *detector)
{
    char input[4096]; size_t at = (size_t)snprintf(input, sizeof(input), "deputy %s\ndeputy %s\ndeputy %s\n", key1, key2, key1);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\n%s\n%s\n%s", host1, host2, host1);
    const char *keys[] = {key1, key2, key1}, *hosts[] = {host1, host2, host1};
    expected_http expected = {.keys = keys, .hosts = hosts, .nkeys = 3, .nhosts = 3, .agent = "TruffleHog deputy-offline"};
    test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "deputy-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, at);
    CHECK(results.len == 9 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], false);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, at);
    CHECK(results.len == 9 && http.calls == 9 && http.releases == 9);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], true);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, at);
    CHECK(!results.len && http.calls == 9 && http.releases == 9); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "deputy %s\n%s", key1, host1);
    const char *keys[] = {key1}, *hosts[] = {host1};
    expected_http expected = {.keys = keys, .hosts = hosts, .nkeys = 1, .nhosts = 1, .agent = "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status, rc; const char *cause, *read_error; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {201, 0, NULL, "ignored", true},
        {204, 0, NULL, "", true}, {299, 0, NULL, "ignored", true}, {300, 0, NULL, NULL, false},
        {401, 0, NULL, "ignored", false}, {403, 0, NULL, NULL, false}, {500, 0, NULL, NULL, false},
        {200, -1, "synthetic timeout", "ignored", false}, {200, 1, "net/http: nil Context", NULL, false},
        {200, 1, "out of memory constructing HTTP headers", NULL, false}, {200, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error},
                          .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key1, cases[i].verified); br_results_clear(&results);
    }
    /* Non-anchored source grammar may capture a hostname suffix; never silently
     * validate/normalize the complete input URL instead of using capture 1. */
    hosts[0] = "bar.as.deputy.com";
    snprintf(input, sizeof(input), "deputy %s\nhttp://foo-bar.as.deputy.com:443/path", key1);
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, true); br_results_clear(&results);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "deputy %s\n%s", key1, host1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static void unbounded_host(const br_detector *detector)
{
    const size_t label = 8192;
    char *host = malloc(label + 32), *input = malloc(label + 128); CHECK(host && input);
    memset(host, 'a', label); strcpy(host + label, ".as.deputy.com");
    snprintf(input, label + 128, "deputy %s\n%s", key1, host);
    const char *keys[] = {key1}, *hosts[] = {host};
    expected_http expected = {.keys = keys, .hosts = hosts, .nkeys = 1, .nhosts = 1, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    url_size = 8 + strlen(host) + sizeof(path); size_t before = url_allocations;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && url_allocations == before + 1);
    check_result(&results.items[0], key1, true); br_results_clear(&results); free(input); free(host); url_size = 0;
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 12345, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "deputy %s\n%s\n%s", key1, host1, host2);
    br_slice data = text(input); br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Deputy result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Deputy result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0;
    fail_alloc_size = 8 + strlen(host1) + sizeof(path); fail_alloc_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate Deputy request URL") && !fail_alloc_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate Deputy request URL") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL; /* URL resource failure BEFORE nil-context skip. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 33; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Skips do NOT append. */
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Deputy result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], key1, true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 32, 0); test_secret(key2, 32, 7);
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); verification(detector); suppressed_setup(detector);
    unbounded_host(detector); fatal_resources(detector);
    return test_finish("Deputy hidden-host occurrence products + PUBLIC OAuth + unbounded URL before skip + rollback");
}
