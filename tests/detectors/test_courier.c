/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char suffix[] = "AbCdEfGhIjKlMnOpQrStUvWxYz09";
static const char key[] = "pk_q1_AbCdEfGhIjKlMnOpQrStUvWxYz09";
static const char other[] = "pk_NotWhitelisted7_AbCdEfGhIjKlMnOpQrStUvWxYz09";
static size_t auth_size, auth_allocations, fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Target actual resource paths, including shared positive-return failures. */
void *malloc(size_t size)
{
    if (auth_size && size == auth_size) ++auth_allocations;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) {
        fail_agent_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(suffix) == 28);
    CHECK(br_courier_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Courier detector output"));
    free(error); error = NULL;
    CHECK(br_courier_init(NULL, NULL) == -1);
    CHECK(br_courier_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_courier_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 665 && detector->version == 0 && !strcmp(detector->name, "Courier"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Courier is a notification service that allows developers to send notifications through multiple channels. Courier API keys can be used to manage and send notifications."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "courier"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 665, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, br_slice input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    size_t before = auth_allocations;
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && auth_allocations == before);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], candidate[128];
    const struct { const char *format; bool match; } cases[] = {
        {"courier %s", true}, {"CoUrIeR:'%s'", true}, {"xxCoUrIeRsuffix\r\n%s", true},
        {"%s courier", false}, {"%s", false}, {"courier%s", false},
        {"courier x%s", false}, {"courier _%s", false}, {"courier %sx", false}, {"courier %s_", false},
        {"courier .%s!", true}, {"courier \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, cases[i].match ? key : NULL);
    }
    const struct { const char *middle; bool match; } middles[] = {
        {"Z", true}, {"0", true}, {"NotWhitelisted7", true}, {"aAzZ09", true},
        {"", false}, {"live_test", false}, {"not-a-name", false}, {"\xc3\xa9", false},
    };
    for (size_t i = 0; i < sizeof(middles) / sizeof(middles[0]); ++i) {
        snprintf(candidate, sizeof(candidate), "pk_%s_%s", middles[i].middle, suffix);
        snprintf(input, sizeof(input), "courier %s", candidate);
        extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, middles[i].match ? candidate : NULL);
    }
    snprintf(input, sizeof(input), "courier Pk_q1_%s", suffix);
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, NULL);
    snprintf(input, sizeof(input), "courier pK_q1_%s", suffix);
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, NULL);
    snprintf(input, sizeof(input), "courier pk_q1_%.27s", suffix);
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, NULL);
    snprintf(input, sizeof(input), "courier pk_q1_%sZ", suffix);
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, NULL);
    snprintf(input, sizeof(input), "courier pk_example_AAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, "pk_example_AAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    extraction_case(detector, (br_slice){0}, NULL);

    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "courier", 7); size_t at = 7;
            for (size_t r = 0; r < gap; ++r) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key, sizeof(key));
            extraction_case(detector, (br_slice){(const unsigned char *)input, at + strlen(key)}, gap == 40 ? key : NULL);
        }
    }
    /* NUL is an ordinary rune in PrefixRegex; malformed bytes remain RE2
     * barriers, not a whole-input unsupported error or PLAIN normalization. */
    memcpy(input, "courier\0", 8); memcpy(input + 8, key, sizeof(key));
    extraction_case(detector, (br_slice){(const unsigned char *)input, 8 + strlen(key)}, key);
    input[7] = (char)0xff;
    extraction_case(detector, (br_slice){(const unsigned char *)input, 8 + strlen(key)}, NULL);
    int n = snprintf(input, sizeof(input), "\xff\ncourier %s\n\xff", key);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, key);
}

typedef struct { const char *const *keys; size_t count; const char *agent; } expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user;
    CHECK(ctx && http->calls <= expected->count);
    const char *expected_key = expected->keys[http->calls - 1];
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.courier.com/preferences"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 665);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(strlen(request->headers[1].value) == strlen(expected_key) + 7);
    CHECK(!memcmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, expected_key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    /* Exactly these three headers: no Content-Type or invented Content-Length. */
}

static void occurrences(const br_detector *detector)
{
    char input[512];
    int n = snprintf(input, sizeof(input), "courier %s\ncourier %s\nCoUrIeR %s", key, other, key);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key, other, key};
    expected_http expected = {keys, 3, "TruffleHog courier-offline"};
    test_http http = {.response = {.status = 204}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "courier-offline"};
    size_t before = auth_allocations;
    br_results results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    CHECK(auth_allocations == before + 2); /* Two separate preparations of the duplicate key. */
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true);
    br_results_clear(&results);
    http.calls = http.releases = 0; before = auth_allocations;
    results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(!results.len && !http.calls && !http.releases && auth_allocations == before);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, (size_t)n);
    CHECK(results.len == 3 && auth_allocations == before);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "courier %s", key);
    const char *keys[] = {key}; expected_http expected = {keys, 1, "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', 'b', 'a', 'd'};
    const struct { int status, rc; const char *cause, *body_error; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {204, 0, NULL, "ignored", true},
        {206, 0, NULL, NULL, true}, {299, 0, NULL, "ignored", true}, {300, 0, NULL, NULL, false},
        {401, 0, NULL, "ignored", false}, {403, 0, NULL, NULL, false}, {429, 0, NULL, NULL, false},
        {500, 0, NULL, "ignored", false},
        {200, -1, "synthetic timeout", NULL, false},
        {200, 1, "net/http: nil Context", "ignored", false},
        {200, 1, "out of memory constructing HTTP headers", NULL, false},
        {200, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].body_error},
                          .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, (size_t)n);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key, cases[i].verified);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "courier %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0;
        if (i == 4) fail_agent_copy = true; /* Actual shared UA allocation failure returns +1. */
        br_results results = test_scan(detector, &contexts[i], true, input, (size_t)n);
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static void unbounded_key(const br_detector *detector)
{
    const size_t middle = 8192, len = 3 + middle + 1 + 28;
    char *large = malloc(len + 1), *input = malloc(len + 9); CHECK(large && input);
    memcpy(large, "pk_", 3); memset(large + 3, 'Z', middle); large[3 + middle] = '_';
    memcpy(large + 4 + middle, suffix, sizeof(suffix));
    memcpy(input, "courier ", 8); memcpy(input + 8, large, len + 1);
    const char *keys[] = {large}; expected_http expected = {keys, 1, "TruffleHog"};
    test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    auth_size = len + sizeof("Bearer "); size_t before = auth_allocations;
    br_results results = test_scan(detector, &ctx, true, input, len + 8);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && auth_allocations == before + 1);
    check_result(&results.items[0], large, true);
    br_results_clear(&results); free(input); free(large);
    auth_size = strlen(key) + sizeof("Bearer ");
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 12345, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0);
    return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    char input[256]; int n = snprintf(input, sizeof(input), "courier %s\ncourier %s", key, key);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    /* Own finding failure precedes the nil-context constructor skip. */
    size_t before = auth_allocations; fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(!fail_part_after && error && !strcmp(error, "cannot create Courier result") && auth_allocations == before);
    check_prior(&results, prior); free(error); error = NULL;
    /* A second finding failure rolls back the first occurrence, not the caller. */
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(!fail_part_after && error && !strcmp(error, "cannot create Courier result") && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0;
    fail_alloc_size = auth_size; fail_alloc_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(!fail_alloc_after && error && !strcmp(error, "cannot allocate Courier Authorization header") && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    /* Real positive regex workspace failure normalizes to fatal -1. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after);
    check_prior(&results, prior);
    fail_alloc_size = strlen(key) + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(!fail_alloc_after && error && !strcmp(error, "out of memory copying detector capture"));
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Courier result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    /* Failures do not poison subsequent invocations or compiled state. */
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], key, true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    auth_size = strlen(key) + sizeof("Bearer ");
    extraction(detector); occurrences(detector); verification(detector); suppressed_setup(detector);
    unbounded_key(detector); fatal_resources(detector);
    return test_finish("Courier exact occurrences + unbounded Bearer + constructor skip + suppressed send domain + rollback");
}
