/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[33], key2[33];
static const char valid_body[] = "not JSON: \"planCredits\":anything; \"token\":a-different-key";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Actual owned resources and positive helper failures, not a provider seam. */
void *malloc(size_t size)
{
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
    CHECK(br_diffbot_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Diffbot detector output"));
    free(error); error = NULL;
    CHECK(br_diffbot_init(NULL, NULL) == -1);
    CHECK(br_diffbot_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_diffbot_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 726 && detector->version == 0 && !strcmp(detector->name, "Diffbot"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Diffbot is a service that provides APIs for extracting data from web pages. Diffbot API tokens can be used to access these services and extract data from web content."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "diffbot"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 726, key, "key");
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
        {"diffbot %s", true}, {"DiFfBoT:'%s'", true}, {"preDIFFBOTsuffix\r\n%s", true},
        {"%s diffbot", false}, {"%s", false}, {"diffbot%s", false},
        {"diffbot x%s", false}, {"diffbot _%s", false}, {"diffbot %sx", false}, {"diffbot %s_", false},
        {"diffbot .%s!", true}, {"diffbot \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, text(input), cases[i].match ? key1 : NULL);
    }
    memcpy(changed, key1, sizeof(key1)); changed[8] = 'A';
    snprintf(input, sizeof(input), "diffbot %s", changed); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "diffbot %.31s", key1); extraction_case(detector, text(input), NULL);
    snprintf(input, sizeof(input), "diffbot %sa", key1); extraction_case(detector, text(input), NULL);
    memset(changed, 'z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "diffbot %s", changed); extraction_case(detector, text(input), changed); /* Alnum, not hex/entropy-filtered. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "diffbot", 7); size_t at = 7;
            for (size_t r = 0; r < gap; ++r) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key1, sizeof(key1));
            extraction_case(detector, (br_slice){(const unsigned char *)input, at + 32}, gap == 40 ? key1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "\xff\ndiffbot %s\n\xff", key1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, key1);
    extraction_case(detector, (br_slice){0}, NULL);
}

typedef struct { int status, rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct {
    const char *const *keys; size_t count;
    const reply *replies;
    const char *agent, *borrowed_url, *current_key;
    const br_scan_ctx *original;
    uint32_t timeout_ms;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user;
    CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *key = expected->keys[http->calls - 1];
    const char prefix[] = "https://api.diffbot.com/v4/account?token=";
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == expected->timeout_ms && request->detector_type == 726);
    CHECK(strlen(prefix) == 41 && strlen(request->url) == 73 && request->url[73] == '\0');
    CHECK(!memcmp(request->url, prefix, 41) && !memcmp(request->url + 41, key, 32));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, expected->agent)); /* No Type/Accept/Auth/dedup headers. */
    expected->borrowed_url = request->url; expected->current_key = key;
    if (expected->replies) {
        const reply *r = &expected->replies[http->calls - 1];
        http->response = (br_http_response){.status = r->status, .body = r->body, .body_error = r->read_error};
        http->send_rc = r->rc; http->send_error = r->send_error;
    }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(strlen(expected->borrowed_url) == 73 && expected->borrowed_url[73] == '\0');
        CHECK(!memcmp(expected->borrowed_url + 41, expected->current_key, 32)); /* Complete stack URL survives error/success release. */
        expected->borrowed_url = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void verification_case(const br_detector *detector, reply response, bool verified)
{
    char input[128]; int n = snprintf(input, sizeof(input), "diffbot %s", key1);
    const char *keys[] = {key1};
    expected_http expected = {.keys = keys, .count = 1, .replies = &response, .agent = "TruffleHog", .timeout_ms = 10000};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key1, verified); br_results_clear(&results);
}

static void binary_markers_and_statuses(const br_detector *detector)
{
    const struct { const char *body; bool verified; } bodies[] = {
        {"", false}, {"\"token\":", false}, {"\"planCredits\":", false},
        {"\"token\":\"unrelated\",\"planCredits\":0", true},
        {"malformed \"planCredits\": nonsense \"token\":!", true},
        {"\"token\":\"\"\"planCredits\":null", true},
        {"\"token\" :1,\"planCredits\":2", false}, {"\"token\":1,\"planCredits\" :2", false},
        {"\"Token\":1,\"planCredits\":2", false}, {"\"token\":1,\"plancredits\":2", false},
        {"{\"token\":1,\"planCredits\":2}", true},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i)
        verification_case(detector, (reply){.status = 200, .body = text(bodies[i].body)}, bodies[i].verified);
    static const char binary[] = "ignored\0\"planCredits\":nonsense\0\"token\":not-the-candidate";
    verification_case(detector, (reply){.status = 200, .body = {(const unsigned char *)binary, sizeof(binary) - 1}}, true);
    verification_case(detector, (reply){.status = 200, .body = text(valid_body), .read_error = "synthetic read failure"}, false);
    verification_case(detector, (reply){.status = 200, .body = text(valid_body), .read_error = ""}, false);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
        verification_case(detector, (reply){.status = statuses[i], .body = text(valid_body)}, statuses[i] >= 200 && statuses[i] < 300);
    verification_case(detector, (reply){.status = 200, .body = text(valid_body), .rc = -1, .send_error = "synthetic timeout"}, false);
    verification_case(detector, (reply){.status = 200, .body = text(valid_body), .rc = 1, .send_error = "net/http: nil Context"}, false);
    verification_case(detector, (reply){.status = 200, .body = text(valid_body), .rc = 1, .send_error = "out of memory constructing HTTP headers"}, false);
    verification_case(detector, (reply){.status = 200, .body = text(valid_body), .rc = 1}, false);
}

static void occurrences_and_timeout(const br_detector *detector)
{
    char input[256]; int n = snprintf(input, sizeof(input), "diffbot %s\nDIFFBOT %s\ndiffbot %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1};
    const reply replies[] = {
        {.status = 200, .body = text(valid_body)}, {.status = 200, .body = text(valid_body), .read_error = ""},
        {.status = 299, .body = text(valid_body)},
    };
    expected_http expected = {.keys = keys, .count = 3, .replies = replies, .agent = "TruffleHog diffbot-offline", .timeout_ms = 10000};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "diffbot-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, (size_t)n);
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3); /* Read error RETAINS current finding; later occurrence still verifies. */
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], i != 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(!results.len && http.calls == 3 && http.releases == 3); br_results_clear(&results); /* Constructor skip, no artificial append. */
    results = test_scan(detector, NULL, false, input, (size_t)n);
    CHECK(results.len == 3); br_results_clear(&results);
    /* The selected Diffbot request's 10s override must NOT mutate a generic
     * SANE request's default. This is an injected control request, not live I/O. */
    char url[74]; snprintf(url, sizeof(url), "https://api.diffbot.com/v4/account?token=%s", key1);
    expected.count = 1; expected.replies = NULL; expected.timeout_ms = 5000; http.calls = http.releases = 0;
    const br_http_request control = {.method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 726};
    br_http_response response = {0}; char *error = NULL;
    CHECK(br_http_send(&ctx, &control, &response, &error) == 0 && !error);
    br_http_release(&ctx, &response); CHECK(http.calls == 1 && http.releases == 1);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "diffbot %s", key1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, (size_t)n);
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
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
    char input[256]; int n = snprintf(input, sizeof(input), "diffbot %s\ndiffbot %s", key1, key2);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    test_http http = {.response = {.status = 200, .body = text(valid_body)}}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Diffbot result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Diffbot result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 33; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Skips never append. */
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Diffbot result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key1, true); check_result(&results.items[1], key2, true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 32, 0); test_secret(key2, 32, 7);
    const br_detector *detector = descriptor();
    extraction(detector); binary_markers_and_statuses(detector); occurrences_and_timeout(detector);
    suppressed_setup(detector); fatal_resources(detector);
    return test_finish("Diffbot occurrences + binary markers + retained read failures + SANE 10s override + rollback");
}
