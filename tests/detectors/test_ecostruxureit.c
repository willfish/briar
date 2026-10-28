/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[60], key2[60];
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Genuine capture/finding/shared-send resources, no auth/formatting seam. */
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

static void make_key(char out[60], size_t len, size_t shift)
{
    memcpy(out, "AK1", 3); test_secret(out + 3, len - 3, shift);
    out[10] = 'G'; out[13] = '/'; out[len - 1] = 'Z';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 53 && strlen(key2) == 58);
    CHECK(br_ecostruxureit_init(NULL, &error) == -1 && error && !strcmp(error, "invalid EcoStruxureIT detector output"));
    free(error); error = NULL;
    CHECK(br_ecostruxureit_init(NULL, NULL) == -1);
    CHECK(br_ecostruxureit_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_ecostruxureit_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 801 && detector->version == 0 && !strcmp(detector->name, "EcoStruxureIT"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "EcoStruxure IT is a cloud-based platform that provides IT infrastructure management. EcoStruxure IT API keys can be used to access and manage IT infrastructure data and operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ecostruxureit"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector; /* Registry/default selection belongs to the parent. */
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 801, key, "key");
    CHECK(strlen(key) >= 53 && strlen(key) <= 58 && result->verified == verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK((size_t)json_object_get_string_len(part) == strlen(key));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[60], captured[60];
    const struct { const char *format; bool matches; } cases[] = {
        {"ecostruxureit '%s'", true}, {"ECoSTRUXUREIT=%s", true}, {"preecostruxureitsuffix:%s", true},
        {"ecostruxureit\r\n%s", true}, {"ecostruxureit\r%s", true}, {"ecostruxureit\n%s", true},
        {"%s", false}, {"%s ecostruxureit", false}, {"eco struxureit %s", false},
        {"ecostruxureit%s", false}, {"ecostruxureit x%s", false}, {"ecostruxureit _%s", false},
        {"ecostruxureit %s_", false}, {"ecostruxureit \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    for (size_t len = 52; len <= 59; ++len) {
        make_key(changed, len, 0); snprintf(input, sizeof(input), "ecostruxureit %s", changed);
        extraction_case(detector, input, strlen(input), len >= 53 && len <= 58 ? changed : NULL);
    }
    const size_t positions[] = {0, 1, 2}; const char invalid_prefix[] = {'a', 'k', 'I'};
    for (size_t i = 0; i < 3; ++i) {
        memcpy(changed, key1, strlen(key1) + 1); changed[positions[i]] = invalid_prefix[i];
        snprintf(input, sizeof(input), "ECOSTRUXUREIT %s", changed); extraction_case(detector, input, strlen(input), NULL); /* AK1 is literal CASE. */
    }
    const char invalid[] = "_-+=.\\";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, strlen(key1) + 1); changed[30] = invalid[i];
        snprintf(input, sizeof(input), "ecostruxureit %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memcpy(changed, "AK1", 3); memset(changed + 3, 'a', 50); changed[53] = '\0';
    snprintf(input, sizeof(input), "ecostruxureit %s", changed); extraction_case(detector, input, strlen(input), changed); /* No entropy/Base64/token validation. */
    memcpy(changed, key1, strlen(key1) + 1); changed[52] = '/';
    snprintf(input, sizeof(input), "ecostruxureit %s", changed); extraction_case(detector, input, strlen(input), NULL); /* Cannot backtrack below 50-tail minimum. */
    memcpy(changed, key2, strlen(key2) + 1); changed[57] = '/';
    memcpy(captured, changed, 57); captured[57] = '\0';
    snprintf(input, sizeof(input), "ecostruxureit %s", changed); extraction_case(detector, input, strlen(input), captured); /* Greedy slash-at-EOF backtracks to word -> slash boundary. */
    snprintf(input, sizeof(input), "ecostruxureit %sQ", changed); extraction_case(detector, input, strlen(input), changed); /* At max length slash -> Q boundary captures slash, excludes Q. */
    snprintf(input, sizeof(input), "ecostruxureit %s/continued", key2); extraction_case(detector, input, strlen(input), key2); /* Alphabet continues after a valid max-length word boundary; no full-token heuristic. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            size_t at = strlen("ecostruxureit"); memcpy(input, "ecostruxureit", at);
            for (size_t i = 0; i < gap; ++i) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key1, strlen(key1)); at += strlen(key1);
            extraction_case(detector, input, at, gap == 40 ? key1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "ecostruxureit%c%s", 0, key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\necostruxureit %s\n\xff", key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "ecostruxureit %s %s", key1, key2); extraction_case(detector, input, (size_t)n, key1);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys; size_t count;
    const char *agent, *borrowed_auth, *current_key;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *key = expected->keys[http->calls - 1]; size_t len = strlen(key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.ecostruxureit.com/rest/v1/organizations"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 801);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 7 + len);
    CHECK(!memcmp(request->headers[1].value, "Bearer ", 7) && !memcmp(request->headers[1].value + 7, key, len + 1));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    CHECK(!expected->borrowed_auth); expected->borrowed_auth = request->headers[1].value; expected->current_key = key;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_auth) {
        CHECK(strlen(expected->borrowed_auth) == 7 + strlen(expected->current_key) && !memcmp(expected->borrowed_auth, "Bearer ", 7));
        CHECK(!memcmp(expected->borrowed_auth + 7, expected->current_key, strlen(expected->current_key) + 1)); /* Full max-65-byte auth plus NUL lives THROUGH release. */
        expected->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void occurrences_and_skips(const br_detector *detector)
{
    char input[320]; snprintf(input, sizeof(input), "ecostruxureit %s\nECOSTRUXUREIT %s\necostruxureit %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; expected_http expected = {.keys = keys, .count = 3, .agent = "TruffleHog eco-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "eco-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3 && !expected.borrowed_auth);
        CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true);
        br_results_clear(&results);
    } /* Every occurrence and repeat scan, not uniqueness or persistent cache. */
    http.calls = http.releases = 0;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && !http.calls && !http.releases); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    char trailing[60]; memcpy(trailing, key2, strlen(key2) + 1); trailing[57] = '/';
    snprintf(input, sizeof(input), "ecostruxureit %sQ", trailing);
    const char *one[] = {trailing}; expected.keys = one; expected.count = 1; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], trailing, true); br_results_clear(&results);
}

static void status_and_send_behavior(const br_detector *detector)
{
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {
        {199, NULL, false}, {200, NULL, true}, {201, "ignored", true}, {204, "", true}, {299, "ignored", true},
        {300, NULL, false}, {401, "ignored", false}, {403, NULL, false}, {500, "", false},
    };
    const char *keys[] = {key2}; expected_http expected = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[128]; snprintf(input, sizeof(input), "ecostruxureit %s", key2);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_auth);
        check_result(&results.items[0], key2, cases[i].verified); br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, key2}};
    http.response = (br_http_response){.status = 200, .body = {body, sizeof(body)}, .body_error = "ignored"};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key2, false); br_results_clear(&results);
    } /* Mixed shared setup/allocation/Do causes all suppress; none classifies as skip. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "ecostruxureit %s", key1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
                             {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "ecostruxureit %s\necostruxureit %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)}; br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create EcoStruxureIT result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL; /* Finding failure precedes nil-context skip. */
    const char *keys[] = {key1, key2}; expected_http expected = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create EcoStruxureIT result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL; /* Roll back earlier verified result, not caller findings. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = strlen(key2) + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = strlen(key2); fail_alloc_after = 1; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create EcoStruxureIT result") && !fail_alloc_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Skips never append. */
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append EcoStruxureIT result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key1, true); check_result(&results.items[1], key2, true); br_results_clear(&results);
}

int main(void)
{
    make_key(key1, 53, 0); make_key(key2, 58, 7);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_skips(detector); status_and_send_behavior(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("EcoStruxureIT");
}
