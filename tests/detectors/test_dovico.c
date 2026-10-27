/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key_a[36], key_b[36], key_c[36];
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_duplicate_after;
static size_t auth_size, auth_allocations;
static const char *fail_duplicate_text;
static bool fail_agent_copy;

/* Target real resource/positive setter failures, not an auth helper seam. */
void *malloc(size_t size)
{
    if (auth_size && size == auth_size) ++auth_allocations;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    if (fail_duplicate_after && fail_duplicate_text && !strcmp(text, fail_duplicate_text) && --fail_duplicate_after == 0) return NULL;
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

static size_t header_size(const char *key, const char *user)
{
    return strlen("WRAP access_token=\"client=") + strlen(key) + strlen("&user_token=") + strlen(user) + sizeof("\"");
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 35 && strlen(key_b) == 35 && strlen(key_c) == 35);
    CHECK(br_dovico_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Dovico detector output"));
    free(error); error = NULL;
    CHECK(br_dovico_init(NULL, NULL) == -1);
    CHECK(br_dovico_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_dovico_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 386 && detector->version == 0 && !strcmp(detector->name, "Dovico"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Dovico is a time tracking and project management service. Dovico keys can be used to access and manage time tracking and project data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "dovico"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, const char *user, bool verified, const char *cause)
{
    size_t klen = strlen(key), ulen = strlen(user);
    CHECK(result->detector_type == 386 && !result->detector_name);
    CHECK(result->raw.len == klen && !memcmp(result->raw.data, key, klen));
    CHECK(result->raw_v2.len == klen + 1 + ulen && !memcmp(result->raw_v2.data, key, klen));
    CHECK(result->raw_v2.data[klen] == ':' && !memcmp(result->raw_v2.data + klen + 1, user, ulen));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == klen && !memcmp(json_object_get_string(part), key, klen));
    CHECK(json_object_object_get_ex(result->secret_parts, "user_key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == ulen && !memcmp(json_object_get_string(part), user, ulen));
}

static void extraction_case(const br_detector *detector, br_slice candidate, const char *captured)
{
    unsigned char input[768]; CHECK(candidate.len + strlen(key_b) + 100 < sizeof(input));
    memcpy(input, candidate.data, candidate.len); size_t at = candidate.len;
    memset(input + at, '.', 80); at += 80;
    at += (size_t)snprintf((char *)input + at, sizeof(input) - at, "\ndovico %s", key_b);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, at);
    CHECK(results.len == (captured ? 2u : 0u) && !http.calls && !http.releases);
    if (captured) {
        check_result(&results.items[0], captured, key_b, false, NULL);
        check_result(&results.items[1], key_b, captured, false, NULL);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[80], extended[37]; snprintf(extended, sizeof(extended), "%sx", key_a);
    const struct { const char *format; int outcome; } cases[] = {
        {"dovico %s", 1}, {"DoViCo:'%s'", 1}, {"preDOVICOsuffix\r\n%s", 1},
        {"%s dovico", 0}, {"%s", 0}, {"dovico%s", 0}, {"dovico _%s", 0},
        {"dovico %s_", 0}, {"dovico %sA", 0}, {"dovico %s-", 1}, {"dovico %s.more", 1},
        {"dovico %sx", 2}, {"dovico \xc3\xa9%s\xc3\xa9", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a);
        extraction_case(detector, text(input), cases[i].outcome == 2 ? extended : cases[i].outcome ? key_a : NULL);
    }
    memcpy(changed, key_a, sizeof(key_a)); changed[8] = 'A';
    snprintf(input, sizeof(input), "dovico %s", changed); extraction_case(detector, text(input), NULL);
    memcpy(changed, key_a, sizeof(key_a)); changed[33] = 'A';
    snprintf(input, sizeof(input), "dovico %s", changed); extraction_case(detector, text(input), NULL);
    memcpy(changed, key_a, sizeof(key_a)); changed[32] = 'X';
    snprintf(input, sizeof(input), "dovico %s", changed); extraction_case(detector, text(input), NULL); /* Separator is a LITERAL dot. */
    snprintf(input, sizeof(input), "dovico %.33s", key_a); extraction_case(detector, text(input), NULL); /* Nonempty tail required. */
    memset(changed, 'z', 32); strcpy(changed + 32, ".z");
    snprintf(input, sizeof(input), "dovico %s", changed); extraction_case(detector, text(input), changed); /* Lower alnum, not hex/entropy-filtered. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "dovico", 6); size_t at = 6;
        for (size_t r = 0; r < gap; ++r) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
        memcpy(input + at, key_a, sizeof(key_a));
        extraction_case(detector, (br_slice){(const unsigned char *)input, at + strlen(key_a)}, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "\xff\ndovico %s\n\xff", key_a);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, key_a);
    snprintf(input, sizeof(input), "dovico %s\ndovico %s", key_a, key_a);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results); /* Unique equality removes every self-pair, even before nil-context verification. */
}

typedef struct { const char *key, *user; int status, rc; const char *cause, *read_error; } row;
typedef struct {
    const row *rows; size_t count;
    const char *agent, *borrowed_auth;
    const row *current;
    const br_scan_ctx *original;
    char *owned_error;
    bool clobber_error;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const row *r = &expected->rows[http->calls - 1];
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.dovico.com/employees/?version=7"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 386);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len); /* Logical NoBody only. */
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    const char *auth = request->headers[1].value;
    CHECK(strlen(auth) + 1 == header_size(r->key, r->user));
    size_t at = strlen("WRAP access_token=\"client="); CHECK(!memcmp(auth, "WRAP access_token=\"client=", at));
    CHECK(!memcmp(auth + at, r->key, strlen(r->key))); at += strlen(r->key);
    CHECK(!memcmp(auth + at, "&user_token=", 12)); at += 12;
    CHECK(!memcmp(auth + at, r->user, strlen(r->user))); at += strlen(r->user);
    CHECK(auth[at] == '"' && auth[at + 1] == '\0');
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    expected->borrowed_auth = auth; expected->current = r;
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    http->response = (br_http_response){.status = r->status, .body = {body, sizeof(body)}, .body_error = r->read_error};
    http->send_rc = r->rc; http->send_error = r->cause;
}

static int send_request(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; expected_http *expected = http->user;
    if (expected) expected->owned_error = *error;
    return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_auth) {
        CHECK(strlen(expected->borrowed_auth) + 1 == header_size(expected->current->key, expected->current->user));
        CHECK(!memcmp(expected->borrowed_auth + 26, expected->current->key, strlen(expected->current->key))); /* Complete owned header survives release. */
        expected->borrowed_auth = NULL;
    }
    if (expected && expected->clobber_error && expected->owned_error) { expected->owned_error[0] = 'X'; expected->owned_error = NULL; }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, send_request, release_response};
}

static void unique_products_and_breaks(const br_detector *detector)
{
    char input[4096]; size_t at = (size_t)snprintf(input, sizeof(input), "dovico %s\ndovico %s\n", key_a, key_a);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\ndovico %s\ndovico %s\ndovico %s", key_b, key_c, key_b);
    const char *keys[] = {key_a, key_a, key_b, key_b, key_c, key_c};
    const char *users[] = {key_b, key_c, key_a, key_c, key_a, key_b};
    br_results results = test_scan(detector, NULL, false, input, at);
    CHECK(results.len == 6);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], users[i], false, NULL);
    CHECK(results.items[0].raw.data != results.items[1].raw.data && results.items[0].secret_parts != results.items[1].secret_parts);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, at); CHECK(results.len == 6);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], users[i], false, "net/http: nil Context");
    br_results_clear(&results);
    const row rows[] = {{key_a, key_b, 401, 0, NULL, "ignored"}, {key_a, key_c, 200, 0, NULL, "ignored"},
                        {key_b, key_a, 200, 0, NULL, ""}, {key_c, key_a, 401, 0, NULL, NULL}, {key_c, key_b, 200, 0, NULL, NULL}};
    expected_http expected = {.rows = rows, .count = 5, .agent = "TruffleHog dovico-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "dovico-offline"}; expected.original = &ctx;
    results = test_scan(detector, &ctx, true, input, at);
    CHECK(results.len == 5 && http.calls == 5 && http.releases == 5); /* Append verified finding, then break only its CURRENT key's user loop. */
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], rows[i].key, rows[i].user, rows[i].status == 200, NULL);
    br_results_clear(&results);
}

static void statuses_and_redaction(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "dovico %s\ndovico %s", key_a, key_b);
    const int statuses[] = {200, 401, 403, 201, 204, 299, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        const row rows[] = {{key_a, key_b, statuses[i], 0, NULL, "ignored"}, {key_b, key_a, statuses[i], 0, NULL, ""}};
        expected_http expected = {.rows = rows, .count = 2, .agent = "TruffleHog"};
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected status code %d", statuses[i]);
        for (size_t j = 0; j < results.len; ++j)
            check_result(&results.items[j], rows[j].key, rows[j].user, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : cause);
        br_results_clear(&results);
    }
    char short_key[35], long_key[36], echo[192]; memcpy(short_key, key_a, 33); strcpy(short_key + 33, "a");
    snprintf(long_key, sizeof(long_key), "%sb", short_key);
    snprintf(input, sizeof(input), "dovico %s\ndovico %s", short_key, long_key);
    snprintf(echo, sizeof(echo), "echo %s / %s", short_key, long_key);
    const row rows[] = {{short_key, long_key, 200, 1, echo, NULL}, {long_key, short_key, 200, 1, echo, NULL}};
    expected_http expected = {.rows = rows, .count = 2, .agent = "TruffleHog", .clobber_error = true};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], short_key, long_key, false, "echo [REDACTED] / [REDACTED]b");
    check_result(&results.items[1], long_key, short_key, false, "echo [REDACTED] / [REDACTED]");
    br_results_clear(&results); /* Key-first replacement is deliberately NOT longest-secret-first. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_causes(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "dovico %s\ndovico %s", key_a, key_b);
    test_http http = {.response = {.status = 401}}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
                             {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}, {.transport = &transport}};
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent", "out of memory constructing HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 2 && http.calls == (i == 4 ? 1u : 0u) && http.releases == (i ? 2u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key_a, key_b, false, causes[i]);
        check_result(&results.items[1], key_b, key_a, false, i == 4 ? NULL : causes[i]); /* One-shot shared OOM retains the first false result, then the next key continues to its 401. */
        br_results_clear(&results);
    }
    CHECK(cancellations == 2);
}

static void unbounded_header(const br_detector *detector)
{
    const size_t tail = 8192; char *large = malloc(33 + tail + 1), *input = malloc(tail + 256); CHECK(large && input);
    memcpy(large, key_a, 33); memset(large + 33, 'z', tail); large[33 + tail] = '\0';
    snprintf(input, tail + 256, "dovico %s\ndovico %s", large, key_b);
    const row rows[] = {{large, key_b, 401, 0, NULL, "ignored"}, {key_b, large, 200, 0, NULL, "ignored"}};
    expected_http expected = {.rows = rows, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    auth_size = header_size(large, key_b); size_t before = auth_allocations;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2 && auth_allocations == before + 2);
    check_result(&results.items[0], large, key_b, false, NULL); check_result(&results.items[1], key_b, large, true, NULL);
    br_results_clear(&results); free(input); free(large); auth_size = 0;
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
    char input[256]; snprintf(input, sizeof(input), "dovico %s\ndovico %s", key_a, key_b);
    br_slice data = text(input); br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    row rows[] = {{key_a, key_b, 200, 0, NULL, NULL}, {key_b, key_a, 200, 0, NULL, NULL}};
    expected_http expected = {.rows = rows, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Dovico result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = header_size(key_a, key_b); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error && fail_alloc_after == 1);
    fail_alloc_after = 0; CHECK(results.len == 3); /* No auth allocation occurs before constructor failure. */
    check_result(&results.items[1], key_a, key_b, false, "net/http: nil Context"); check_result(&results.items[2], key_b, key_a, false, "net/http: nil Context");
    while (results.len > 1) br_result_clear(&results.items[--results.len]);
    check_prior(&results, prior);
    fail_part_after = 4;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Dovico result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; fail_alloc_size = header_size(key_a, key_b); fail_alloc_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot allocate Dovico Authorization header") && !fail_alloc_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    rows[0].status = rows[1].status = 429; http.calls = http.releases = 0;
    fail_duplicate_text = "unexpected status code 429"; fail_duplicate_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set Dovico verification error") && !fail_duplicate_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL;
    fail_duplicate_text = "net/http: nil Context"; fail_duplicate_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set Dovico verification error") && !fail_duplicate_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = strlen(key_a) + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    rows[0].status = rows[1].status = 200; http.calls = http.releases = 0;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Dovico result") && http.calls == 1 && http.releases == 1); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results); /* Verified's break MUST NOT swallow a push +1. */
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key_a, key_b, true, NULL); check_result(&results.items[1], key_b, key_a, true, NULL);
    br_results_clear(&results);
}

int main(void)
{
    char prefix[33]; test_secret(prefix, 32, 0);
    snprintf(key_a, sizeof(key_a), "%s.aa", prefix); snprintf(key_b, sizeof(key_b), "%s.bb", prefix); snprintf(key_c, sizeof(key_c), "%s.cc", prefix);
    const br_detector *detector = descriptor();
    extraction(detector); unique_products_and_breaks(detector); statuses_and_redaction(detector); setup_causes(detector);
    unbounded_header(detector); fatal_resources(detector);
    return test_finish("Dovico");
}
