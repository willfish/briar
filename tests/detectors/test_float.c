/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[62], key2[62];
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Genuine capture/finding/shared-send resources, no auth/formatter seam. */
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

static void make_key(char out[62], size_t payload, size_t shift)
{
    memcpy(out, "0123456789abcdef", 16); test_secret(out + 16, payload, shift);
    out[19] = 'G'; out[24] = '+'; out[33] = '/'; out[16 + payload - 1] = 'z';
    out[16 + payload] = '='; out[17 + payload] = '\0';
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 59 && strlen(key2) == 60);
    CHECK(br_float_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Float detector output"));
    free(error); error = NULL;
    CHECK(br_float_init(NULL, NULL) == -1);
    CHECK(br_float_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_float_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 249 && detector->version == 0 && !strcmp(detector->name, "Float"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Float is a resource management software used for planning and scheduling projects. Float API keys can be used to access and modify project data and schedules."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "float"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 249, key, "key");
    CHECK(strlen(key) >= 59 && strlen(key) <= 60 && result->verified == verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK((size_t)json_object_get_string_len(part) == strlen(key));
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
    char input[256], changed[62];
    const struct { const char *format; bool matches; } cases[] = {
        {"float '%s'", true}, {"FLoAt=%s", true}, {"prefloatsuffix:%s", true},
        {"float\r\n%s", true}, {"float\r%s", true}, {"float\n%s", true},
        {"%s", false}, {"%s float", false}, {"flo at %s", false}, {"float%s", false},
        {"float x%s", false}, {"float _%s", false}, {"float %.58s", false},
        {"float %ssuffix", true}, {"float %s==", true}, {"float %s/", true},
        {"float \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1); extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    } /* Literal '=' is captured without any trailing boundary/EOF assertion. */
    for (size_t payload = 41; payload <= 44; ++payload) {
        make_key(changed, payload, 0); snprintf(input, sizeof(input), "float %s", changed);
        extraction_case(detector, input, strlen(input), payload == 42 || payload == 43 ? changed : NULL);
    }
    const char bad_hex[] = "Ag_+-";
    for (size_t i = 0; i < sizeof(bad_hex) - 1; ++i) {
        memcpy(changed, key1, strlen(key1) + 1); changed[5] = bad_hex[i];
        snprintf(input, sizeof(input), "FLOAT %s", changed); extraction_case(detector, input, strlen(input), NULL); /* Only keyword CI; leading 16 are LOWER hex. */
    }
    const char bad_payload[] = "_-!=.";
    for (size_t i = 0; i < sizeof(bad_payload) - 1; ++i) {
        memcpy(changed, key1, strlen(key1) + 1); changed[30] = bad_payload[i];
        snprintf(input, sizeof(input), "float %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memcpy(changed, key1, strlen(key1) + 1); changed[58] = '!'; snprintf(input, sizeof(input), "float %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memset(changed, 'a', 16); memset(changed + 16, 'A', 42); changed[58] = '='; changed[59] = '\0';
    snprintf(input, sizeof(input), "float %s", changed); extraction_case(detector, input, strlen(input), changed); /* No entropy/Base64/padding-bit validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "float", 5); size_t at = 5;
            for (size_t i = 0; i < gap; ++i) { if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = '.'; }
            memcpy(input + at, key1, strlen(key1)); at += strlen(key1); extraction_case(detector, input, at, gap == 40 ? key1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "float%c%s", 0, key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\nfloat %s\n\xff", key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "float %s %s", key1, key2); extraction_case(detector, input, (size_t)n, key1);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys; size_t count;
    const char *agent, *borrowed_auth, *current_key, *borrowed_provider_agent;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *key = expected->keys[http->calls - 1]; size_t len = strlen(key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.float.com/v3/people"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 249);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 7 + len && !memcmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!memcmp(request->headers[0].value + 7, key, len + 1));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog3 (example@example.com)"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    CHECK(!expected->borrowed_auth); expected->borrowed_auth = request->headers[0].value; expected->current_key = key; expected->borrowed_provider_agent = request->headers[1].value;
    /* This is the injected LOGICAL header list. No claim that curl serializes
     * duplicate User-Agent values like Go's actual net/http wire path. */
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_auth) {
        CHECK(strlen(expected->borrowed_auth) == 7 + strlen(expected->current_key) && !memcmp(expected->borrowed_auth, "Bearer ", 7));
        CHECK(!memcmp(expected->borrowed_auth + 7, expected->current_key, strlen(expected->current_key) + 1)); /* Full max-67 auth plus NUL survives THROUGH release. */
        CHECK(!strcmp(expected->borrowed_provider_agent, "TruffleHog3 (example@example.com)")); expected->borrowed_auth = expected->borrowed_provider_agent = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void occurrences_and_nil(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "float %s\nFLOAT %s\nfloat %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; expected_http expected = {.keys = keys, .count = 3, .agent = "TruffleHog float-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "float-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input)); CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 3 && http.calls == 3 && http.releases == 3 && !expected.borrowed_auth);
        CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], true);
        br_results_clear(&results);
    }
    http.calls = http.releases = 0;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && !http.calls && !http.releases); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results); /* All duplicates/scans are original occurrences, no unique/cache behavior. */
}

static void statuses_and_suppressed_send(const br_detector *detector)
{
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {
        {199, NULL, false}, {200, NULL, true}, {201, "ignored", true}, {204, "", true}, {299, "ignored", true},
        {300, NULL, false}, {401, "ignored", false}, {403, NULL, false}, {500, "", false},
    };
    const char *keys[] = {key2}; expected_http expected = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[96]; snprintf(input, sizeof(input), "float %s", key2);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_auth);
        check_result(&results.items[0], key2, cases[i].verified); br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, key2}};
    http.response = (br_http_response){.status = 200, .body = {body, sizeof(body)}, .body_error = ""};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key2, false); br_results_clear(&results);
    } /* Whole mixed send-domain errors suppress, no text-based skip or setter. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "float %s", key1); test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input)); CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true}; prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "float %s\nfloat %s", key1, key2); br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Float result") && !fail_part_after); check_prior(&results, prior); free(error); error = NULL;
    const char *keys[] = {key1, key2}; expected_http expected = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Float result") && !fail_part_after && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL; /* Late finding failure rolls back earlier verified addition, not caller. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = strlen(key2) + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after); check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 60; fail_alloc_after = 2; http.calls = http.releases = 0; /* First capture copy is 60 bytes; second finding's Raw is 60. */
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Float result") && !fail_alloc_after && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Constructor skips never append. */
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Float result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key1, true); check_result(&results.items[1], key2, true); br_results_clear(&results);
}

int main(void)
{
    make_key(key1, 42, 0); make_key(key2, 43, 7);
    const br_detector *detector = descriptor(); extraction(detector); occurrences_and_nil(detector); statuses_and_suppressed_send(detector); suppressed_setup(detector); resources_and_rollback(detector);
    return test_finish("Float leading-boundary captures + provider/common logical UAs");
}
