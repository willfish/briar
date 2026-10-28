/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_version_after, fail_version_string_after;
static size_t version_adds, version_strings;
static bool fail_agent_copy;
static const char *borrowed_auth, *borrowed_key;
static size_t borrowed_len;

typedef struct { const br_detector *detector; size_t len; char key1[105], key2[105]; const char *url, *version; } fullstory_fixture;

void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

struct json_object *json_object_new_string(const char *text)
{
    if (!strcmp(text, "1") || !strcmp(text, "2")) {
        ++version_strings;
        if (fail_version_string_after && --fail_version_string_after == 0) return NULL;
    }
    return json_object_new_string_len(text, (int)strlen(text));
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    if (!strcmp(name, "version")) { ++version_adds; if (fail_version_after && --fail_version_after == 0) return 1; }
    return json_object_object_add_ex(object, name, value, 0);
}

static void descriptors(fullstory_fixture fixtures[2])
{
    int (*const factories[])(const br_detector **, char **) = {br_fullstory_v1_init, br_fullstory_v2_init};
    const char *descriptions[] = {
        "Fullstory is a digital experience analytics platform that captures and analyzes customer interactions on websites and mobile apps. Fullstory API keys can be used to access and analyze this data.",
        "Fullstory is a digital experience analytics platform. Fullstory keys can be used to access user session data and analytics.",
    };
    CHECK(BR_ABI_REVISION == 1);
    for (size_t v = 0; v < 2; ++v) {
        const br_detector *detector = NULL, *again = NULL; char *error = NULL;
        CHECK(factories[v](NULL, &error) == -1 && error && !strcmp(error, "invalid Fullstory detector output")); free(error); error = NULL;
        CHECK(factories[v](NULL, NULL) == -1); CHECK(factories[v](&detector, &error) == 0 && detector && !error);
        CHECK(factories[v](&again, NULL) == 0 && again == detector); fixtures[v].detector = detector;
        CHECK(detector->type == 394 && detector->version == (int)v + 1 && !strcmp(detector->name, "Fullstory"));
        CHECK(detector->custom_name && !*detector->custom_name && !strcmp(detector->description, descriptions[v]));
        CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "fullstory")); /* v2 dispatch is NOT na1. */
        CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
        CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    }
    CHECK(fixtures[0].detector != fixtures[1].detector && fixtures[0].detector->state != fixtures[1].detector->state);
    fixtures[0].len = 88; fixtures[0].version = "1"; fixtures[0].url = "https://api.fullstory.com/operations/v1";
    fixtures[1].len = 104; fixtures[1].version = "2"; fixtures[1].url = "https://api.fullstory.com/v2/users";
    test_secret(fixtures[0].key1, 88, 0); test_secret(fixtures[0].key2, 88, 11);
    fixtures[0].key1[2] = 'Z'; fixtures[0].key1[20] = '-'; fixtures[0].key1[40] = '+'; fixtures[0].key1[50] = '/'; fixtures[0].key1[87] = 'K';
    fixtures[0].key2[2] = 'A'; fixtures[0].key2[20] = '/'; fixtures[0].key2[40] = '-'; fixtures[0].key2[50] = '+'; fixtures[0].key2[87] = 'Q';
    memcpy(fixtures[1].key1, "na1.", 4); memcpy(fixtures[1].key2, "na1.", 4); test_secret(fixtures[1].key1 + 4, 100, 7); test_secret(fixtures[1].key2 + 4, 100, 15);
    fixtures[1].key1[6] = 'Z'; fixtures[1].key1[24] = '+'; fixtures[1].key1[44] = '/'; fixtures[1].key1[103] = 'K';
    fixtures[1].key2[6] = 'A'; fixtures[1].key2[24] = '/'; fixtures[1].key2[44] = '+'; fixtures[1].key2[103] = 'Q';
}

static void check_result(const fullstory_fixture *fixture, const br_result *result, const char *key, bool verified)
{
    CHECK(result->detector_type == 394 && !result->detector_name && result->raw.len == fixture->len && !memcmp(result->raw.data, key, fixture->len));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1); br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)fixture->len && !memcmp(json_object_get_string(part), key, fixture->len + 1));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1); br_json *version = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, "version", &version) && json_object_is_type(version, json_type_string));
    CHECK(json_object_get_string_len(version) == 1 && !strcmp(json_object_get_string(version), fixture->version));
}

static void extraction_case(const fullstory_fixture *fixture, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(fixture->detector, &ctx, false, input, len); CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(fixture, &results.items[0], expected, false);
    br_results_clear(&results);
}

static void v1_extraction(const fullstory_fixture *fixture)
{
    char input[512], changed[90];
    const struct { const char *format; bool matches; } cases[] = {
        {"fullstory '%s'", true}, {"FULLstory=%s", true}, {"prefullstory suffix:%s", true}, {"fullstory\r\n%s", true},
        {"%s", false}, {"full story %s", false}, {"fullstory%s", false}, {"fullstory x%s", false}, {"fullstory _%s", false},
        {"fullstory %s_", false}, {"fullstory %s9", false}, {"fullstory %.87s", false}, {"fullstory %s=", true}, {"fullstory +%s", true},
        {"fullstory \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) { snprintf(input, sizeof(input), cases[i].format, fixture->key1); extraction_case(fixture, input, strlen(input), cases[i].matches ? fixture->key1 : NULL); }
    const char invalid[] = "_=.[:";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { memcpy(changed, fixture->key1, 89); changed[44] = invalid[i]; snprintf(input, sizeof(input), "fullstory %s", changed); extraction_case(fixture, input, strlen(input), NULL); }
    memcpy(changed, fixture->key1, 89); changed[0] = '-'; snprintf(input, sizeof(input), "fullstory %s", changed); extraction_case(fixture, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "fullstory X%s", changed); extraction_case(fixture, input, strlen(input), changed); /* Literal hyphen capture starts at WORD->nonword boundary. */
    memcpy(changed, fixture->key1, 89); changed[87] = '+'; snprintf(input, sizeof(input), "fullstory %s", changed); extraction_case(fixture, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "fullstory %sX", changed); extraction_case(fixture, input, strlen(input), changed); /* Word-boundary, not full-token alphabet assertion. */
    memset(changed, 'A', 88); changed[88] = '\0'; snprintf(input, sizeof(input), "fullstory %s", changed); extraction_case(fixture, input, strlen(input), changed); /* No entropy/Base64 validation. */
    for (size_t gap = 40; gap <= 41; ++gap) for (int unicode = 0; unicode < 2; ++unicode) {
        memcpy(input, "fullstory", 9); size_t at = 9;
        for (size_t i = 0; i < gap; ++i) { if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = ':'; }
        memcpy(input + at, fixture->key1, 88); at += 88; extraction_case(fixture, input, at, gap == 40 ? fixture->key1 : NULL);
    }
    int n = snprintf(input, sizeof(input), "\xff\nfullstory%c%s", 0, fixture->key1); extraction_case(fixture, input, (size_t)n, fixture->key1); extraction_case(fixture, NULL, 0, NULL);
}

static void v2_extraction(const fullstory_fixture *fixture)
{
    char input[512], changed[105];
    const struct { const char *format; bool matches; } cases[] = {
        {"%s", true}, {"fullstory '%s'", true}, {"UNRELATED %s", true}, {"-%s", true}, {"%s=", true},
        {"x%s", false}, {"_%s", false}, {"%s_", false}, {"%s9", false}, {"%.103s", false}, {"\xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) { snprintf(input, sizeof(input), cases[i].format, fixture->key1); extraction_case(fixture, input, strlen(input), cases[i].matches ? fixture->key1 : NULL); }
    const char *bad_prefixes[] = {"NA1.", "Na1.", "nA1.", "na2.", "na1X"};
    for (size_t i = 0; i < sizeof(bad_prefixes) / sizeof(bad_prefixes[0]); ++i) { memcpy(changed, fixture->key1, 105); memcpy(changed, bad_prefixes[i], 4); extraction_case(fixture, changed, 104, NULL); }
    const char invalid[] = "_-=.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { memcpy(changed, fixture->key1, 105); changed[54] = invalid[i]; extraction_case(fixture, changed, 104, NULL); }
    memcpy(changed, fixture->key1, 105); changed[103] = '+'; extraction_case(fixture, changed, 104, NULL);
    snprintf(input, sizeof(input), "%sX", changed); extraction_case(fixture, input, strlen(input), changed); /* Nonword-to-word end boundary accepts exact 104-byte capture, not whole-token validation. */
    memcpy(changed, "na1.", 4); memset(changed + 4, 'A', 100); changed[104] = '\0'; extraction_case(fixture, changed, 104, changed);
    memset(input, ':', 200); memcpy(input + 200, fixture->key1, 105); extraction_case(fixture, input, 304, fixture->key1); /* DIRECT, no prefix/proximity dependency. */
    int n = snprintf(input, sizeof(input), "\xff%c%s", 0, fixture->key1); extraction_case(fixture, input, (size_t)n, fixture->key1); extraction_case(fixture, NULL, 0, NULL);
}

typedef struct { const fullstory_fixture *fixture; const char *const *keys; size_t nkeys; const char *agent; const br_scan_ctx *original; } expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; const fullstory_fixture *fixture = expected->fixture; CHECK(ctx && ctx == expected->original && http->calls <= expected->nkeys);
    const char *key = expected->keys[http->calls - 1]; CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, fixture->url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 394);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization") && strlen(request->headers[0].value) == 6 + fixture->len);
    CHECK(!memcmp(request->headers[0].value, "Basic ", 6) && !memcmp(request->headers[0].value + 6, key, fixture->len + 1)); /* Literal TOKEN, not true Basic/TOKEN: or any codec. */
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent)); /* No Type/Accept. */
    CHECK(!borrowed_auth && !borrowed_key); borrowed_auth = request->headers[0].value; borrowed_key = key; borrowed_len = fixture->len;
}

static void release_response(void *user, br_http_response *response)
{
    if (borrowed_auth) {
        CHECK(strlen(borrowed_auth) == 6 + borrowed_len && !memcmp(borrowed_auth, "Basic ", 6));
        CHECK(!memcmp(borrowed_auth + 6, borrowed_key, borrowed_len + 1) && borrowed_auth[6 + borrowed_len] == '\0');
    } else CHECK(!borrowed_key && !((test_http *)user)->calls); /* Shared setup rejected before callback. */
    borrowed_auth = borrowed_key = NULL; test_http_release(user, response); /* Exact bounded auth stays valid THROUGH release. */
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void occurrences(const fullstory_fixture *fixture)
{
    char input[512]; int n = snprintf(input, sizeof(input), "fullstory %s\nfullstory %s\nfullstory %s", fixture->key1, fixture->key2, fixture->key1);
    const char *keys[] = {fixture->key1, fixture->key2, fixture->key1}; expected_http expected = {.fixture = fixture, .keys = keys, .nkeys = 3, .agent = "TruffleHog fullstory-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "fullstory-offline"}; expected.original = &ctx;
    size_t before = version_adds; br_results results = test_scan(fixture->detector, &ctx, false, input, (size_t)n); CHECK(results.len == 3 && !http.calls && !http.releases && version_adds == before + 3);
    for (size_t i = 0; i < results.len; ++i) check_result(fixture, &results.items[i], keys[i], false);
    CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts && results.items[0].extra_data != results.items[2].extra_data); br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; before = version_adds; results = test_scan(fixture->detector, &ctx, true, input, (size_t)n);
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3 && version_adds == before + 3);
        for (size_t i = 0; i < results.len; ++i) check_result(fixture, &results.items[i], keys[i], true);
        br_results_clear(&results);
    } /* Original occurrences/duplicates, no set, break, fold or persistent cache. */
    http.calls = http.releases = 0; before = version_adds; results = test_scan(fixture->detector, NULL, true, input, (size_t)n);
    CHECK(!results.len && !http.calls && !http.releases && version_adds == before + 3); br_results_clear(&results); /* All owned version resources BEFORE constructor skip, not false-kept. */
}

static void statuses_and_suppressed_send(const fullstory_fixture *fixture)
{
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {{199, NULL, false}, {200, NULL, true}, {201, "ignored", true}, {204, "", true}, {299, "ignored", true}, {300, NULL, false}, {401, "ignored", false}, {403, NULL, false}, {500, "", false}};
    const char *keys[] = {fixture->key1}; expected_http expected = {.fixture = fixture, .keys = keys, .nkeys = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[128]; snprintf(input, sizeof(input), "fullstory %s", fixture->key1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        br_results results = test_scan(fixture->detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(fixture, &results.items[0], fixture->key1, cases[i].verified); br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "cannot create Fullstory version metadata"}, {-1, NULL}, {1, fixture->key1}};
    http.response = (br_http_response){.status = 200, .body = {body, sizeof(body)}, .body_error = ""};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(fixture->detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(fixture, &results.items[0], fixture->key1, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const fullstory_fixture *fixture)
{
    char input[128]; snprintf(input, sizeof(input), "fullstory %s", fixture->key1); test_http http = {0}; br_transport transport = transport_for(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(fixture->detector, &contexts[i], true, input, strlen(input)); CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy && !borrowed_auth && !borrowed_key);
        check_result(fixture, &results.items[0], fixture->key1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true}; prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); prior.extra_data = json_object_new_object(); CHECK(prior.extra_data);
    CHECK(json_object_object_add(prior.extra_data, "sentinel", json_object_new_string("caller")) == 0); br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
    CHECK(results->items[0].extra_data == prior.extra_data && json_object_object_length(prior.extra_data) == 1);
    br_json *sentinel = NULL; CHECK(json_object_object_get_ex(prior.extra_data, "sentinel", &sentinel) && !strcmp(json_object_get_string(sentinel), "caller"));
}

static void resources_and_rollback(const fullstory_fixture *fixture)
{
    char input[256]; snprintf(input, sizeof(input), "fullstory %s\nfullstory %s", fixture->key1, fixture->key2); br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL; size_t before = version_adds;
    fail_part_after = 1;
    CHECK(fixture->detector->scan(fixture->detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Fullstory result") && !fail_part_after && version_adds == before); check_prior(&results, prior); free(error); error = NULL;
    fail_version_after = 1;
    CHECK(fixture->detector->scan(fixture->detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Fullstory version metadata") && !fail_version_after); check_prior(&results, prior); free(error); error = NULL; /* OWN positive metadata add failure BEFORE nil-context skip. */
    before = version_adds; size_t strings_before = version_strings; fail_version_string_after = 1;
    CHECK(fixture->detector->scan(fixture->detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Fullstory version metadata") && !fail_version_string_after && version_adds == before && version_strings == strings_before + 1); check_prior(&results, prior); free(error); error = NULL;
    const char *keys[] = {fixture->key1, fixture->key2}; expected_http expected = {.fixture = fixture, .keys = keys, .nkeys = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 2;
    CHECK(fixture->detector->scan(fixture->detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Fullstory result") && !fail_part_after && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL;
    fail_version_after = 2; http.calls = http.releases = 0;
    CHECK(fixture->detector->scan(fixture->detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Fullstory version metadata") && !fail_version_after && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL; /* Rollback earlier VERIFIED invocation finding, retain caller raw/error/metadata pointers. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; before = version_adds;
    CHECK(fixture->detector->scan(fixture->detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after && version_adds == before); check_prior(&results, prior); /* Positive iterator error normalizes fatal. */
    fail_alloc_size = fixture->len + 1; fail_alloc_after = 1;
    CHECK(fixture->detector->scan(fixture->detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after); check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0; before = version_adds;
    CHECK(fixture->detector->scan(fixture->detector, NULL, true, data, &results, &error) == 0 && !error && version_adds == before + 2); check_prior(&results, prior);
    CHECK(fixture->detector->scan(fixture->detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Fullstory result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(fixture->detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(fixture, &results.items[i], keys[i], true);
    br_results_clear(&results);
}

int main(void)
{
    fullstory_fixture fixtures[2] = {0}; descriptors(fixtures); v1_extraction(&fixtures[0]); v2_extraction(&fixtures[1]);
    for (size_t v = 0; v < 2; ++v) { occurrences(&fixtures[v]); statuses_and_suppressed_send(&fixtures[v]); suppressed_setup(&fixtures[v]); resources_and_rollback(&fixtures[v]); }
    CHECK(!borrowed_auth && !borrowed_key); return test_finish("Fullstory v1/v2 exact captures + owned string versions + literal Basic");
}
