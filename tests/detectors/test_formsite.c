/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[33], key2[33];
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;
static const char *borrowed_url, *borrowed_auth;
static char saved_url[48], saved_auth[40];

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

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 32 && strlen(key2) == 32);
    CHECK(br_formsite_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Formsite detector output")); free(error); error = NULL;
    CHECK(br_formsite_init(NULL, NULL) == -1);
    CHECK(br_formsite_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_formsite_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 839 && detector->version == 0 && !strcmp(detector->name, "Formsite"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Formsite is an online form builder service. Formsite API keys can be used to access and manage forms and data submissions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "formsite"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 839, key, "key"); /* Exactly ONE part/NO RawV2: required server and user stay hidden, including verified findings. */
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 32);
}

static size_t append_record(char *input, size_t at, const char *value, size_t gap)
{
    memset(input + at, '.', gap); at += gap;
    return at + (size_t)sprintf(input + at, "FORMsite %s", value); /* Synthetic fixture only; production uses direct bounded assembly. */
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *key, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len); CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], key, false);
    br_results_clear(&results);
}

static void component_case(const br_detector *detector, const char *key, const char *server, const char *user, size_t count)
{
    char input[512]; size_t at = append_record(input, 0, key, 0); at = append_record(input, at, server, 80); at = append_record(input, at, user, 80);
    extraction_case(detector, input, at, key, count);
}

static void extraction(const br_detector *detector)
{
    component_case(detector, key1, "fs1", "AbC123", 1);
    const struct { const char *server; size_t count; } servers[] = {{"fs0", 1}, {"fs12", 1}, {"fs999", 1}, {"fs0001", 2}, {"FS1", 0}, {"Fs12", 0}, {"fS1234", 0}, {"fs", 0}, {"fs12345", 0}, {"fs1_", 0}, {"xfs1", 0}, {"fs1x", 0}, {"fs-1", 0}, {"fs\xd9\xa1", 0}};
    for (size_t i = 0; i < sizeof(servers) / sizeof(servers[0]); ++i) component_case(detector, key1, servers[i].server, "AbC123", servers[i].count);
    const struct { const char *user; size_t count; } users[] = {{"ABC123", 1}, {"abcdef", 1}, {"123456", 1}, {"AbC12", 0}, {"AbC1234", 0}, {"AbC12_", 0}, {"AbC12-", 0}, {"_AbC123", 0}, {"AbC123_", 0}, {"fs1234", 2}};
    for (size_t i = 0; i < sizeof(users) / sizeof(users[0]); ++i) component_case(detector, key1, "fs1", users[i].user, users[i].count);
    char changed[35]; memset(changed, 'A', 32); changed[32] = '\0'; component_case(detector, changed, "fs1", "AbC123", 1); /* No entropy/hex-only filter. */
    memcpy(changed, key1, 33); changed[16] = '_'; component_case(detector, changed, "fs1", "AbC123", 0); changed[16] = '-'; component_case(detector, changed, "fs1", "AbC123", 0);
    memcpy(changed, key1, 33); changed[31] = '\0'; component_case(detector, changed, "fs1", "AbC123", 0);
    memcpy(changed, key1, 32); changed[32] = '9'; changed[33] = '\0'; component_case(detector, changed, "fs1", "AbC123", 0);
    changed[0] = '_'; memcpy(changed + 1, key1, 33); component_case(detector, changed, "fs1", "AbC123", 0);
    char input[512];
    const char *single[] = {key1, "fs1", "AbC123"};
    for (size_t i = 0; i < 3; ++i) { size_t at = append_record(input, 0, single[i], 0); extraction_case(detector, input, at, key1, 0); }
    size_t at = append_record(input, 0, key1, 0); at = append_record(input, at, "fs1", 80); extraction_case(detector, input, at, key1, 0); /* User required. */
    at = append_record(input, 0, key1, 0); at = append_record(input, at, "AbC123", 80); extraction_case(detector, input, at, key1, 0); /* Server required. */
    at = append_record(input, 0, key1, 0); at = append_record(input, at, "fs1234", 80); extraction_case(detector, input, at, key1, 1); /* SERVER6 independently supplies USER6, no inference-based removal. */
    for (size_t gap = 40; gap <= 41; ++gap) for (int unicode = 0; unicode < 2; ++unicode) {
        memcpy(input, "formsite", 8); at = 8;
        for (size_t i = 0; i < gap; ++i) { if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = '.'; }
        memcpy(input + at, key1, 32); at += 32; at = append_record(input, at, "fs1", 80); at = append_record(input, at, "AbC123", 80);
        extraction_case(detector, input, at, key1, gap == 40 ? 1 : 0);
    }
    at = (size_t)snprintf(input, sizeof(input), "\xff\nformsite%c%s", 0, key1); at = append_record(input, at, "fs1", 80); at = append_record(input, at, "AbC123", 80); extraction_case(detector, input, at, key1, 1);
    at = (size_t)snprintf(input, sizeof(input), "form site %s", key1); at = append_record(input, at, "fs1", 80); at = append_record(input, at, "AbC123", 80); extraction_case(detector, input, at, key1, 0);
    extraction_case(detector, NULL, 0, NULL, 0);
}

typedef struct { const char *const *keys, *const *servers, *const *users; size_t nkeys, nservers, nusers; const char *agent; const br_scan_ctx *original; } expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->nkeys * expected->nservers * expected->nusers);
    size_t product = http->calls - 1; const char *key = expected->keys[product / (expected->nservers * expected->nusers)];
    const char *server = expected->servers[(product / expected->nusers) % expected->nservers], *user = expected->users[product % expected->nusers];
    char url[48]; int len = snprintf(url, sizeof(url), "https://%s.formsite.com/api/v2/%s/forms", server, user); CHECK(len == 41 + (int)strlen(server));
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && strlen(request->url) == (size_t)len);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 839); /* Not invented PUBLIC semantics. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization") && strlen(request->headers[0].value) == 39);
    CHECK(!memcmp(request->headers[0].value, "Bearer ", 7) && !memcmp(request->headers[0].value + 7, key, 33));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent)); /* No Type/Accept. */
    CHECK(!borrowed_url && !borrowed_auth); borrowed_url = request->url; borrowed_auth = request->headers[0].value;
    memcpy(saved_url, url, (size_t)len + 1); memcpy(saved_auth, request->headers[0].value, 40);
}

static void release_response(void *user, br_http_response *response)
{
    if (borrowed_url) {
        CHECK(borrowed_auth && !strcmp(borrowed_url, saved_url) && !memcmp(borrowed_url, saved_url, strlen(saved_url) + 1));
        CHECK(!memcmp(borrowed_auth, saved_auth, 40) && borrowed_auth[39] == '\0'); borrowed_url = borrowed_auth = NULL;
    } else CHECK(!borrowed_auth && !((test_http *)user)->calls); /* Shared setup failed before callback. */
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void independent_products(const br_detector *detector)
{
    char input[8192]; const char *keys[] = {key1, key2, key1}, *servers[] = {"fs1", "fs1234", "fs1"}, *users[] = {"fs1234", "MiX123", "MiX123"};
    expected_http expected = {.keys = keys, .servers = servers, .users = users, .nkeys = 3, .nservers = 3, .nusers = 3, .agent = "TruffleHog formsite-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "formsite-offline"}; expected.original = &ctx;
    size_t at = 0; const char *records[] = {key1, key2, key1, "fs1", "fs1234", "fs1", "MiX123", "MiX123"};
    for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); ++i) at = append_record(input, at, records[i], i ? 80 : 0);
    br_results results = test_scan(detector, &ctx, false, input, at); CHECK(results.len == 27 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 9], false);
    CHECK(results.items[0].raw.data != results.items[1].raw.data && results.items[0].secret_parts != results.items[1].secret_parts); br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 27 && http.calls == 27 && http.releases == 27);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 9], true);
        br_results_clear(&results);
    } /* Independent original products/duplicates in ALL THREE roles, key/server/user order, no verified break or exclusion of SERVER6 from users. */
    http.calls = http.releases = 0; results = test_scan(detector, NULL, true, input, at); CHECK(!results.len && !http.calls && !http.releases); br_results_clear(&results);
    const char *one_key[] = {key1}, *one_server[] = {"fs1"}, *one_user[] = {"MiX123"}; expected.keys = one_key; expected.servers = one_server; expected.users = one_user; expected.nkeys = expected.nservers = expected.nusers = 1;
    at = (size_t)snprintf(input, sizeof(input), "FoRmSiTe %s fs1 MiX123", key1); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, true); br_results_clear(&results); /* ONE cue, three independent proximity/backtracking searches. */
    const char *overlap[] = {"fs1234"}; expected.servers = expected.users = overlap;
    at = (size_t)snprintf(input, sizeof(input), "formsite %s fs1234 MiX123", key1); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, true); br_results_clear(&results); /* USER6 is the SERVER6 at distance34, NOT the later unprefixed user at distance41. */
    const char *zero_server[] = {"fs0001"}, *zero_users[] = {"fs0001", "AbC123"}; expected.servers = zero_server; expected.users = zero_users; expected.nusers = 2;
    at = append_record(input, 0, key1, 0); at = append_record(input, at, "fs0001", 80); at = append_record(input, at, "AbC123", 80); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], key1, true);
    br_results_clear(&results); /* Complete MAX47 URL+NUL48, original case/user and leading server zeros. */
    expected.servers = one_server; expected.users = one_user; expected.nusers = 1;
    at = append_record(input, 0, key1, 0); at = append_record(input, at, "fs1", 2048); at = append_record(input, at, "MiX123", 2048); http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, true); br_results_clear(&results); /* Span1024 is engine hint, NOT local cap. */
}

static void statuses_and_suppressed_send(const br_detector *detector)
{
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {{199, NULL, false}, {200, NULL, true}, {201, "ignored", true}, {204, "", true}, {299, "ignored", true}, {300, NULL, false}, {401, "ignored", false}, {403, NULL, false}, {500, "", false}};
    const char *keys[] = {key1}, *servers[] = {"fs1"}, *users[] = {"AbC123"}; expected_http expected = {.keys = keys, .servers = servers, .users = users, .nkeys = 1, .nservers = 1, .nusers = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[128]; snprintf(input, sizeof(input), "formsite %s fs1 AbC123", key1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, cases[i].verified); br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, key1}};
    http.response = (br_http_response){.status = 200, .body = {body, sizeof(body)}, .body_error = ""};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "formsite %s fs1 AbC123", key1); test_http http = {0}; br_transport transport = transport_for(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input)); CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy && !borrowed_url && !borrowed_auth);
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
    char input[512]; size_t at = append_record(input, 0, key1, 0); at = append_record(input, at, key2, 80); at = append_record(input, at, "fs1", 80); at = append_record(input, at, "AbC123", 80); br_slice data = {(const unsigned char *)input, at};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Formsite result") && !fail_part_after); check_prior(&results, prior); free(error); error = NULL; /* Finding BEFORE complete URL preparation/constructor skip. */
    const char *keys[] = {key1, key2}, *servers[] = {"fs1"}, *users[] = {"AbC123"}; expected_http expected = {.keys = keys, .servers = servers, .users = users, .nkeys = 2, .nservers = 1, .nusers = 1, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Formsite result") && !fail_part_after && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL; /* Late own +1 failure rolls back earlier verified product, preserves caller pointers. */
    for (size_t collection = 1; collection <= 3; ++collection) {
        fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = collection;
        CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    } /* Actual positive iterator failures for KEY, then SERVER, then USER collections, each before constructor skip. */
    fail_alloc_size = 7; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after); check_prior(&results, prior); free(error); error = NULL; /* USER6 copy fails after complete key/server sets. */
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior);
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Formsite result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 32, 0); test_secret(key2, 32, 11); key1[3] = 'Z'; key1[31] = 'K'; key2[3] = 'A'; key2[31] = 'Q';
    const br_detector *detector = descriptor(); extraction(detector); independent_products(detector); statuses_and_suppressed_send(detector); suppressed_setup(detector); resources_and_rollback(detector);
    CHECK(!borrowed_url && !borrowed_auth); return test_finish("Formsite independent occurrence triples + overlapping roles + hidden fields");
}
