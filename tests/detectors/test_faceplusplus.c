/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[33], key2[33];
static const char base_url[] = "https://api-us.faceplusplus.com/facepp/v3/faceset/getfacesets?api_key=";
static size_t fail_alloc_size, fail_alloc_after, fail_key_after, fail_secret_after;
static bool fail_agent_copy;

/* Genuine captures/parts/RawV2/shared-send resources, no URL/formatter seam. */
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
    if (fail_key_after && !strcmp(name, "key") && --fail_key_after == 0) return 1;
    if (fail_secret_after && !strcmp(name, "secret") && --fail_secret_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 32 && strlen(key2) == 32 && strlen(base_url) == 70);
    CHECK(br_faceplusplus_init(NULL, &error) == -1 && error && !strcmp(error, "invalid FacePlusPlus detector output"));
    free(error); error = NULL;
    CHECK(br_faceplusplus_init(NULL, NULL) == -1);
    CHECK(br_faceplusplus_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_faceplusplus_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 416 && detector->version == 0 && !strcmp(detector->name, "FacePlusPlus"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Face++ is a facial recognition service that provides APIs for detecting and analyzing faces. Face++ API keys and secrets can be used to access and manipulate these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "faceplusplus"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector; /* Registry/default/type-name/CLI integration is parent-owned. */
}

static void check_result(const br_result *result, const char *key, const char *secret, bool verified)
{
    CHECK(result->detector_type == 416 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, key, 32));
    CHECK(result->raw_v2.len == 64 && !memcmp(result->raw_v2.data, key, 32) && !memcmp(result->raw_v2.data + 32, secret, 32)); /* Literal KEYSECRET, no colon/NUL. */
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), key, 32));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), secret, 32));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, expected, false); /* A single occurrence MUST produce its self-pair. */
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"faceplusplus '%s'", true}, {"FACEpLUSPLUS=%s", true}, {"prefaceplusplussuffix:%s", true},
        {"faceplusplus\r\n%s", true}, {"faceplusplus\r%s", true}, {"faceplusplus\n%s", true},
        {"%s", false}, {"%s faceplusplus", false}, {"face plus plus %s", false}, {"faceplusplus%s", false},
        {"faceplusplus x%s", false}, {"faceplusplus _%s", false}, {"faceplusplus %s_", false}, {"faceplusplus %s9", false},
        {"faceplusplus %.31s", false}, {"faceplusplus \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char invalid[] = "+/=.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "faceplusplus %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'a', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "faceplusplus %s", changed); extraction_case(detector, input, strlen(input), changed); /* No local validation/filter. */
    memcpy(changed, key1, sizeof(changed)); changed[0] = '-';
    snprintf(input, sizeof(input), "faceplusplus %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "faceplusplus X%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key1, sizeof(changed)); changed[31] = '-';
    snprintf(input, sizeof(input), "faceplusplus %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "faceplusplus %sX", changed); extraction_case(detector, input, strlen(input), changed); /* Nonword -> external word boundary, no full-token heuristic. */
    memcpy(changed, key1, sizeof(changed)); changed[0] = changed[31] = '_';
    snprintf(input, sizeof(input), "faceplusplus %s", changed); extraction_case(detector, input, strlen(input), changed); /* Underscore is a word byte, unlike hyphen. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "faceplusplus", 12); size_t at = 12;
            for (size_t i = 0; i < gap; ++i) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key1, 32); at += 32;
            extraction_case(detector, input, at, gap == 40 ? key1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "faceplusplus%c%s", 0, key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\nfaceplusplus %s\n\xff", key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "faceplusplus %s %s", key1, key2); extraction_case(detector, input, (size_t)n, key1); /* Whole-match non-overlap. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct {
    const char *const *credentials; size_t count;
    const char *agent, *borrowed_url, *current_key, *current_secret;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count * expected->count);
    size_t pair = http->calls - 1;
    const char *key = expected->credentials[pair / expected->count], *secret = expected->credentials[pair % expected->count];
    CHECK(!strcmp(request->method, "POST") && strlen(request->url) == 146 && !memcmp(request->url, base_url, 70));
    CHECK(!memcmp(request->url + 70, key, 32) && !memcmp(request->url + 102, "&api_secret=", 12) && !memcmp(request->url + 114, secret, 33));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 416);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len); /* BODYLESS POST. */
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent));
    CHECK(!expected->borrowed_url); expected->borrowed_url = request->url; expected->current_key = key; expected->current_secret = secret;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(strlen(expected->borrowed_url) == 146 && !memcmp(expected->borrowed_url, base_url, 70));
        CHECK(!memcmp(expected->borrowed_url + 70, expected->current_key, 32) && !memcmp(expected->borrowed_url + 102, "&api_secret=", 12));
        CHECK(!memcmp(expected->borrowed_url + 114, expected->current_secret, 33)); /* Complete 146-byte URL plus NUL survives THROUGH release. */
        expected->borrowed_url = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void products_and_nil_context(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "faceplusplus %s\nFACEPLUSPLUS %s\nfaceplusplus %s", key1, key2, key1);
    const char *credentials[] = {key1, key2, key1}; expected_http expected = {.credentials = credentials, .count = 3, .agent = "TruffleHog facepp-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "facepp-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 9 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], credentials[i / 3], credentials[i % 3], false);
    CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].raw_v2.data != results.items[2].raw_v2.data && results.items[0].secret_parts != results.items[2].secret_parts);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 9 && http.calls == 9 && http.releases == 9 && !expected.borrowed_url);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], credentials[i / 3], credentials[i % 3], true);
        br_results_clear(&results);
    } /* No unique sets, no equal-value skip, no verified-break or persistent cache. */
    http.calls = http.releases = 0;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && !http.calls && !http.releases); br_results_clear(&results);
    char trailing[33]; memcpy(trailing, key1, sizeof(trailing)); trailing[31] = '-';
    snprintf(input, sizeof(input), "faceplusplus %sX", trailing); const char *one[] = {trailing}; expected.credentials = one; expected.count = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], trailing, trailing, true); br_results_clear(&results);

    char far[2304]; size_t at = (size_t)snprintf(far, sizeof(far), "faceplusplus %s\n", key1);
    memset(far + at, '.', 2048); at += 2048; at += (size_t)snprintf(far + at, sizeof(far) - at, "\nfaceplusplus %s", key2);
    const char *separated[] = {key1, key2}; expected.credentials = separated; expected.count = 2; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, far, at);
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4); /* Span 1024 MUST NOT become a detector-local distance cap. */
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], separated[i / 2], separated[i % 2], true);
    br_results_clear(&results);
}

static void statuses_and_suppressed_send(const br_detector *detector)
{
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {
        {199, NULL, false}, {200, NULL, true}, {201, "ignored", true}, {204, "", true}, {299, "ignored", true},
        {300, NULL, false}, {401, "ignored", false}, {403, NULL, false}, {500, "", false},
    };
    const char *credentials[] = {key1}; expected_http expected = {.credentials = credentials, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    char input[64]; snprintf(input, sizeof(input), "faceplusplus %s", key1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_url);
        check_result(&results.items[0], key1, key1, cases[i].verified); br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, key1}};
    http.response = (br_http_response){.status = 200, .body = {body, sizeof(body)}, .body_error = "ignored"};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], key1, key1, false); br_results_clear(&results);
    } /* Every mixed shared setup/allocation/Do cause suppresses, never classifies as skip. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "faceplusplus %s", key1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
                             {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; if (i == 4) fail_agent_copy = true;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        check_result(&results.items[0], key1, key1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.raw_v2.data = malloc(6); CHECK(prior.raw_v2.data); memcpy(prior.raw_v2.data, "prior2", 6); prior.raw_v2.len = 6;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].raw_v2.data == prior.raw_v2.data && results->items[0].raw_v2.len == 6 && !memcmp(prior.raw_v2.data, "prior2", 6));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "faceplusplus %s\nfaceplusplus %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)}; br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    fail_key_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FacePlusPlus result") && !fail_key_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_secret_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FacePlusPlus result") && !fail_secret_after);
    check_prior(&results, prior); free(error); error = NULL; /* BOTH parts/RawV2 must succeed before constructor skip. */
    const char *credentials[] = {key1, key2}; expected_http expected = {.credentials = credentials, .count = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_secret_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create FacePlusPlus result") && !fail_secret_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL; /* Late secret-part failure clears new Raw/parts/V2 and rolls back earlier verified pair. */
    fail_alloc_size = 64; fail_alloc_after = 4; http.calls = http.releases = 0; /* Two capture arrays, first RawV2, then failing second RawV2. */
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create FacePlusPlus result") && !fail_alloc_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 33; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* All N² constructor skips, no pushes. */
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FacePlusPlus result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], credentials[i / 2], credentials[i % 2], true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 32, 0); test_secret(key2, 32, 7);
    key1[5] = 'A'; key1[9] = '-'; key1[19] = '_'; key1[31] = 'Z'; key2[5] = 'G'; key2[9] = '_'; key2[19] = '-'; key2[31] = 'K';
    const br_detector *detector = descriptor();
    extraction(detector); products_and_nil_context(detector); statuses_and_suppressed_send(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("FacePlusPlus original occurrence N-squared products");
}
