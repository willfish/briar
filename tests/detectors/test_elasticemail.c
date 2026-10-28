/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[97], key2[97];
static const char base_url[] = "https://api.elasticemail.com/v2/account/profileoverview?apikey=";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, fail_duplicate_after;
static const char *fail_duplicate_text;
static bool fail_agent_copy;

/* Genuine capture/finding/JSON/shared-send resources, no URL/formatter seam. */
void *malloc(size_t size)
{
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
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 96 && strlen(key2) == 96 && strlen(base_url) == 63);
    CHECK(br_elasticemail_init(NULL, &error) == -1 && error && !strcmp(error, "invalid ElasticEmail detector output"));
    free(error); error = NULL;
    CHECK(br_elasticemail_init(NULL, NULL) == -1);
    CHECK(br_elasticemail_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_elasticemail_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 112 && detector->version == 0 && !strcmp(detector->name, "ElasticEmail"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "ElasticEmail is an email marketing service. ElasticEmail API keys can be used to send emails, manage contacts, and access other features of the service."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "elasticemail")); /* DISPATCH, not extraction prefix. */
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 112, key, "key");
    CHECK(result->raw.len == 96 && result->verified == verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 96);
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
    char input[512], changed[97];
    const struct { const char *format; bool matches; } cases[] = {
        {"elastic '%s'", true}, {"ELasTIC=%s", true}, {"preelasticsuffix:%s", true}, {"elasticemail %s", true},
        {"elastic\r\n%s", true}, {"elastic\r%s", true}, {"elastic\n%s", true},
        {"%s", false}, {"%s elastic", false}, {"elas tic %s", false}, {"elastic%s", false},
        {"elastic x%s", false}, {"elastic _%s", false}, {"elastic %s_", false}, {"elastic %s9", false},
        {"elastic %.95s", false}, {"elastic \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char invalid[] = "+/=.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[40] = invalid[i];
        snprintf(input, sizeof(input), "elastic %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'a', 96); changed[96] = '\0';
    snprintf(input, sizeof(input), "elastic %s", changed); extraction_case(detector, input, strlen(input), changed); /* No local entropy/token parser. */
    memcpy(changed, key1, sizeof(changed)); changed[0] = '-';
    snprintf(input, sizeof(input), "elastic %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "elastic X%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key1, sizeof(changed)); changed[95] = '-';
    snprintf(input, sizeof(input), "elastic %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "elastic %sX", changed); extraction_case(detector, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "elastic", 7); size_t at = 7;
            for (size_t i = 0; i < gap; ++i) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, key1, 96); at += 96;
            extraction_case(detector, input, at, gap == 40 ? key1 : NULL);
        }
    }
    for (size_t gap = 35; gap <= 36; ++gap) {
        memcpy(input, "elasticemail", 12); memset(input + 12, '.', gap); memcpy(input + 12 + gap, key1, 96);
        extraction_case(detector, input, 12 + gap + 96, gap == 35 ? key1 : NULL); /* email's 5 runes count AGAINST the elastic prefix window. */
    }
    int n = snprintf(input, sizeof(input), "elastic%c%s", 0, key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\nelastic %s\n\xff", key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "elastic %s %s", key1, key2); extraction_case(detector, input, (size_t)n, key1);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { int status, rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct {
    const char *const *keys; size_t count;
    const reply *replies;
    const char *agent, *borrowed_url, *current_key;
    const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *key = expected->keys[http->calls - 1]; const reply *r = &expected->replies[http->calls - 1];
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == 159 && !memcmp(request->url, base_url, 63));
    CHECK(!memcmp(request->url + 63, key, 97)); /* Complete 159-byte URL plus NUL. */
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 112);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, expected->agent));
    CHECK(!expected->borrowed_url); expected->borrowed_url = request->url; expected->current_key = key;
    http->response = (br_http_response){.status = r->status, .body = r->body, .body_error = r->read_error}; http->send_rc = r->rc; http->send_error = r->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(strlen(expected->borrowed_url) == 159 && !memcmp(expected->borrowed_url, base_url, 63));
        CHECK(!memcmp(expected->borrowed_url + 63, expected->current_key, 97)); /* URL lives THROUGH release, including failure. */
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
    char input[128]; snprintf(input, sizeof(input), "elastic %s", key1);
    const char *keys[] = {key1}; expected_http expected = {.keys = keys, .count = 1, .replies = &response, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_url);
    check_result(&results.items[0], key1, verified); br_results_clear(&results);
}

static void occurrences_and_skips(const br_detector *detector)
{
    char input[384]; snprintf(input, sizeof(input), "elastic %s\nELASTICEMAIL %s\nelastic %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; reply replies[] = {{.status = 500, .body = text("{\"success\":true}")}, {.status = 401, .body = text("{\"success\":true}")}, {.status = 200, .body = text("{\"success\":true}")}};
    expected_http expected = {.keys = keys, .count = 3, .replies = replies, .agent = "TruffleHog elastic-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "elastic-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3 && !expected.borrowed_url);
        CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], true);
        br_results_clear(&results);
    }
    http.calls = http.releases = 0;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && !http.calls && !http.releases); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results); /* URL preparation precedes constructor skip; no invented fallible formatter seam. */
}

static void whole_typed_json(const br_detector *detector)
{
    const struct { const char *body; bool verified; } cases[] = {
        {"null", false}, {"{}", false}, {"{\"success\":false}", false}, {"{\"success\":true}", true},
        {"{\"success\":null}", false}, {"{\"success\":true,\"success\":null}", true},
        {"{\"success\":true,\"success\":false}", false}, {"{\"success\":false,\"SUCCESS\":true}", true},
        {" {\"Success\":true}\r\n", true}, {"{\"\\u0073uccess\":true}", true},
        {"{\"\\u017fuccess\":true}", true}, {"{\"\xc5\xbfuccess\":true}", true},
        {"{\"success\":\"true\"}", false}, {"{\"success\":1}", false}, {"{\"success\":[]}", false},
        {"{\"success\":{},\"success\":true}", false}, {"{\"success\":\"bad\",\"success\":true}", false},
        {"{\"success\":true,\"success\":1,\"success\":null}", false},
        {"{\"unknown\":184467440737095516160000000000000000,\"nested\":[1e9999,{\"x\":-9223372036854775809}],\"success\":true}", true},
        {"{\"success\":\"bad\",\"unknown\":184467440737095516160000000000000000,\"success\":true}", false},
        {"{\"success\":true} {\"success\":false}", false}, {"{\"success\":true} trailing", false},
        {"[]", false}, {"true", false}, {"\"text\"", false}, {"1e9999", false},
        {"", false}, {"{", false}, {"{\"success\":}", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        verification_case(detector, (reply){.status = 500, .body = text(cases[i].body)}, cases[i].verified);
    verification_case(detector, (reply){.status = 401, .body = text("{\"success\":true}"), .read_error = "synthetic partial read"}, false);
    verification_case(detector, (reply){.status = 200, .body = text("{\"success\":true}"), .read_error = ""}, false);
    fail_duplicate_text = "unexpected end of JSON input"; fail_duplicate_after = 1;
    verification_case(detector, (reply){.status = 500, .body = text("{"), .read_error = ""}, false);
    CHECK(fail_duplicate_after == 1); fail_duplicate_after = 0; /* Read failure must NOT even enter decode/cause allocation. */
    verification_case(detector, (reply){.status = 500, .body = text("{\"success\":true}"), .rc = 1, .send_error = "net/http: nil Context"}, false);
    verification_case(detector, (reply){.status = 500, .body = text("{\"success\":true}"), .rc = 1, .send_error = "out of memory constructing HTTP headers"}, false);
    verification_case(detector, (reply){.status = 500, .body = text("{\"success\":true}"), .rc = -1}, false);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "elastic %s", key1);
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
    char input[256]; snprintf(input, sizeof(input), "elastic %s\nelastic %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)}; br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const char *keys[] = {key1, key2}; reply replies[] = {{.status = 200, .body = text("{\"success\":true}")}, {.status = 500, .body = text("{\"success\":true}")}};
    expected_http expected = {.keys = keys, .count = 2, .replies = replies, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create ElasticEmail result") && !fail_part_after);
    check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create ElasticEmail result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    replies[1].body = text("{"); http.calls = http.releases = 0;
    fail_duplicate_text = "unexpected end of JSON input"; fail_duplicate_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode ElasticEmail verification response") && !fail_duplicate_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL; /* Ordinary decode +1 cause allocation failure MUST be fatal -1. */
    replies[1].body = text("{\"success\":\"bad\",\"success\":true}"); http.calls = http.releases = 0;
    fail_duplicate_text = "json: cannot unmarshal string into Go struct field .success of type bool"; fail_duplicate_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode ElasticEmail verification response") && !fail_duplicate_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL; /* Original-span projector resource failure is not ordinary type suppression. */
    const char huge[] = "{\"success\":true,\"unknown\":1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901}";
    replies[1].body = text(huge); http.calls = http.releases = 0; fail_alloc_size = sizeof(huge); fail_alloc_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot decode ElasticEmail verification response") && !fail_alloc_after && http.calls == 2 && http.releases == 2);
    check_prior(&results, prior); free(error); error = NULL; /* Real validation-shadow allocation, not a new JSON seam. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 97; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    replies[1].body = text("{\"success\":true}"); http.calls = http.releases = 0;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior); /* Constructor skips never push. */
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append ElasticEmail result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key1, true); check_result(&results.items[1], key2, true); br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 96, 0); test_secret(key2, 96, 7);
    key1[5] = 'A'; key1[10] = 'G'; key1[35] = '-'; key1[66] = '_'; key1[95] = 'Z';
    key2[5] = 'Z'; key2[10] = 'Q'; key2[35] = '_'; key2[66] = '-'; key2[95] = 'K';
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_skips(detector); whole_typed_json(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("ElasticEmail");
}
