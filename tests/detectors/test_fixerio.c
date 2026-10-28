/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key1[33], key2[33];
static const char base_url[] = "https://data.fixer.io/api/latest?access_key=";
static const unsigned char success_marker[] = "\"success\": true";
static const unsigned char restricted_marker[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
static size_t fail_alloc_size, fail_alloc_after, fail_part_after;
static bool fail_agent_copy;

/* Genuine capture/finding/shared-send resources, not a URL/formatter seam. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 32 && strlen(key2) == 32 && strlen(base_url) == 44);
    CHECK(br_fixerio_init(NULL, &error) == -1 && error && !strcmp(error, "invalid FixerIO detector output"));
    free(error); error = NULL;
    CHECK(br_fixerio_init(NULL, NULL) == -1);
    CHECK(br_fixerio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_fixerio_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 149 && detector->version == 0 && !strcmp(detector->name, "FixerIO"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Fixer.io is a foreign exchange rates and currency conversion API. Fixer.io API keys can be used to access and retrieve current and historical foreign exchange rates."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "fixer")); /* NOT fixerio-required. */
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 149, key, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 32);
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
    char input[256], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"fixer '%s'", true}, {"FIXer=%s", true}, {"prefixersuffix:%s", true}, {"fixerio %s", true},
        {"fixer\r\n%s", true}, {"fixer\r%s", true}, {"fixer\n%s", true},
        {"%s", false}, {"%s fixer", false}, {"fix er %s", false}, {"fixer%s", false},
        {"fixer x%s", false}, {"fixer _%s", false}, {"fixer %s_", false}, {"fixer %s9", false},
        {"fixer %.31s", false}, {"fixer \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1); extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char invalid[] = "_-+/=.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key1, sizeof(changed)); changed[16] = invalid[i]; snprintf(input, sizeof(input), "fixer %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'Z', 32); changed[32] = '\0'; snprintf(input, sizeof(input), "fixer %s", changed); extraction_case(detector, input, strlen(input), changed); /* Mixed alnum, not hex/entropy/token validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "fixer", 5); size_t at = 5;
            for (size_t i = 0; i < gap; ++i) { if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = '.'; }
            memcpy(input + at, key1, 32); at += 32; extraction_case(detector, input, at, gap == 40 ? key1 : NULL);
        }
    }
    int n = snprintf(input, sizeof(input), "fixer%c%s", 0, key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\nfixer %s\n\xff", key1); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "fixer %s %s", key1, key2); extraction_case(detector, input, (size_t)n, key1);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { int status, rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct {
    const char *const *keys; size_t count; const reply *replies;
    const char *agent, *borrowed_url, *current_key; const br_scan_ctx *original;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->count);
    const char *key = expected->keys[http->calls - 1]; const reply *r = &expected->replies[http->calls - 1];
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == 76 && !memcmp(request->url, base_url, 44));
    CHECK(!memcmp(request->url + 44, key, 33)); /* Full URL plus NUL, not a formatted/capped approximation. */
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 149);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, expected->agent));
    CHECK(!expected->borrowed_url); expected->borrowed_url = request->url; expected->current_key = key;
    http->response = (br_http_response){.status = r->status, .body = r->body, .body_error = r->read_error}; http->send_rc = r->rc; http->send_error = r->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_url) {
        CHECK(strlen(expected->borrowed_url) == 76 && !memcmp(expected->borrowed_url, base_url, 44));
        CHECK(!memcmp(expected->borrowed_url + 44, expected->current_key, 33)); expected->borrowed_url = NULL;
    }
    test_http_release(user, response); /* Exactly one owned release, not source's duplicate deferred Close. */
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void verification_case(const br_detector *detector, reply response, bool keep, bool verified)
{
    char input[64]; snprintf(input, sizeof(input), "fixer %s", key1);
    const char *keys[] = {key1}; expected_http expected = {.keys = keys, .count = 1, .replies = &response, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == (keep ? 1u : 0u) && http.calls == 1 && http.releases == 1 && !expected.borrowed_url);
    if (keep) check_result(&results.items[0], key1, verified);
    br_results_clear(&results);
}

static void occurrences_and_drops(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "fixer %s\nFIXER %s\nfixer %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; reply replies[] = {
        {.status = 200, .body = {success_marker, sizeof(success_marker) - 1}},
        {.status = 201, .body = {restricted_marker, sizeof(restricted_marker) - 1}},
        {.status = 299, .body = {success_marker, sizeof(success_marker) - 1}},
    };
    expected_http expected = {.keys = keys, .count = 3, .replies = replies, .agent = "TruffleHog fixerio-offline"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "fixerio-offline"}; expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input)); CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        CHECK(results.items[0].raw.data != results.items[2].raw.data && results.items[0].secret_parts != results.items[2].secret_parts);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], true);
        br_results_clear(&results);
    }
    replies[1].read_error = ""; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 3 && http.releases == 3);
    check_result(&results.items[0], key1, true); check_result(&results.items[1], key1, true); br_results_clear(&results); /* DROP current occurrence, continue subsequent duplicate without invocation rollback. */
    http.calls = http.releases = 0;
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len && !http.calls && !http.releases); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
}

static void exact_binary_markers_and_statuses(const br_detector *detector)
{
    static const unsigned char binary_success[] = "junk\0\xff\"success\": true\x80";
    static const unsigned char binary_restricted[] = "junk\0\xff\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"\x80";
    const struct { int status; br_slice body; const char *read_error; bool keep, verified; } cases[] = {
        {200, {success_marker, sizeof(success_marker) - 1}, NULL, true, true},
        {201, {restricted_marker, sizeof(restricted_marker) - 1}, NULL, true, true},
        {204, {binary_success, sizeof(binary_success) - 1}, NULL, true, true},
        {299, {binary_restricted, sizeof(binary_restricted) - 1}, NULL, true, true},
        {199, {restricted_marker, sizeof(restricted_marker) - 1}, NULL, true, false},
        {300, {success_marker, sizeof(success_marker) - 1}, NULL, true, false},
        {401, {restricted_marker, sizeof(restricted_marker) - 1}, NULL, true, false},
        {403, {success_marker, sizeof(success_marker) - 1}, NULL, true, false},
        {500, {binary_restricted, sizeof(binary_restricted) - 1}, NULL, true, false},
        {200, {success_marker, sizeof(success_marker) - 1}, "partial read", false, false},
        {200, {binary_restricted, sizeof(binary_restricted) - 1}, "", false, false},
        {500, {success_marker, sizeof(success_marker) - 1}, "", false, false},
        {401, {0}, "read before rejected status", false, false}, {200, {0}, NULL, true, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        verification_case(detector, (reply){.status = cases[i].status, .body = cases[i].body, .read_error = cases[i].read_error}, cases[i].keep, cases[i].verified);
    const struct { const char *body; bool verified; } spelling[] = {
        {"not JSON \"success\": trueish trailing", true}, {"{\"success\":true}", false}, {"{\"success\":  true}", false},
        {"{\"Success\": true}", false}, {"{\"success\": True}", false},
        {"{\"info\": \"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"}", false},
        {"{\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption\"}", false},
        {"{\"info\":\"Access restricted - Your current Subscription Plan does not support HTTPS Encryption.\"}", false},
        {"{\"success\":false,\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"}", true},
    };
    for (size_t i = 0; i < sizeof(spelling) / sizeof(spelling[0]); ++i) verification_case(detector, (reply){.status = 200, .body = text(spelling[i].body)}, true, spelling[i].verified);
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, key1}};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i)
        verification_case(detector, (reply){.status = 200, .rc = failures[i].rc, .body = {success_marker, sizeof(success_marker) - 1}, .read_error = "", .send_error = failures[i].cause}, true, false); /* Do errors KEEP even with populated read_error; never classify as skip/DROP. */
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "fixer %s", key1); test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
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

static void resources_before_skip_drop_and_rollback(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "fixer %s\nfixer %s", key1, key2); br_slice data = text(input);
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const char *keys[] = {key1, key2}; reply replies[] = {
        {.status = 200, .body = {success_marker, sizeof(success_marker) - 1}},
        {.status = 500, .body = {restricted_marker, sizeof(restricted_marker) - 1}, .read_error = ""},
    };
    expected_http expected = {.keys = keys, .count = 2, .replies = replies, .agent = "TruffleHog"}; test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FixerIO result") && !fail_part_after); check_prior(&results, prior); free(error); error = NULL;
    replies[0].read_error = "would DROP"; fail_part_after = 1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FixerIO result") && !fail_part_after && !http.calls && !http.releases); check_prior(&results, prior); free(error); error = NULL;
    replies[0].read_error = NULL; fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create FixerIO result") && !fail_part_after && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL; /* Earlier verified addition rolls back; caller survives and second candidate never reaches DROP. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 33; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after); check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error && !http.calls && !http.releases); check_prior(&results, prior); /* Constructor skips never push. */
    replies[0].read_error = "";
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == 0 && !error && http.calls == 2 && http.releases == 2); check_prior(&results, prior); /* Both read-error DROPs never push, even at rejected status. */
    replies[0].read_error = NULL; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FixerIO result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    replies[1].status = 201; replies[1].read_error = NULL; http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2); check_result(&results.items[0], key1, true); check_result(&results.items[1], key2, true); br_results_clear(&results);
}

int main(void)
{
    test_secret(key1, 32, 0); test_secret(key2, 32, 7); key1[4] = 'A'; key1[15] = 'G'; key2[4] = 'Z'; key2[15] = 'Q';
    const br_detector *detector = descriptor(); extraction(detector); occurrences_and_drops(detector); exact_binary_markers_and_statuses(detector); suppressed_setup(detector); resources_before_skip_drop_and_rollback(detector);
    return test_finish("FixerIO exact binary markers + read-error DROP + retained send errors");
}
