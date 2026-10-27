/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[61], other_key[61];
static const char success[] = "\"success\":true";
static size_t fail_finding_after;

/* Fail an actual key-part allocation, not an invented URL/auth copy. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 60 || len == 5);
    if (len == 60 && fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[61]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 60 && strlen(other_key) == 60);
    CHECK(br_commodities_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Commodities detector output")); free(error); error = NULL;
    CHECK(!br_commodities_init(&detector, &error) && detector && !error);
    CHECK(!br_commodities_init(&again, NULL) && again == detector);
    CHECK(detector->type == 566 && detector->version == 0 && !strcmp(detector->name, "Commodities") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Commodities API keys can be used to access and modify commodity data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "commodities"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 566, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[62];
    const char *formats[] = {"commodities '%s'", "COMMODITIES=-%s-", "prefixCoMmOdItIeSsuffix\r\n%s", "commodities \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); expect_one(detector, input, key);
    }
    expect_one(detector, "", NULL); expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "commod ities %s", key); expect_one(detector, input, NULL);
    const char *bad[] = {"commodities _%s", "commodities %s_", "commodities x%s", "commodities %sA", "commodities %.59s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); expect_one(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[10] = '_';
    snprintf(input, sizeof(input), "commodities %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = '-';
    snprintf(input, sizeof(input), "commodities %s", changed); expect_one(detector, input, NULL);
    memset(changed, 'Z', 60); changed[60] = '\0';
    snprintf(input, sizeof(input), "commodities %s", changed); expect_one(detector, input, changed); /* Mixed alnum, not hex/entropy validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "commodities", 11); memset(input + 11, '.', gap);
        snprintf(input + 11 + gap, sizeof(input) - 11 - gap, "%s", other_key);
        expect_one(detector, input, gap == 40 ? other_key : NULL);
    }
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
typedef struct { const char *key; int status; br_slice body; const char *read_error; int send_rc; const char *send_error; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *expected_ctx; const char *borrowed_url; uint32_t timeout_limit; } script;

static void check_url(const char *url, const char *expected_key)
{
    char expected[sizeof("https://commodities-api.com/api/latest?access_key=") + 60];
    int n = snprintf(expected, sizeof(expected), "https://commodities-api.com/api/latest?access_key=%s", expected_key);
    CHECK(n > 0 && (size_t)n + 1 == sizeof(expected));
    CHECK(url && strlen(url) == (size_t)n && !strcmp(url, expected)); /* Complete mixed-case key plus terminating NUL. */
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 566 && request->profile == BR_HTTP_SANE);
    if (steps->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= steps->timeout_limit);
    else CHECK(request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, step->key);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog")); /* No Type/Accept/Auth/manual Content-Length. */
    steps->borrowed_url = request->url;
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->read_error};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(http->calls && http->calls <= steps->count);
    check_url(steps->borrowed_url, steps->rows[http->calls - 1].key); steps->borrowed_url = NULL;
    test_http_release(user, response); /* Always release, including read-error DROP. */
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == (verify ? steps->count : 0) && http.releases == http.calls && !steps->borrowed_url);
    return results;
}

static void binary_marker_and_read_drop(const br_detector *detector)
{
    const struct { br_slice body; const char *read_error; int status; bool keep, verified; } cases[] = {
        {TEXT(success), NULL, 200, true, true},
        {TEXT("\xff\0past NUL \"success\":true"), NULL, 201, true, true},
        {TEXT("not JSON \"success\":true trailing"), NULL, 299, true, true},
        {TEXT("{\"success\": true}"), NULL, 200, true, false}, /* NOT Coinlayer's spaced marker. */
        {TEXT("{\"Success\":true}"), NULL, 200, true, false},
        {TEXT("{\"success\":TRUE}"), NULL, 200, true, false},
        {TEXT("{\"success\":\ntrue}"), NULL, 200, true, false},
        {TEXT(""), NULL, 200, true, false},
        {TEXT("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, 200, true, false},
        {TEXT(success), NULL, 204, true, true}, {TEXT(success), NULL, 199, true, false},
        {TEXT(success), NULL, 300, true, false}, {TEXT(success), NULL, 401, true, false},
        {TEXT("not JSON"), NULL, 503, true, false},
        {TEXT(success), "read failure", 200, false, false},
        {TEXT(success), "", 299, false, false}, /* EMPTY error pointer still causes DROP. */
        {TEXT(success), "", 401, false, false},
        {TEXT("not JSON"), "read failure", 503, false, false},
        {TEXT(""), "", 204, false, false},
    };
    char input[80]; snprintf(input, sizeof(input), "commodities %s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = cases[i].status, .body = cases[i].body, .read_error = cases[i].read_error}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == (cases[i].keep ? 1u : 0u));
        if (cases[i].keep) check_result(&results.items[0], key, cases[i].verified);
        br_results_clear(&results);
    }
}

static void occurrence_continuation_and_do_precedence(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "commodities %s\ncommodities %s\ncommodities %s", key, key, other_key);
    script steps = {.count = 3, .rows = {
        {.key = key, .status = 200, .body = TEXT(success)},
        {.key = key, .status = 401, .body = TEXT(success), .read_error = ""},
        {.key = other_key, .status = 299, .body = TEXT(success)},
    }};
    br_results results = run(detector, input, false, &steps); CHECK(results.len == 3);
    check_result(&results.items[0], key, false); check_result(&results.items[1], key, false); check_result(&results.items[2], other_key, false); br_results_clear(&results);
    results = run(detector, input, true, &steps); CHECK(results.len == 2);
    check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true); br_results_clear(&results); /* Read DROP at 401, then continue later occurrences. */
    steps.rows[1].send_rc = 1; steps.rows[1].send_error = "no such host";
    results = run(detector, input, true, &steps); CHECK(results.len == 3);
    check_result(&results.items[0], key, true); check_result(&results.items[1], key, false); check_result(&results.items[2], other_key, true); br_results_clear(&results); /* Do KEEP outranks the SAME body_error DROP. */
    steps.rows[1].send_rc = 0; steps.rows[1].send_error = NULL; steps.rows[1].read_error = NULL;
    results = run(detector, input, true, &steps); CHECK(results.len == 3);
    check_result(&results.items[0], key, true); check_result(&results.items[1], key, false); check_result(&results.items[2], other_key, true); br_results_clear(&results); /* Read success/non-2xx KEEP, no dedup/consumption. */
    snprintf(input, sizeof(input), "commodities %s", key);
    const char *errors[] = {"no such host", "net/http: nil Context", "context canceled", "context deadline exceeded",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent", "unsupported: native SANE policy", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{.key = key, .status = 200, .body = TEXT(success), .read_error = i % 2 ? "" : "read failure", .send_rc = i % 2 ? 1 : -1, .send_error = errors[i]}}};
        results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results); /* Combined Do/setup domain suppresses before examining read errors. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void contexts_and_deadlines(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "commodities %s\ncommodities %s", key, other_key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other_key, false); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctxs[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}};
    for (size_t i = 0; i < sizeof(ctxs) / sizeof(ctxs[0]); ++i) {
        http.calls = http.releases = 0;
        results = test_scan(detector, &ctxs[i], true, input, strlen(input));
        CHECK(results.len == 2 && !http.calls && http.releases == (i ? 2u : 0u));
        check_result(&results.items[0], key, false); check_result(&results.items[1], other_key, false); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "commodities %s", key);
    for (int shorter = 0; shorter <= 1; ++shorter) {
        script steps = {.count = 1, .rows = {{.key = key, .status = 200, .body = TEXT(success)}}, .timeout_limit = shorter ? 2000 : 0};
        http = (test_http){.inspect = inspect, .user = &steps}; transport = transport_for(&http);
        struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + (shorter ? 2000 : 20000);
        br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline}; steps.expected_ctx = &ctx;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline && !steps.borrowed_url);
        check_result(&results.items[0], key, true); br_results_clear(&results);
    }
}

static void resources_before_drop(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "commodities %s\ncommodities %s\ncommodities %s", key, other_key, key);
    for (int nil_context = 0; nil_context <= 1; ++nil_context) {
        script steps = {.count = 3, .rows = {
            {.key = key, .status = 200, .body = TEXT(success)},
            {.key = other_key, .status = 401, .body = TEXT(success), .read_error = ""},
            {.key = key, .status = 299, .body = TEXT(success)},
        }};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        fail_finding_after = 2;
        int rc = detector->scan(detector, nil_context ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, "cannot create Commodities result") && !fail_finding_after);
        CHECK(http.calls == (nil_context ? 0u : 1u) && http.releases == http.calls && results.len == 1 && !steps.borrowed_url);
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
        free(error); br_results_clear(&results);
        http.calls = http.releases = 0;
        results = test_scan(detector, nil_context ? NULL : &ctx, true, input, strlen(input));
        CHECK(results.len == (nil_context ? 0u : 2u) && http.calls == (nil_context ? 0u : 3u) && http.releases == http.calls);
        if (!nil_context) { check_result(&results.items[0], key, true); check_result(&results.items[1], key, true); }
        br_results_clear(&results); /* Resource failure was fatal BEFORE ordinary read/constructor DROP. */
    }
}

int main(void)
{
    test_secret(key, 60, 0); test_secret(other_key, 60, 9);
    key[0] = 'Z'; key[23] = 'G'; key[59] = 'Y'; other_key[2] = 'A'; other_key[17] = 'Q';
    const br_detector *detector = descriptor();
    extraction(detector); binary_marker_and_read_drop(detector); occurrence_continuation_and_do_precedence(detector); contexts_and_deadlines(detector); resources_before_drop(detector);
    return test_finish("Commodities");
}
