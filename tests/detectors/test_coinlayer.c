/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char other_key[] = "987654zyxwvutsrqponmlkjihgfedcba";
static const char success[] = "\"success\": true";
static const char restricted[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
static size_t fail_finding_after;

/* One necessary provider-finding allocation, no synthetic URL/auth copy. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32 || len == 5);
    if (len == 32 && fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[33]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other_key) == 32);
    CHECK(br_coinlayer_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Coinlayer detector output")); free(error); error = NULL;
    CHECK(!br_coinlayer_init(&detector, &error) && detector && !error);
    CHECK(!br_coinlayer_init(&again, NULL) && again == detector);
    CHECK(detector->type == 402 && detector->version == 0 && !strcmp(detector->name, "Coinlayer") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Coinlayer provides real-time and historical cryptocurrency exchange rates. The API key can be used to access this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "coinlayer"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 402, expected, "key");
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
    char input[192], changed[34];
    const char *formats[] = {"coinlayer '%s'", "COINLAYER=-%s-", "prefixCoInLaYeRsuffix\r\n%s", "coinlayer \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); expect_one(detector, input, key);
    }
    expect_one(detector, "", NULL); expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "coin layer %s", key); expect_one(detector, input, NULL);
    const char *bad[] = {"coinlayer _%s", "coinlayer %s_", "coinlayer x%s", "coinlayer %sa", "coinlayer %.31s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); expect_one(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = 'A';
    snprintf(input, sizeof(input), "COINLAYER %s", changed); expect_one(detector, input, NULL); /* Keyword CI only. */
    memcpy(changed, key, sizeof(key)); changed[10] = '_';
    snprintf(input, sizeof(input), "coinlayer %s", changed); expect_one(detector, input, NULL);
    memset(changed, 'z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "coinlayer %s", changed); expect_one(detector, input, changed); /* Not hex or entropy validation. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "coinlayer", 9); memset(input + 9, '.', gap);
        snprintf(input + 9 + gap, sizeof(input) - 9 - gap, "%s", other_key);
        expect_one(detector, input, gap == 40 ? other_key : NULL);
    }
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
typedef struct { const char *key; int status; br_slice body; const char *read_error; int send_rc; const char *send_error; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *expected_ctx; const char *borrowed_url; } script;

static void check_url(const char *url, const char *expected_key)
{
    char expected[128]; snprintf(expected, sizeof(expected), "https://api.coinlayer.com/api/livelive?access_key=%s", expected_key);
    CHECK(url && strlen(url) == strlen(expected) && !strcmp(url, expected)); /* Full token, terminating NUL and source typo. */
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 402 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
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
    check_url(steps->borrowed_url, steps->rows[http->calls - 1].key); steps->borrowed_url = NULL; /* Stack URL remains live through release, even on read error. */
    test_http_release(user, response);
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

static void binary_markers_and_reads(const br_detector *detector)
{
    const struct { br_slice body; const char *read_error; int status; bool verified; } cases[] = {
        {TEXT(success), NULL, 200, true}, {TEXT(restricted), NULL, 200, true},
        {TEXT("not JSON \"success\": true trailing"), NULL, 201, true},
        {TEXT("\xff\0past NUL \"success\": true"), NULL, 299, true},
        {TEXT("\0\xff\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, 200, true},
        {TEXT(""), NULL, 200, false}, {TEXT("{\"success\":true}"), NULL, 200, false},
        {TEXT("{\"success\":  true}"), NULL, 200, false}, {TEXT("{\"Success\": true}"), NULL, 200, false},
        {TEXT("{\"success\": True}"), NULL, 200, false},
        {TEXT("\"info\": \"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, 200, false},
        {TEXT("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption\""), NULL, 200, false},
        {TEXT("\"info\":\"Access Restricted - Your current Subscription Plan does not support https Encryption.\""), NULL, 200, false},
        {TEXT(success), "read failure", 200, false}, {TEXT(restricted), "", 200, false},
        {TEXT(success), "", 299, false}, /* A non-NULL EMPTY error still means ReadAll failed. */
        {TEXT(success), NULL, 199, false}, {TEXT(success), NULL, 300, false},
        {TEXT(restricted), NULL, 401, false}, {TEXT(restricted), "read failure", 503, false},
        {TEXT(success), "", 403, false}, {TEXT(success), NULL, 204, true},
    };
    char input[64]; snprintf(input, sizeof(input), "coinlayer %s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = cases[i].status, .body = cases[i].body, .read_error = cases[i].read_error}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, cases[i].verified); br_results_clear(&results);
    }
}

static void occurrences_and_do_errors(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "coinlayer %s\ncoinlayer %s\ncoinlayer %s", key, key, other_key);
    script steps = {.count = 3, .rows = {
        {.key = key, .status = 200, .body = TEXT(success)},
        {.key = key, .status = 201, .body = TEXT(restricted)},
        {.key = other_key, .status = 200, .body = TEXT(success), .read_error = ""},
    }};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, verify && i < 2);
        br_results_clear(&results); /* Success does not consume duplicates or break later candidates. */
    }
    for (size_t i = 0; i < 3; ++i) { steps.rows[i].send_rc = 1; steps.rows[i].send_error = "no such host"; }
    for (int retry = 0; retry < 2; ++retry) {
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, false);
        br_results_clear(&results); /* No DNS cache/suppression. */
    }
    snprintf(input, sizeof(input), "coinlayer %s", key);
    const char *errors[] = {"no such host", "net/http: nil Context", "context canceled", "context deadline exceeded",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent", "unsupported: native SANE policy", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{.key = key, .status = 200, .body = TEXT(success), .send_rc = i % 2 ? 1 : -1, .send_error = errors[i]}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results); /* Whole shared error domain suppressed, no setter/classifier. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void contexts_and_resources(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "coinlayer %s\ncoinlayer %s", key, other_key);
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
    for (int nil_context = 0; nil_context <= 1; ++nil_context) {
        script steps = {.count = 2, .rows = {{.key = key, .status = 200, .body = TEXT(success)}, {.key = other_key, .status = 299, .body = TEXT(restricted)}}};
        http = (test_http){.inspect = inspect, .user = &steps}; transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        fail_finding_after = 2;
        int rc = detector->scan(detector, nil_context ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, "cannot create Coinlayer result") && !fail_finding_after);
        CHECK(http.calls == (nil_context ? 0u : 1u) && http.releases == http.calls && results.len == 1 && !steps.borrowed_url);
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
        free(error); br_results_clear(&results);
        http.calls = http.releases = 0;
        results = test_scan(detector, nil_context ? NULL : &ctx, true, input, strlen(input));
        CHECK(results.len == (nil_context ? 0u : 2u) && http.calls == (nil_context ? 0u : 2u) && http.releases == http.calls);
        if (!nil_context) { check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true); }
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); binary_markers_and_reads(detector); occurrences_and_do_errors(detector); contexts_and_resources(detector);
    return test_finish("Coinlayer");
}
