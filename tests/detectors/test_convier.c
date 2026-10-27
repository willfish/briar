/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[44], other_key[44];
static const char success[] = "\"error\":false";
static size_t fail_size, fail_after, tracked_allocations;

/* Fail actual capture/Raw/regex-workspace allocations, not invented auth copies. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size) {
        ++tracked_allocations;
        if (--fail_after == 0) return NULL;
    }
    return calloc(1, size);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 43 && strlen(other_key) == 43);
    CHECK(br_convier_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Convier detector output")); free(error); error = NULL;
    CHECK(!br_convier_init(&detector, &error) && detector && !error);
    CHECK(!br_convier_init(&again, NULL) && again == detector);
    CHECK(detector->type == 664 && detector->version == 0 && !strcmp(detector->name, "Convier") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Convier is a service for managing and verifying event data. Convier keys can be used to interact with the Convier API to manage event data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "convier"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 664, expected, "key");
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 43);
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
    char input[256], changed[45];
    const char *formats[] = {"convier '%s'", "CONVIER=-%s-", "prefixCoNvIeRsuffix\r\n%s", "convier\r%s", "convier\n%s", "convier \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); expect_one(detector, input, key);
    }
    expect_one(detector, "", NULL); expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "con vier %s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "%s convier", key); expect_one(detector, input, NULL);
    const char *bad[] = {"convier%s", "convier _%s", "convier %s_", "convier x%s", "convier %sA", "convier 1%s", "convier %.42s", "convier %s0"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); expect_one(detector, input, NULL);
    }
    const struct { size_t at; char value; } changes[] = {{0, 'A'}, {1, 'z'}, {2, '/'}, {2, '\\'}, {20, '_'}, {20, '-'}, {20, '+'}, {20, '.'}};
    for (size_t i = 0; i < sizeof(changes) / sizeof(changes[0]); ++i) {
        memcpy(changed, key, sizeof(key)); changed[changes[i].at] = changes[i].value;
        snprintf(input, sizeof(input), "CONVIER %s", changed); expect_one(detector, input, NULL);
    }
    snprintf(input, sizeof(input), "convier %s", key + 1); expect_one(detector, input, NULL); /* Exactly two decimal digits. */
    memcpy(changed, "99|", 3); memset(changed + 3, 'Z', 40); changed[43] = '\0';
    snprintf(input, sizeof(input), "convier %s", changed); expect_one(detector, input, changed); /* No entropy/hex/word filtering. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "convier", 7); memset(input + 7, '.', gap);
        memcpy(input + 7 + gap, other_key, sizeof(other_key));
        expect_one(detector, input, gap == 40 ? other_key : NULL);
    }
    snprintf(input, sizeof(input), "convier %s %s", key, other_key); expect_one(detector, input, key); /* Non-overlapping whole matches need another prefix. */
    static const char prefix[] = "noise\0CONVIER\r\n";
    memcpy(input, prefix, sizeof(prefix) - 1); memcpy(input + sizeof(prefix) - 1, key, sizeof(key) - 1);
    br_results results = test_scan(detector, NULL, false, input, sizeof(prefix) + sizeof(key) - 2);
    CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    results = test_scan(detector, NULL, false, NULL, 0); CHECK(!results.len); br_results_clear(&results);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
typedef struct { const char *key; int status; br_slice body; const char *read_error; int send_rc; const char *send_error; } reply;
typedef struct {
    reply rows[3]; size_t count;
    const br_scan_ctx *expected_ctx;
    const char *authorization, *suffix;
    uint32_t timeout_limit;
} script;

static void check_authorization(const char *authorization, const char *expected_key)
{
    CHECK(authorization && strlen(authorization) == 50);
    CHECK(!memcmp(authorization, "Bearer ", 7) && !memcmp(authorization + 7, expected_key, 43));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 664 && request->profile == BR_HTTP_SANE);
    if (steps->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= steps->timeout_limit);
    else CHECK(request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://convier.me/api/event"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    steps->authorization = request->headers[0].value; check_authorization(steps->authorization, step->key);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->suffix ? "TruffleHog offline-convier" : "TruffleHog")); /* No invented Type/Accept/manual Content-Length. */
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->read_error};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    if (steps->authorization) {
        CHECK(http->calls && http->calls <= steps->count);
        check_authorization(steps->authorization, steps->rows[http->calls - 1].key);
        steps->authorization = NULL; /* Complete borrowed Bearer remains live through release. */
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == (verify ? steps->count : 0) && http.releases == http.calls && !steps->authorization);
    return results;
}

static void binary_marker_and_read_drop(const br_detector *detector)
{
    const struct { br_slice body; bool verified; } bodies[] = {
        {TEXT(success), true}, {TEXT("\xff\0past NUL \"error\":false"), true},
        {TEXT("not JSON \"error\":false trailing"), true}, {TEXT("\"error\":falsehood"), true},
        {TEXT("{\"error\": false}"), false}, {TEXT("{\"Error\":false}"), false},
        {TEXT("{\"error\":FALSE}"), false}, {TEXT("{\"error\":\nfalse}"), false},
        {TEXT("{\"error\":true}"), false}, {TEXT(""), false}, {{0}, false},
    };
    char input[64]; snprintf(input, sizeof(input), "convier %s", key);
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = 200, .body = bodies[i].body}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, bodies[i].verified); br_results_clear(&results);
    }
    const int statuses[] = {199, 200, 201, 204, 299, 300, 301, 302, 307, 308, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        for (int read_error = 0; read_error <= 2; ++read_error) {
            script steps = {.count = 1, .rows = {{.key = key, .status = statuses[i], .body = TEXT(success), .read_error = read_error ? (read_error == 1 ? "" : "read failure") : NULL}}};
            br_results results = run(detector, input, true, &steps); CHECK(results.len == (read_error ? 0u : 1u));
            if (!read_error) check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
            br_results_clear(&results); /* Any non-NULL read error, even empty, drops at EVERY status. */
        }
    }
}

static void occurrences_and_send_precedence(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "convier %s\nconvier %s\nconvier %s", key, key, other_key);
    script steps = {.count = 3, .suffix = "offline-convier", .rows = {
        {.key = key, .status = 200, .body = TEXT(success)},
        {.key = key, .status = 401, .body = TEXT(success), .read_error = ""},
        {.key = other_key, .status = 299, .body = TEXT(success)},
    }};
    br_results results = run(detector, input, false, &steps); CHECK(results.len == 3);
    check_result(&results.items[0], key, false); check_result(&results.items[1], key, false); check_result(&results.items[2], other_key, false); br_results_clear(&results);
    results = run(detector, input, true, &steps); CHECK(results.len == 2);
    check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true); br_results_clear(&results); /* Read DROP continues to later occurrences. */
    steps.rows[1].send_rc = 1; steps.rows[1].send_error = "no such host";
    results = run(detector, input, true, &steps); CHECK(results.len == 3);
    check_result(&results.items[0], key, true); check_result(&results.items[1], key, false); check_result(&results.items[2], other_key, true); br_results_clear(&results); /* Failed send KEEP outranks the SAME read DROP. */
    steps.rows[1].send_rc = 0; steps.rows[1].send_error = NULL; steps.rows[1].read_error = NULL;
    results = run(detector, input, true, &steps); CHECK(results.len == 3);
    check_result(&results.items[0], key, true); check_result(&results.items[1], key, false); check_result(&results.items[2], other_key, true); br_results_clear(&results); /* Non-2xx/read success retains false, no dedup. */
    snprintf(input, sizeof(input), "convier %s", key);
    const char *errors[] = {"no such host", "net/http: nil Context", "context canceled", "context deadline exceeded",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent", "unsupported: native SANE policy", "cannot create Convier result", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{.key = key, .status = 200, .body = TEXT(success), .read_error = i % 2 ? "" : "read failure", .send_rc = i % 2 ? 1 : -1, .send_error = errors[i]}}};
        results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results); /* Suppress whole shared-send domain, not classified error text. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void contexts_and_deadlines(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "convier %s\nconvier %s", key, other_key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other_key, false); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctxs[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\nagent"}};
    for (size_t i = 0; i < sizeof(ctxs) / sizeof(ctxs[0]); ++i) {
        http.calls = http.releases = 0;
        results = test_scan(detector, &ctxs[i], true, input, strlen(input));
        CHECK(results.len == 2 && !http.calls && http.releases == (i ? 2u : 0u));
        check_result(&results.items[0], key, false); check_result(&results.items[1], other_key, false); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "convier %s", key);
    for (int shorter = 0; shorter <= 1; ++shorter) {
        script steps = {.count = 1, .rows = {{.key = key, .status = 200, .body = TEXT(success)}}, .timeout_limit = shorter ? 2000 : 0};
        http = (test_http){.inspect = inspect, .user = &steps}; transport = transport_for(&http);
        struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + (shorter ? 2000 : 20000);
        br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline}; steps.expected_ctx = &ctx;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline && !steps.authorization);
        check_result(&results.items[0], key, true); br_results_clear(&results);
    }
}

static void resources_before_skips_and_rollback(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "convier %s\nconvier %s\nconvier %s", key, other_key, key);
    const struct { bool verify, nil_ctx, no_error; size_t size, after, calls; const char *error; } cases[] = {
        {true, false, false, 43, 2, 1, "cannot create Convier result"},
        {true, true, false, 43, 2, 0, "cannot create Convier result"},
        {false, false, true, 43, 2, 0, "cannot create Convier result"},
        {true, true, false, 44, 2, 0, "out of memory copying detector capture"},
        {true, true, false, 2 * sizeof(br_span), 1, 0, "out of memory iterating regex"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
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
        unsigned char *saved_raw = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        br_json *saved_parts = results.items[0].secret_parts;
        fail_size = cases[i].size; fail_after = cases[i].after; tracked_allocations = 0;
        int rc = detector->scan(detector, cases[i].nil_ctx ? NULL : &ctx, cases[i].verify,
                                (br_slice){(const unsigned char *)input, strlen(input)}, &results, cases[i].no_error ? NULL : &error);
        CHECK(rc == -1 && !fail_after && tracked_allocations == cases[i].after);
        CHECK(cases[i].no_error ? !error : error && !strcmp(error, cases[i].error));
        CHECK(http.calls == cases[i].calls && http.releases == http.calls && !steps.authorization);
        CHECK(results.len == 1 && results.items[0].detector_type == 777 && results.items[0].verified);
        CHECK(results.items[0].raw.data == saved_raw && results.items[0].raw.len == 5 && !memcmp(saved_raw, "prior", 5));
        CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned") && results.items[0].secret_parts == saved_parts);
        br_json *part = NULL; CHECK(json_object_object_get_ex(saved_parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
        free(error); br_results_clear(&results); /* Fatal own resources precede ordinary constructor/read skips; rollback only this invocation. */
    }
    script steps = {.count = 3, .rows = {
        {.key = key, .status = 200, .body = TEXT(success)},
        {.key = other_key, .status = 401, .body = TEXT(success), .read_error = ""},
        {.key = key, .status = 299, .body = TEXT(success)},
    }};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 2);
    check_result(&results.items[0], key, true); check_result(&results.items[1], key, true); br_results_clear(&results);
}

int main(void)
{
    memcpy(key, "00|", 3); test_secret(key + 3, 40, 0); key[5] = 'Z'; key[21] = 'Q'; key[42] = 'Y';
    memcpy(other_key, "07|", 3); test_secret(other_key + 3, 40, 9); other_key[9] = 'G'; other_key[42] = 'A';
    const br_detector *detector = descriptor();
    extraction(detector); binary_marker_and_read_drop(detector); occurrences_and_send_precedence(detector); contexts_and_deadlines(detector); resources_before_skips_and_rollback(detector);
    return test_finish("Convier");
}
