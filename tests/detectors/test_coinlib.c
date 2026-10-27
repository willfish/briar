/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "g7h9j2k5m6n8p3q4";
static const char other[] = "zzzzzzzzzzzzzzzz";
static size_t fail_part_after, fail_alloc_size, fail_alloc_after, allocation_failures;

/* Exercise actual capture/adapter allocations, not an invented URL allocation. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

/* A real positive +1 metadata failure must remain fatal before a nil-ctx skip. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 16 && strlen(other) == 16);
    CHECK(br_coinlib_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Coinlib detector output"));
    free(error); error = NULL;
    CHECK(!br_coinlib_init(&detector, &error) && detector && !error);
    CHECK(!br_coinlib_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 378 && detector->version == 0 && !strcmp(detector->name, "Coinlib") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Coinlib is a cryptocurrency data provider. Coinlib API keys can be used to access and retrieve cryptocurrency data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "coinlib"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 378, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[18];
    snprintf(input, sizeof(input), "coinlib = '%s'", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "COINLIB=%s", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "preCoInLiBsuffix\r\n%s", other); expect_one(detector, input, other);
    snprintf(input, sizeof(input), "coinlib\r%s", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "coinlib\n%s", key); expect_one(detector, input, key);
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "coin lib %s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinlib%s", key); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = 'G';
    snprintf(input, sizeof(input), "COINLIB %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[8] = '_';
    snprintf(input, sizeof(input), "coinlib %s", changed); expect_one(detector, input, NULL);
    changed[8] = '-'; snprintf(input, sizeof(input), "coinlib %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[15] = '\0';
    snprintf(input, sizeof(input), "coinlib %s", changed); expect_one(detector, input, NULL);
    snprintf(changed, sizeof(changed), "%sa", key);
    snprintf(input, sizeof(input), "coinlib %s", changed); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinlib _%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinlib %s_", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinlib X%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinlib %sX", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinlib -%s-", key); expect_one(detector, input, key);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "coinlib%*s%s", gap, "", key);
        expect_one(detector, input, gap == 40 ? key : NULL);
    }
    /* One non-overlapping whole match per prefix, not every following token. */
    snprintf(input, sizeof(input), "coinlib %s %s", key, other); expect_one(detector, input, key);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    reply rows[3];
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
    char expected_url[80];
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 378 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "https://coinlib.io/api/v1/global?key=%s&pref=EUR", step->key) == 62);
    CHECK(strlen(request->url) == 62 && !strcmp(request->url, steps->expected_url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    /* UA only: no Authorization, Content-Type, Accept or logical Content-Length. */
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog Coinlib-offline" : "TruffleHog"));
    steps->borrowed_url = request->url;
    static const unsigned char body[] = "\xff\0ignored non-JSON";
    http->response = (br_http_response){
        .status = step->status,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1},
        .body_error = "synthetic ignored body read error",
    };
    http->send_error = step->send_error;
    http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *steps = http->user;
    CHECK(steps->borrowed_url && strlen(steps->borrowed_url) == 62 && !strcmp(steps->borrowed_url, steps->expected_url));
    steps->borrowed_url = NULL;
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url);
    return results;
}

static void occurrences_and_nil(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "coinlib %s\nCOINLIB %s\ncoinlib %s", key, other, key);
    const char *keys[] = {key, other, key};
    script steps = {.count = 3, .agent_suffix = "Coinlib-offline"};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = i == 1 ? 503 : 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {0};
        br_results results = run(detector, input, verify, verify ? &steps : &none);
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i != 1);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
}

static void statuses_and_do_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "coinlib %s", key);
    /* All 100 2xx codes verify, even with unreadable/binary/absent bodies. */
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = status, .nil_body = status % 2 == 0};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = rejected[i]};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create Coinlib result", "synthetic Do error key=g7h9j2k5m6n8p3q4", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    /* No detector-local entropy filtering or deduplication on verification. */
    snprintf(input, sizeof(input), "coinlib %s", other);
    script steps = {.count = 1}; steps.rows[0] = (reply){.key = other, .status = 200};
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 1); check_result(&results.items[0], other, true); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }

static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "coinlib %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL,
        };
        size_t failures = allocation_failures;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_alloc_after && allocation_failures == failures + (mode == 4 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned"));
    CHECK(results->items[0].secret_parts == parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "coinlib %s\ncoinlib %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    /* Regex scratch failure is a real positive +1 capture-helper return. */
    br_captures captures = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &captures, false, &error) == 1 && error && !fail_alloc_after);
    CHECK(!strcmp(error, "out of memory iterating regex")); free(error); error = NULL; br_captures_clear(&captures);

    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2};
        steps.rows[0] = (reply){.key = key, .status = 200};
        steps.rows[1] = (reply){.key = other, .status = 200};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0};
        CHECK(!br_finding_key(&prior, 777, "prior", "key"));
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(!br_results_push(&results, &prior));
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error;
        br_json *parts = results.items[0].secret_parts;
        fail_part_after = 2;
        int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, "cannot create Coinlib result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        for (int capture = 0; capture < 2; ++capture) {
            fail_alloc_size = capture ? 17 : 2 * sizeof(br_span); fail_alloc_after = 1;
            rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_alloc_after);
            CHECK(!strcmp(error, capture ? "out of memory copying detector capture" : "out of memory iterating regex"));
            CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls);
            check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        }
        br_results_clear(&results);
    }
    script steps = {.count = 2};
    steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 200};
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], other, true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil(detector); statuses_and_do_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("Coinlib lower-alnum occurrences + borrowed EUR query + all 2xx + send suppression + own rollback");
}
