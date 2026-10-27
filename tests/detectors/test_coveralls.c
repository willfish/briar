/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "A7b9C2d5E-F6g8H3j4K-M1n0P2q4R-S6t8U1v";
static const char other[] = "Z9y8X7w6V-U5t4S3r2Q-P1n0M9k8J-H7g6F5e";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;

/* Exercise actual shared-resource failures, not an invented auth allocation. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 37 && strlen(other) == 37);
    CHECK(br_coveralls_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    /* The native prefix helper returns positive failure; the factory normalizes it. */
    fail_alloc_size = sizeof("(?i:coveralls)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_coveralls_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_coveralls_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_coveralls_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 192 && detector->version == 0 && !strcmp(detector->name, "Coveralls"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Coveralls is a web service to help you track your code coverage over time, and ensure that all your new code is fully covered. Coveralls tokens can be used to access and modify coverage data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "coveralls"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 192, expected, "key");
    CHECK(result->raw.len == 37 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 37 && !memcmp(json_object_get_string(part), expected, 37));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[240], changed[39];
    const char *accepted[] = {"coveralls = '%s'", "CoVeRaLlS\r\n%s", "preCOVERALLSsuffix:%s", "coveralls\r%s", "coveralls\n%s", "coveralls-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s coveralls", "cover alls %s", "coveralls%s", "coveralls _%s", "coveralls %s_", "coveralls X%s", "coveralls %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "coveralls%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
        memcpy(input, "coveralls", 9);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 9 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 9 + 2 * gap, key, sizeof(key));
        extraction_case(detector, input, 9 + 2 * gap + 37, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[36] = '\0';
    snprintf(input, sizeof(input), "coveralls %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[37] = 'a'; changed[38] = '\0';
    snprintf(input, sizeof(input), "coveralls %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char disallowed[] = "_.:/";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[15] = disallowed[i];
        snprintf(input, sizeof(input), "coveralls %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    /* Word boundaries are not a ban on endpoint hyphens: a hyphen requires an
     * adjacent outside word byte. Prefix consumption can expose that boundary. */
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "coveralls %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "coverallsX%s", changed); extraction_case(detector, input, strlen(input), changed);
    snprintf(input, sizeof(input), "coveralls%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[36] = '-';
    snprintf(input, sizeof(input), "coveralls %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "coveralls %sX", changed); extraction_case(detector, input, strlen(input), changed);
    changed[0] = '-';
    snprintf(input, sizeof(input), "coverallsX%sY", changed); extraction_case(detector, input, strlen(input), changed);
    const char uuid[] = "aabbccdd-eeff-1122-3344-556677889900";
    snprintf(input, sizeof(input), "coveralls %s", uuid); extraction_case(detector, input, strlen(input), NULL);
    memset(changed, 'a', 37); changed[37] = '\0';
    snprintf(input, sizeof(input), "coveralls %s", changed); extraction_case(detector, input, strlen(input), changed); /* No UUID, entropy or FP filter. */
    memcpy(changed, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a", 38);
    snprintf(input, sizeof(input), "coveralls %s", changed); extraction_case(detector, input, strlen(input), changed); /* Hex is allowed, not required. */
    snprintf(input, sizeof(input), "coveralls %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Non-overlapping whole matches, not all nearby words. */
    int n = snprintf(input, sizeof(input), "coveralls%c%s", 0, key);
    CHECK(n == 47); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%ccoveralls %s%c", 0xff, key, 0xff);
    CHECK(n == 49); extraction_case(detector, input, (size_t)n, key); /* No whole-input UTF-8 guard. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    reply rows[3];
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_auth, *agent_suffix;
    char expected_auth[44];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->expected_ctx && http->releases == at);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 192 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://coveralls.io/api/repos/github/secretscanner02/scanner"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    /* One literal lower-case token auth and the common UA; no Type/Accept/CL. */
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(snprintf(steps->expected_auth, sizeof(steps->expected_auth), "token %s", step->key) == 43);
    CHECK(strlen(request->headers[0].value) == 43 && !memcmp(request->headers[0].value, steps->expected_auth, 44));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->agent_suffix ? "TruffleHog coveralls-offline" : "TruffleHog"));
    steps->borrowed_auth = request->headers[0].value;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){
        .status = step->status,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = "synthetic ignored body read error",
    };
    http->send_error = step->send_error; http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && strlen(steps->borrowed_auth) == 43);
    CHECK(!memcmp(steps->borrowed_auth, steps->expected_auth, 44));
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth);
    return results;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "coveralls %s\nCOVERALLS %s\ncoveralls %s", key, other, key);
    const char *keys[] = {key, other, key};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .agent_suffix = "coveralls-offline"};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = 1, .send_error = "synthetic timeout"};
        steps.rows[1] = (reply){.key = other, .status = 204};
        steps.rows[2] = (reply){.key = key, .status = 299, .send_rc = -7, .send_error = "context canceled"};
        br_results results = run(detector, input, verify, &steps);
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i == 1);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
        br_results_clear(&results);
    }
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "coveralls %s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = status, .nil_body = status % 2 == 0};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = rejected[i]};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create Coveralls result", "synthetic token A7b9C2d5E-F6g8H3j4K-M1n0P2q4R-S6t8U1v", "unsupported native client configuration", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = 2 * sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "coveralls %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL,
        };
        size_t before = allocation_failures;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_alloc_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
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
    char input[112]; snprintf(input, sizeof(input), "coveralls %s\ncoveralls %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures probe = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &probe, false, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&probe);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2};
        steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 200};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; br_results results = {0};
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        for (int failure = 0; failure < 5; ++failure) {
            if (failure == 0) fail_part_after = 2; /* First finding already appended (or nil-ctx skipped). */
            else {
                fail_alloc_size = failure == 1 ? 37 : failure == 2 ? 38 : failure == 3 ? 2 * sizeof(br_span) : 8 * sizeof(char *);
                fail_alloc_after = failure < 3 ? 2 : 1;
            }
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_part_after && !fail_alloc_after);
            const char *expected = failure < 2 ? "cannot create Coveralls result" : failure == 2 ? "out of memory copying detector capture" : failure == 3 ? "out of memory iterating regex" : "out of memory collecting detector captures";
            CHECK(!strcmp(error, expected));
            CHECK(http.calls == (mode == 1 && failure < 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = 0;
        }
        /* A genuine positive +1 append-guard failure is fatal, not a skip. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append Coveralls result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error);
        check_prior(&results, raw, prior_error, parts); br_results_clear(&results);
    }
    script steps = {.count = 2};
    steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 299};
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], other, true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_and_send_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("Coveralls");
}
