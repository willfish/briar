/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "AbCdEfGhIjKlMnOpQr90";
static const char other_key[] = "z9Y8x7W6v5U4t3S2r1Q0";
static size_t fail_finding_after;

/* One targeted failure in the actual key-part allocation, not an auth copy. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 20 || len == 5);
    if (len == 20 && fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[21]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 20 && strlen(other_key) == 20);
    CHECK(br_codacy_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Codacy detector output")); free(error); error = NULL;
    CHECK(!br_codacy_init(&detector, &error) && detector && !error);
    CHECK(!br_codacy_init(&again, NULL) && again == detector);
    CHECK(detector->type == 185 && detector->version == 0 && !strcmp(detector->name, "Codacy") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Codacy is an automated code review tool that helps developers and teams improve code quality. Codacy API tokens can be used to access and manage code quality reports and settings."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "codacy"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 185, expected, "key");
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
    char input[192], changed[22];
    const char *formats[] = {"codacy '%s'", "CODACY=-%s-", "prefixCoDaCysuffix\r\n%s", "codacy \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); expect_one(detector, input, key);
    }
    snprintf(input, sizeof(input), "codacy %s", other_key); expect_one(detector, input, other_key); /* Upper/lower G-Z and digits, not hex. */
    expect_one(detector, "", NULL); expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "coda cy %s", key); expect_one(detector, input, NULL);
    const char *bad[] = {"codacy _%s", "codacy %s_", "codacy x%s", "codacy %sa", "codacy %.19s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); expect_one(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[10] = '_';
    snprintf(input, sizeof(input), "codacy %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = '-';
    snprintf(input, sizeof(input), "codacy %s", changed); expect_one(detector, input, NULL);
    memset(changed, 'a', 20); changed[20] = '\0';
    snprintf(input, sizeof(input), "codacy %s", changed); expect_one(detector, input, changed); /* No entropy filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "codacy", 6); memset(input + 6, '.', gap);
        snprintf(input + 6 + gap, sizeof(input) - 6 - gap, "%s", key);
        expect_one(detector, input, gap == 40 ? key : NULL);
    }
}

typedef struct { const char *key; int status, send_rc; const char *send_error; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *expected_ctx; const char *borrowed_key; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 185 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://app.codacy.com/api/v3/user"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Api-Token") && !strcmp(request->headers[1].value, step->key)); /* Exact Go canonical case, no Bearer/Authorization. */
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog")); /* No Type/logical Content-Length. */
    steps->borrowed_key = request->headers[1].value;
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain/close error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(http->calls && http->calls <= steps->count);
    CHECK(steps->borrowed_key && strlen(steps->borrowed_key) == 20 && !memcmp(steps->borrowed_key, steps->rows[http->calls - 1].key, 20));
    steps->borrowed_key = NULL; /* Complete capture remains borrowed and alive through release. */
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == (verify ? steps->count : 0) && http.releases == http.calls && !steps->borrowed_key);
    return results;
}

static void verification(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "codacy %s\ncodacy %s\ncodacy %s", key, key, other_key);
    script steps = {.count = 3, .rows = {{key, 200, 0, NULL}, {key, 201, 0, NULL}, {other_key, 401, 0, NULL}}};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, verify && i < 2);
        br_results_clear(&results); /* Duplicate occurrences and later candidates survive earlier success. */
    }
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){i < 2 ? key : other_key, 200, 1, "no such host"};
    for (int retry = 0; retry < 2; ++retry) {
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, false);
        br_results_clear(&results); /* No cache, DNS suppression or consumption. */
    }
    snprintf(input, sizeof(input), "codacy %s", key);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        steps = (script){.count = 1, .rows = {{key, statuses[i], 0, NULL}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *errors[] = {"no such host", "net/http: nil Context", "context canceled", "context deadline exceeded",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent", "unsupported: native SANE policy", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{key, 200, i % 2 ? 1 : -1, errors[i]}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results); /* Suppress all shared send errors, no stage-text classifier/setter. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void contexts(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "codacy %s\ncodacy %s", key, other_key);
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
}

static void resource_rollback(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "codacy %s\ncodacy %s", key, other_key);
    script steps = {.count = 2, .rows = {{key, 200, 0, NULL}, {other_key, 299, 0, NULL}}};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
    fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create Codacy result") && !fail_finding_after);
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1 && !steps.borrowed_key);
    CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
    CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); contexts(detector); resource_rollback(detector);
    return test_finish("Codacy");
}
