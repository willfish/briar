/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[31], other_key[31];
static size_t fail_finding_after;

/* One targeted allocation failure in the real key-part builder. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 30 || len == 5);
    if (len == 30 && fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[31]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 30 && strlen(other_key) == 30);
    CHECK(br_cloudimage_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CloudImage detector output")); free(error); error = NULL;
    CHECK(!br_cloudimage_init(&detector, &error) && detector && !error);
    CHECK(!br_cloudimage_init(&again, NULL) && again == detector);
    CHECK(detector->type == 721 && detector->version == 0 && !strcmp(detector->name, "CloudImage") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "CloudImage is a service that provides image optimization and delivery. CloudImage API keys can be used to access and modify image data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cloudimage"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 721, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!http.calls && !http.releases && results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[32];
    const char *formats[] = {"cloudimage '%s'", "CLOUDIMAGE=-%s-", "prefixClOuDiMaGesuffix\r\n%s", "cloudimage \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); expect_one(detector, input, key);
    }
    expect_one(detector, "", NULL); expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "cloud image %s", key); expect_one(detector, input, NULL);
    const char *bad[] = {"cloudimage _%s", "cloudimage %s_", "cloudimage x%s", "cloudimage %sa", "cloudimage %.29s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); expect_one(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = 'A';
    snprintf(input, sizeof(input), "CLOUDIMAGE %s", changed); expect_one(detector, input, NULL); /* Only keyword is CI. */
    memcpy(changed, key, sizeof(key)); changed[10] = '-';
    snprintf(input, sizeof(input), "cloudimage %s", changed); expect_one(detector, input, NULL);
    memset(changed, '_', 30); changed[30] = '\0';
    snprintf(input, sizeof(input), "cloudimage %s", changed); expect_one(detector, input, changed); /* '_' is a word byte; no hex/entropy filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "cloudimage", 10); memset(input + 10, '.', gap);
        snprintf(input + 10 + gap, sizeof(input) - 10 - gap, "%s", other_key);
        expect_one(detector, input, gap == 40 ? other_key : NULL);
    }
}

typedef struct { const char *key; int status, send_rc; const char *send_error; } reply;
typedef struct {
    reply rows[3]; size_t count; const br_scan_ctx *expected_ctx;
    uint32_t timeout_limit; const char *borrowed_key;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 721 && request->profile == BR_HTTP_SANE);
    if (steps->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= steps->timeout_limit);
    else CHECK(request->timeout_ms == 10000); /* Explicit provider override, NOT SANE's default 5000. */
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.cloudimage.com/invalidate"));
    static const unsigned char payload[] =
        "{\"scope\":\"urls\",\"urls\":[\"/sample.li/paris.jpg?width=400\",\"/sample.li/flat.jpg?width=400\"]}\n\t\t\t";
    _Static_assert(sizeof(payload) - 1 == 94, "pinned CloudImage payload length");
    CHECK(request->body.data && request->body.len == 94 && !memcmp(request->body.data, payload, 94));
    CHECK(request->body.data[90] == '\n' && request->body.data[91] == '\t' && request->body.data[92] == '\t' && request->body.data[93] == '\t');
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Client-Key") && !strcmp(request->headers[1].value, step->key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog")); /* No Accept/Auth/manual Content-Length. */
    steps->borrowed_key = request->headers[1].value;
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain/close error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(http->calls && http->calls <= steps->count);
    CHECK(steps->borrowed_key && !strcmp(steps->borrowed_key, steps->rows[http->calls - 1].key));
    steps->borrowed_key = NULL; /* Complete captured value is still alive during release. */
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
    char input[160]; snprintf(input, sizeof(input), "cloudimage %s\ncloudimage %s\ncloudimage %s", key, key, other_key);
    script steps = {.count = 3, .rows = {{key, 200, 0, NULL}, {key, 201, 0, NULL}, {other_key, 401, 0, NULL}}};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, verify && i < 2);
        br_results_clear(&results); /* Duplicate occurrences are not deduplicated or consumed after success. */
    }
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){i < 2 ? key : other_key, 200, 1, "no such host"};
    for (int retry = 0; retry < 2; ++retry) {
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, false);
        br_results_clear(&results); /* No DNS suppression/cache across candidates or scans. */
    }
    snprintf(input, sizeof(input), "cloudimage %s", key);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        steps = (script){.count = 1, .rows = {{key, statuses[i], 0, NULL}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *errors[] = {"no such host", "net/http: nil Context", "context canceled", "context deadline exceeded",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent",
        "unsupported: redirects for native HTTP POST", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{key, 200, i % 2 ? 1 : -1, errors[i]}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results); /* All shared send/setup/Do errors suppressed, no text classifier/setter. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_timeout(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "cloudimage %s\ncloudimage %s", key, other_key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other_key, false); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0;
        results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 2 && !http.calls && http.releases == (i ? 2u : 0u));
        check_result(&results.items[0], key, false); check_result(&results.items[1], other_key, false); br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "cloudimage %s", key);
    for (int shorter = 0; shorter <= 1; ++shorter) {
        script steps = {.count = 1, .rows = {{key, 200, 0, NULL}}, .timeout_limit = shorter ? 2000 : 0};
        http = (test_http){.inspect = inspect, .user = &steps}; transport = transport_for(&http);
        struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + (shorter ? 2000 : 20000);
        br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline}; steps.expected_ctx = &ctx;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline && !steps.borrowed_key);
        check_result(&results.items[0], key, true); br_results_clear(&results); /* Shorter deadline clamps; longer leaves provider's 10000 unchanged. */
    }
}

static void resource_rollback(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "cloudimage %s\ncloudimage %s", key, other_key);
    script steps = {.count = 2, .rows = {{key, 200, 0, NULL}, {other_key, 201, 0, NULL}}};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
    fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create CloudImage result") && !fail_finding_after);
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
    test_secret(key, 30, 0); test_secret(other_key, 30, 9);
    key[0] = key[15] = key[29] = '_'; other_key[9] = '_';
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); context_and_timeout(detector); resource_rollback(detector);
    return test_finish("CloudImage");
}
