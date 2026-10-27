/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static const char key[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char other[] = "987654zyxwvutsrqponmlkjihgfedcba";
static bool track_basic;
static size_t basic_allocations, fail_basic_after;

/* Basic("api-key", KEY32) actually owns 7+4*ceil(40/3)=63 bytes.
 * Count/fail that necessary helper allocation, not an invented auth copy.
 * Zero-filled forwarding memory remains a valid malloc result. */
void *malloc(size_t size)
{
    if (track_basic && size == 63) {
        ++basic_allocations;
        if (fail_basic_after && --fail_basic_after == 0) return NULL;
    }
    return calloc(1, size);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_clinchpad_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Clinchpad detector output")); free(error); error = NULL;
    CHECK(!br_clinchpad_init(&detector, &error) && detector && !error);
    CHECK(!br_clinchpad_init(&again, NULL) && again == detector);
    CHECK(detector->type == 255 && detector->version == 0 && !strcmp(detector->name, "Clinchpad") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Clinchpad is a CRM tool. Clinchpad API keys can be used to access and modify data within Clinchpad."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "clinchpad"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 255, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    basic_allocations = 0; track_basic = true;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input)); track_basic = false;
    CHECK(!basic_allocations && !http.calls && !http.releases && results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[34];
    const char *formats[] = {"clinchpad '%s'", "CLINCHPAD=-%s-", "prefixClInChPaDsuffix\r\n%s", "clinchpad \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key); expect_one(detector, input, key);
    }
    expect_one(detector, "", NULL); expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "clinch pad %s", key); expect_one(detector, input, NULL);
    const char *bad[] = {"clinchpad _%s", "clinchpad %s_", "clinchpad x%s", "clinchpad %sa", "clinchpad %.31s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key); expect_one(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = 'A';
    snprintf(input, sizeof(input), "CLINCHPAD %s", changed); expect_one(detector, input, NULL); /* Keyword CI cannot widen the capture. */
    memcpy(changed, key, sizeof(key)); changed[10] = '_';
    snprintf(input, sizeof(input), "clinchpad %s", changed); expect_one(detector, input, NULL);
    memset(changed, 'z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "clinchpad %s", changed); expect_one(detector, input, changed); /* Lower alnum, not hex; no entropy filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "clinchpad", 9); memset(input + 9, '.', gap);
        snprintf(input + 9 + gap, sizeof(input) - 9 - gap, "%s", other);
        expect_one(detector, input, gap == 40 ? other : NULL);
    }
}

typedef struct { const char *key, *send_error; int status, send_rc; } reply;
typedef struct {
    reply rows[3]; size_t count; const br_scan_ctx *expected_ctx;
    const char *authorization; /* Borrowed through release, never copied in the provider. */
} script;

static void check_authorization(const char *value, const char *password)
{
    CHECK(value && strlen(value) == 62 && !memcmp(value, "Basic ", 6));
    CHECK(value[60] == '=' && value[61] == '=');
    unsigned char plain[48];
    CHECK(EVP_DecodeBlock(plain, (const unsigned char *)value + 6, 56) == 42);
    CHECK(!memcmp(plain, "api-key:", 8) && !memcmp(plain + 8, password, 32)); /* Exactly 40 bytes after removing two padding bytes. */
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 255 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.clinchpad.com/api/v1/pipelines"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* Basic + UA only; no Type/Accept/logical Content-Length. */
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    steps->authorization = request->headers[0].value; check_authorization(steps->authorization, step->key);
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain/close error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(http->calls && http->calls <= steps->count);
    check_authorization(steps->authorization, steps->rows[http->calls - 1].key); /* Still complete and alive during release. */
    steps->authorization = NULL;
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    basic_allocations = 0; track_basic = true;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); track_basic = false;
    CHECK(http.calls == (verify ? steps->count : 0) && http.releases == http.calls);
    CHECK(basic_allocations == (verify ? steps->count : 0) && !steps->authorization);
    return results;
}

static void occurrences_and_verification(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "clinchpad %s\nclinchpad %s\nclinchpad %s", key, key, other);
    script steps = {.count = 3, .rows = {{key, NULL, 200, 0}, {key, NULL, 201, 0}, {other, NULL, 401, 0}}};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = run(detector, input, verify, &steps);
        CHECK(results.len == 3); /* Occurrences, including duplicate credentials; success never consumes/breaks. */
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, verify && i < 2);
        br_results_clear(&results);
    }
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){i < 2 ? key : other, "no such host", 200, 1};
    for (int retry = 0; retry < 2; ++retry) {
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], steps.rows[i].key, false);
        br_results_clear(&results); /* No DNS suppression/cache, within or across scans. */
    }
    snprintf(input, sizeof(input), "clinchpad %s", key);
    const int statuses[] = {199, 200, 201, 204, 206, 299, 300, 401, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        steps = (script){.count = 1, .rows = {{key, NULL, statuses[i], 0}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *errors[] = {"no such host", "context canceled", "context deadline exceeded", "net/http: nil Context",
        "out of memory constructing HTTP headers", "out of memory constructing HTTP user agent",
        "out of memory constructing Basic authentication", "unsupported: native SANE policy", key, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{key, errors[i], 200, i % 2 ? 1 : -1}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results); /* No setter or error-text stage classifier. */
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "clinchpad %s\nclinchpad %s", key, other);
    fail_basic_after = 1; basic_allocations = 0; track_basic = true;
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); track_basic = false;
    CHECK(results.len == 2 && !basic_allocations && fail_basic_after == 1); fail_basic_after = 0;
    check_result(&results.items[0], key, false); check_result(&results.items[1], other, false); br_results_clear(&results);
    basic_allocations = 0; track_basic = true;
    results = test_scan(detector, NULL, true, input, strlen(input)); track_basic = false;
    CHECK(!results.len && basic_allocations == 2); br_results_clear(&results); /* Prep first, then constructor SKIP for each occurrence. */
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; basic_allocations = 0; track_basic = true;
        results = test_scan(detector, &contexts[i], true, input, strlen(input)); track_basic = false;
        CHECK(results.len == 2 && basic_allocations == 2 && !http.calls && http.releases == (i ? 2u : 0u));
        check_result(&results.items[0], key, false); check_result(&results.items[1], other, false); br_results_clear(&results);
    }

    const br_slice username = {(const unsigned char *)"api-key", 7}, password = {(const unsigned char *)key, 32};
    char *authorization = NULL, *error = NULL; basic_allocations = 0; fail_basic_after = 1; track_basic = true;
    int rc = br_http_basic_auth(username, password, &authorization, &error); track_basic = false;
    CHECK(rc == 1 && !authorization && !fail_basic_after && basic_allocations == 1 && error && !strcmp(error, "out of memory constructing Basic authentication")); free(error);
    for (int nil_context = 0; nil_context <= 1; ++nil_context) {
        script steps = {.count = 2, .rows = {{key, NULL, 200, 0}, {other, NULL, 299, 0}}};
        http = (test_http){.inspect = inspect, .user = &steps}; transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && !br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        basic_allocations = 0; fail_basic_after = 2; track_basic = true; error = NULL;
        rc = detector->scan(detector, nil_context ? NULL : &ctx, true,
            (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); track_basic = false;
        CHECK(rc == -1 && error && !strcmp(error, "out of memory constructing Basic authentication"));
        CHECK(!fail_basic_after && basic_allocations == 2 && results.len == 1 && http.calls == (nil_context ? 0u : 1u) && http.releases == http.calls);
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
        free(error); br_results_clear(&results);
        http.calls = http.releases = 0; basic_allocations = 0; track_basic = true;
        results = test_scan(detector, nil_context ? NULL : &ctx, true, input, strlen(input)); track_basic = false;
        CHECK(results.len == (nil_context ? 0u : 2u) && basic_allocations == 2 && http.calls == (nil_context ? 0u : 2u) && http.releases == http.calls);
        if (!nil_context) { check_result(&results.items[0], key, true); check_result(&results.items[1], other, true); }
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_verification(detector); context_and_resource(detector);
    return test_finish("Clinchpad");
}
