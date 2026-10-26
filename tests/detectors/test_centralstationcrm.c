/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[31], other_key[31];
static size_t fail_finding_after;

/* One targeted provider-finding allocation failure, not a Do error. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 30);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[31]; memcpy(copy, value, 30); copy[30] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 30 && strlen(other_key) == 30);
    CHECK(br_centralstationcrm_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid CentralStationCRM detector output")); free(error); error = NULL;
    CHECK(!br_centralstationcrm_init(&detector, &error) && detector && !error);
    CHECK(!br_centralstationcrm_init(&again, NULL) && again == detector);
    CHECK(detector->type == 318 && detector->version == 0 && !strcmp(detector->name, "CentralStationCRM"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "CentralStationCRM is a customer relationship management service. The API keys can be used to access and manage customer data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "centralstationcrm"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, bool verified)
{
    test_key_result(result, 318, secret, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1 : 0) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[31];
    snprintf(input, sizeof(input), "centralstation %s", key);
    CHECK(!strstr(input, detector->keywords[0]));
    extraction_case(detector, input, key); /* Direct scan differs from dispatch; no CLI claim. */
    const char *formats[] = {"CENTRALSTATION '%s'", "centralstationcrm %s", "prefixcEnTrAlStAtIoNSuffix=%s", "centralstation\r\n%s", "centralstation \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, key); /* Includes g-z, not hex-only. */
    }
    extraction_case(detector, "", NULL);
    extraction_case(detector, key, NULL);
    const char *bad[] = {"centralstation _%s", "centralstation %s_", "centralstation x%s", "centralstation %sa", "centralstation %.29s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[20] = 'G';
    snprintf(input, sizeof(input), "CENTRALSTATION %s", changed);
    extraction_case(detector, input, NULL); /* Keyword CI is scoped; capture stays lowercase. */
    changed[20] = '-'; snprintf(input, sizeof(input), "centralstation %s", changed);
    extraction_case(detector, input, NULL);
    memset(changed, 'a', 30); changed[30] = '\0';
    snprintf(input, sizeof(input), "centralstation %s", changed);
    extraction_case(detector, input, changed); /* No entropy filter. */
    const struct { const char *prefix; size_t gap; bool matches; } gaps[] = {
        {"centralstation", 40, true}, {"centralstation", 41, false},
        {"centralstationcrm", 37, true}, {"centralstationcrm", 38, false},
    };
    for (size_t i = 0; i < sizeof(gaps) / sizeof(gaps[0]); ++i) {
        size_t len = strlen(gaps[i].prefix);
        memcpy(input, gaps[i].prefix, len); memset(input + len, '.', gaps[i].gap);
        snprintf(input + len + gaps[i].gap, sizeof(input) - len - gaps[i].gap, "%s", key);
        extraction_case(detector, input, gaps[i].matches ? key : NULL); /* crm consumes three gap bytes. */
    }
    snprintf(input, sizeof(input), "centralstation %s %s", key, key);
    extraction_case(detector, input, key); /* First match consumes the only prefix. */
}

typedef struct { const char *keys[3]; size_t len; uint32_t timeout_limit; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.centralstationcrm.net/api/users.json"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 318);
    if (expected->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    else CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* Canonical X-Apikey + default UA; no Type/Accept/Auth. */
    CHECK(!strcmp(request->headers[0].name, "X-Apikey") && !strcmp(request->headers[0].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    /* Release-count assertion describes ABI1, not scan-deferred Close-only. */
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "centralstation %s\nCENTRALSTATIONCRM %s\ncentralstation %s", key, other_key, key);
    expected_requests expected = {.keys = {key, other_key, key}, .len = 3};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], verify);
        br_results_clear(&results);
    }
    http = (test_http){.send_rc = 1, .send_error = "no such host", .inspect = inspect_request, .user = &expected};
    for (int retry = 0; retry < 2; ++retry) {
        http.calls = http.releases = 0;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], false);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0); br_results_clear(&results); /* Known creation failure skips candidates only. */
}

static void statuses_and_do_errors(const br_detector *detector)
{
    char input[96], sensitive[128]; snprintf(input, sizeof(input), "centralstation %s", key);
    snprintf(sensitive, sizeof(sensitive), "synthetic Do/read error X-apikey=%s", key);
    expected_requests expected = {.keys = {key}, .len = 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true},
        {299, 0, NULL, true}, {300, 0, NULL, false}, {400, 0, NULL, false}, {401, 0, NULL, false},
        {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "no such host", false}, {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {200, 1, "unsupported: native curl HTTP client profile", false}, {200, 1, NULL, false},
        {200, -1, "net/http: nil Context", false},
        {200, 1, "out of memory creating CentralStationCRM result", false},
        {200, 1, "out of memory constructing HTTP headers", false},
    };
    /* Opaque Do-error text is not stage identity. Actual adapter allocation/setup
     * shares this domain; these tests do not claim resource-stage parity. */
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key, cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "centralstation %s", key);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
            .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(&results.items[0], key, false); br_results_clear(&results);
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    expected_requests expected = {.keys = {key}, .len = 1, .timeout_limit = 2000};
    test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    check_result(&results.items[0], key, true); br_results_clear(&results);
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_finding_after = 1;
    CHECK(br_finding_key_bytes(&probe, 318, (br_slice){(const unsigned char *)key, 30}, "key") != 0);
    CHECK(!fail_finding_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1); /* Core errors need not be negative. */
    char input[160]; snprintf(input, sizeof(input), "centralstation %s\ncentralstation %s", key, other_key);
    expected_requests expected = {.keys = {key, other_key}, .len = 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result prior = {.detector_type = 777, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    unsigned char *saved_raw = prior.raw.data; char *saved_error = prior.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0);
    char *error = NULL; fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_finding_after && rc == -1 && error && !strcmp(error, "out of memory creating CentralStationCRM result"));
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == saved_raw && !memcmp(saved_raw, "keep", 4));
    CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == saved_raw);
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 30, 0); key[0] = 'g';
    test_secret(other_key, 30, 7); other_key[0] = 'z';
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences_and_nil_context(detector);
    statuses_and_do_errors(detector);
    context(detector);
    resource_rollback(detector);
    return test_finish("CentralStationCRM");
}
