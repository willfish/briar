/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[41], other_key[41];
static size_t fail_finding_after;

/* Focused provider-finding failure, not a transport error. Captures here are
 * 40 non-NUL ASCII bytes; the ordinary constructor copies the same value. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 40);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[41]; memcpy(copy, value, 40); copy[40] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(other_key) == 40);
    CHECK(br_calorieninja_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid CalorieNinja detector output")); free(error); error = NULL;
    CHECK(!br_calorieninja_init(&detector, &error) && detector && !error);
    CHECK(!br_calorieninja_init(&again, NULL) && again == detector);
    CHECK(detector->type == 474 && detector->version == 0 && !strcmp(detector->name, "CalorieNinja"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "CalorieNinja is a service that provides nutritional information for various foods. CalorieNinja API keys can be used to access this nutritional data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "calorieninja"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, bool verified)
{
    test_key_result(result, 474, secret, "key");
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
    char input[192], changed[41];
    const char *formats[] = {"calorieninja %s", "CALORIENINJA '%s'", "prefixCaLoRiEnInJaSuffix=%s", "calorieninja\r\n%s", "calorieninja \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, key); /* Mixed upper/lower/digits, including non-hex. */
    }
    extraction_case(detector, "", NULL);
    extraction_case(detector, key, NULL);
    const char *bad[] = {"calorieninja _%s", "calorieninja %s_", "calorieninja X%s", "calorieninja %sA", "calorieninja %.39s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[20] = '-';
    snprintf(input, sizeof(input), "calorieninja %s", changed);
    extraction_case(detector, input, NULL);
    memset(changed, 'Z', 40); changed[40] = '\0';
    snprintf(input, sizeof(input), "calorieninja %s", changed);
    extraction_case(detector, input, changed); /* No hex/entropy filter. */
    memset(changed, 'g', 40);
    snprintf(input, sizeof(input), "calorieninja %s", changed);
    extraction_case(detector, input, changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "calorieninja", 12); memset(input + 12, '.', gap);
        snprintf(input + 12 + gap, sizeof(input) - 12 - gap, "%s", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "calorieninja %s %s", key, key);
    extraction_case(detector, input, key); /* First match consumes the only prefix. */
}

typedef struct { const char *keys[3]; size_t len; uint32_t timeout_limit; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.calorieninjas.com/v1/nutrition?query"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 474);
    if (expected->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    else CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3); /* JSON + X-Api-Key + default UA; no Accept or Authorization. */
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && !strcmp(request->headers[1].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    /* Release-count assertion describes ABI1, not upstream's deferred close-only lifecycle. */
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "calorieninja %s\nCALORIENINJA %s\ncalorieninja %s", key, other_key, key);
    expected_requests expected = {.keys = {key, other_key, key}, .len = 3};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
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
    CHECK(results.len == 0); /* Known creation failure skips candidates, not the scan. */
    br_results_clear(&results);
}

static void statuses_and_do_errors(const br_detector *detector)
{
    char input[96], sensitive[128]; snprintf(input, sizeof(input), "calorieninja %s", key);
    snprintf(sensitive, sizeof(sensitive), "synthetic Do/read error X-Api-Key=%s", key);
    expected_requests expected = {.keys = {key}, .len = 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true},
        {299, 0, NULL, true}, {300, 0, NULL, false}, {400, 0, NULL, false}, {401, 0, NULL, false},
        {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "no such host", false}, {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {200, 1, "unsupported: native curl HTTP client profile", false}, {200, 1, NULL, false},
        {200, -1, "net/http: nil Context", false},
        {200, 1, "out of memory creating CalorieNinja result", false},
        {200, 1, "out of memory constructing HTTP headers", false},
    };
    /* Misleading injected error TEXT is not stage identity. These are not
     * proofs about actual adapter allocation failures in the mixed ABI domain. */
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key, cases[i].verified);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "calorieninja %s", key);
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
    CHECK(br_finding_key_bytes(&probe, 474, (br_slice){(const unsigned char *)key, 40}, "key") != 0);
    CHECK(!fail_finding_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1); /* Core failures need not be negative. */
    char input[192]; snprintf(input, sizeof(input), "calorieninja %s\ncalorieninja %s", key, other_key);
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
    CHECK(!fail_finding_after && rc == -1 && error && !strcmp(error, "out of memory creating CalorieNinja result"));
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == saved_raw && !memcmp(saved_raw, "keep", 4));
    CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
    free(error); error = NULL;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == 0 && !error && results.len == 1 && results.items[0].raw.data == saved_raw);
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key, true); check_result(&results.items[1], other_key, true);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 40, 0); key[0] = 'G'; key[20] = 'Z';
    test_secret(other_key, 40, 7); other_key[20] = 'Q';
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences_and_nil_context(detector);
    statuses_and_do_errors(detector);
    context(detector);
    resource_rollback(detector);
    return test_finish("CalorieNinja");
}
