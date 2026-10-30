/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_marketstack_init(const br_detector **out, char **error);

static const char key[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char other[] = "0123456789abcdef0123456789abcdef";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_marketstack_init(NULL, &error) == -1 && error &&
          !strcmp(error, "invalid Marketstack detector output"));
    free(error);
    error = NULL;
    CHECK(!br_marketstack_init(&detector, &error) && detector && !error);
    CHECK(!br_marketstack_init(&again, NULL) && again == detector);
    CHECK(detector->type == 363 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Marketstack") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Marketstack is a service that provides real-time market data. Marketstack API keys can be used to access this data and perform various operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "marketstack"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 363, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[33];
    const char *formats[] = {"marketstack %s", "MARKETSTACK=%s", "xxMarketStackyy\n%s", "marketstack\t%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        expect_one(detector, input, key);
    }
    expect_one(detector, key, NULL);
    expect_one(detector, "", NULL);
    snprintf(input, sizeof(input), "market stack %s", key);
    expect_one(detector, input, NULL);
    memcpy(changed, key, 33);
    changed[0] = 'A';
    snprintf(input, sizeof(input), "marketstack %s", changed);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "marketstack %s extra", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "marketstack x%s", key);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "marketstack %.31s", key);
    expect_one(detector, input, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "marketstack", 11);
        memset(input + 11, '.', gap);
        memcpy(input + 11 + gap, other, 33);
        expect_one(detector, input, gap == 40 ? other : NULL);
    }
    snprintf(input, sizeof(input), "marketstack %s marketstack %s", key, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false);
    check_result(&results.items[1], key, false);
    br_results_clear(&results);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char expected[96];
    snprintf(expected, sizeof(expected),
             "https://api.marketstack.com/v1/eod?access_key=%s&symbols=AAPL", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, expected));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 363 && request->nheaders == 1 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog"));
}

static bool stop(void *user)
{
    (void)user;
    return true;
}

static void verification(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "marketstack %s", key);
    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);

    const int statuses[] = {199, 200, 299, 300, 401, 500};
    const bool verified[] = {false, true, true, false, false, false};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http = (test_http){.inspect = inspect, .response = {.status = statuses[i]}};
        transport = test_transport(&http);
        ctx = (br_scan_ctx){.transport = &transport};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key, verified[i]);
        br_results_clear(&results);
    }
    http = (test_http){.inspect = inspect, .send_rc = 1, .send_error = "no such host",
                       .response = {.status = 200}};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls && !http.releases);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);

    http = (test_http){.inspect = inspect};
    transport = test_transport(&http);
    br_scan_ctx done = {.transport = &transport, .cancelled = stop, .deadline_monotonic_ms = 1};
    results = test_scan(detector, &done, true, input, strlen(input));
    CHECK(results.len == 1 && !http.calls && http.releases == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

static void invalid_scan(const br_detector *detector)
{
    char *error = NULL;
    br_results results = {0};
    CHECK(detector->scan(NULL, NULL, false, (br_slice){0}, &results, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){0}, NULL, &error) == -1 && error);
    free(error);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    invalid_scan(detector);
    return test_finish("marketstack");
}
