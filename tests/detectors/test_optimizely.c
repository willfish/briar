/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_optimizely_init(const br_detector **out, char **error);

static const char key[] = "Ab3-def:0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd123456";
static const char other[] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 54 && strlen(other) == 54);
    CHECK(br_optimizely_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_optimizely_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 595 && !strcmp(detector->name, "Optimizely"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Optimizely is a platform for A/B testing and feature flagging. Optimizely API keys can be used to manage and access these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "optimizely"));
    CHECK(detector->scan && detector->state && !detector->clean && !detector->false_positive);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 595, expected, "key");
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
    char input[160];
    snprintf(input, sizeof(input), "optimizely %s", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "OPTIMIZELY:%s", key);
    expect_one(detector, input, key);
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "optimizely %s_", key);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "optimizely %.53s", key);
    expect_one(detector, input, NULL);
    memcpy(input, "optimizely", 10);
    memset(input + 10, '-', 40);
    memcpy(input + 50, other, 55);
    expect_one(detector, input, other);
    input[10 + 40] = 'x';
    memcpy(input + 51, other, 55);
    expect_one(detector, input, NULL);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char bearer[64];
    snprintf(bearer, sizeof(bearer), "Bearer %s", key);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.optimizely.com/v2/projects"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 595 && request->nheaders == 2 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, bearer));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "optimizely %s", key);
    test_http http = {.inspect = inspect, .response = {.status = 204}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);
    http = (test_http){.inspect = inspect, .response = {.status = 401}, .send_rc = 0};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.releases == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    http = (test_http){.send_rc = -1, .send_error = "context deadline exceeded", .response = {.status = 200}};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.releases == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("optimizely");
}
