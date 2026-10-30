/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_timezoneapi_init(const br_detector **out, char **error);

static const char key[] = "AbcdefghijKLMNOPQrst";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_timezoneapi_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_timezoneapi_init(&detector, &error) == 0 && !error && detector->type == 289);
    CHECK(!strcmp(detector->name, "Timezoneapi") && !strcmp(detector->keywords[0], "timezoneapi"));
    CHECK(!strcmp(detector->description, "Timezoneapi is a service that provides time zone information. Timezoneapi keys can be used to access and retrieve time zone data."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[64];
    snprintf(url, sizeof(url), "https://timezoneapi.io/api/ip/?token=%s", (const char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 289);
    CHECK(!request->nheaders || (request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent")));
    CHECK(!request->body.len);
}

static void extraction(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "timezoneapi token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 289, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s timezoneapi", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "timezoneapi %s1", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "TIMEZONEAPI %s\ntimezoneapi %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[80], two[160];
    snprintf(input, sizeof(input), "timezoneapi %s", key);
    snprintf(two, sizeof(two), "timezoneapi %s\ntimezoneapi %s", key, key);
    const unsigned char dated[] = "zone\ndate: today\n";
    const unsigned char missing[] = "{\"ok\":true}";
    const struct { int status; const unsigned char *body; size_t len; const char *read_error; bool verified; } cases[] = {
        {200, dated, sizeof(dated) - 1, NULL, true},
        {299, dated, sizeof(dated) - 1, NULL, true},
        {200, missing, sizeof(missing) - 1, NULL, false},
        {401, dated, sizeof(dated) - 1, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {cases[i].body, cases[i].len}}, .inspect = inspect, .user = (void *)key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http failed = {.send_rc = 1, .send_error = "context deadline exceeded", .inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&failed);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    test_http broken = {.response = {.status = 200, .body = {(const unsigned char *)"date", 4}, .body_error = "read reset"}, .inspect = inspect, .user = (void *)key};
    transport = test_transport(&broken);
    ctx = (br_scan_ctx){.transport = &transport};
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)two, strlen(two)}, &results, &error) != 0);
    CHECK(error && !strcmp(error, "read reset") && results.len == 0 && broken.calls == 1 && broken.releases == 1);
    free(error);
    br_results_clear(&results);

    char huge[65538];
    memset(huge, 'd', sizeof(huge));
    test_http long_line = {.response = {.status = 200, .body = {(const unsigned char *)huge, sizeof(huge)}}, .inspect = inspect, .user = (void *)key};
    transport = test_transport(&long_line);
    ctx = (br_scan_ctx){.transport = &transport};
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && !strcmp(error, "bufio.Scanner: token too long") && results.len == 0);
    free(error);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Timezoneapi");
}
