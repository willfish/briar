/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_scrapingant_init(const br_detector **out, char **error);

static const char key[] = "uifssyi7y40rf7ryyr3vczj8xbhbv49f";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[128];
    snprintf(url, sizeof(url), "https://api.scrapingant.com/v1/general?url=example.com&x-api-key=%s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE && request->detector_type == 560);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !request->body.len);
}

static void expect_fail(const br_detector *detector, const char *input, const char *message)
{
    br_results results = {0};
    br_result prior = {0};
    CHECK(br_finding_key_bytes(&prior, 1, (br_slice){(const unsigned char *)"keep", 4}, "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error));
    CHECK(error && !strcmp(error, message) && results.len == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_scrapingant_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 560 && !strcmp(detector->name, "ScrapingAnt"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "scrapingant"));
    char input[192];
    snprintf(input, sizeof(input), "scrapingant token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 560, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "scrapingant %s | %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "scrapingant%*s%s", 41, "", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    snprintf(input, sizeof(input), "scrapingant %s", key);
    expect_fail(detector, input, "cannot create context from nil parent");

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "scrapingant %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    return test_finish("scrapingant");
}
