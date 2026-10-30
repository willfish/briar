/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_worldcoinindex_init(const br_detector **out, char **error);

static const char key[] = "CQ4tKlZUi74jEckzgck4tTdXlLodOqtHdos";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[160];
    snprintf(url, sizeof(url),
             "https://www.worldcoinindex.com/apiservice/ticker?key=%s&label=ethbtc-ltcbtc&fiat=btc", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 415 && request->nheaders == 1 && !request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_worldcoinindex_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 415 && !strcmp(detector->keywords[0], "worldcoinindex"));
    char input[192];
    snprintf(input, sizeof(input), "worldcoinindex token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 415, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "worldcoinindex %s | %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    const char *invalid = "worldcoinindex CQ4tKlZUi74jE?kzgck4tTdXlLodOqtHdos";
    results = test_scan(detector, NULL, false, invalid, strlen(invalid));
    CHECK(results.len == 0);

    const char body[] = "{\"Markets\":[]}";
    test_http http = {.inspect = inspect, .response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "worldcoinindex %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)body, sizeof(body) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    http.response.body_error = "read failed";
    http.response.status = 200;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == calls);
    return test_finish("worldcoinindex");
}
