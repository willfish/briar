/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_weatherbit_init(const br_detector **out, char **error);

static const char key[] = "zqjxo96wmdi1rdcvohnpu0v3bkypbuti";
static const char url[] = "https://api.weatherbit.io/v2.0/history/airquality?lat=38.0&lon=-78.0&key=zqjxo96wmdi1rdcvohnpu0v3bkypbuti";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 597);
    CHECK(request->nheaders == 2 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog weatherbit-offline"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_weatherbit_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 597 && !strcmp(detector->name, "WeatherBit"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "weatherbit"));
    CHECK(!strcmp(detector->description,
        "Weatherbit is a weather data service provider. Weatherbit API keys can be used to access weather data and related services."));
    CHECK(br_weatherbit_init(NULL, &error) != 0 && error); free(error);
    char input[128];
    snprintf(input, sizeof(input), "weatherbit token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 597, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "weatherbit keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "weatherbit = '%s'", "zqjx?96wmdi1rdcvohnpu0v3bkypbuti");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "WEATHERBIT %s weatherbit %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2); br_results_clear(&results);
    snprintf(input, sizeof(input), "weatherbit %s", key);
    test_http http = {.response = {.status = 299, .body_error = "ignored"}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "weatherbit-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 400; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 1; http.send_error = url; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    return test_finish("WeatherBit");
}
