/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_streak_init(const br_detector **out, char **error);

static const char key[] = "bf1949fA2574fb6b2deb94AdA51f0719";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.streak.com/api/v1/pipelines"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, "Basic YmYxOTQ5ZkEyNTc0ZmI2YjJkZWI5NEFkQTUxZjA3MTk6"));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 549 && !request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_streak_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 549 && !strcmp(detector->keywords[0], "streak"));
    char input[160];
    snprintf(input, sizeof(input), "streak token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 549, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "streak %s | %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    const char *upper = "streak bf1949fB2574fb6b2deb94AdA51f0719";
    results = test_scan(detector, NULL, false, upper, strlen(upper));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "streak %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == calls);
    http.send_rc = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    return test_finish("streak");
}
