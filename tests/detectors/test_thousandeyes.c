/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_thousandeyes_init(const br_detector **out, char **error);

static const char key[] = "QRv5GRXQjWmQ6esvXuvk3pcw0IMAw5NO";
static const char email[] = "ejtaK2kkwuVx@1U6Evvih9YeT";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.thousandeyes.com/v6/endpoint-data/user-sessions/web.json"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, "Basic ZWp0YUsya2t3dVZ4QDFVNkV2dmloOVllVDpRUnY1R1JYUWpXbVE2ZXN2WHV2azNwY3cwSU1BdzVOTw=="));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 640 && !request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_thousandeyes_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 640 && detector->max_credential_span == 1024);
    char input[256];
    snprintf(input, sizeof(input), "thousandeyes token - '%s'\nthousandeyes token - '%s'\n", key, email);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 640, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "thousandeyes %s thousandeyes %s thousandeyes %s thousandeyes user2@ab.cd", key, key, email);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 4);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "thousandeyes %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "thousandeyes %s thousandeyes %s", key, email);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == calls);
    http.send_rc = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    return test_finish("thousandeyes");
}
