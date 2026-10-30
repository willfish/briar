/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_restpackscreenshotapi_init(const br_detector **, char **);

static char key[49];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://restpack.io/api/screenshot/usage"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Access-Token") && !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog"));
}

int main(void)
{
    memset(key, 'a', 48);
    key[48] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_restpackscreenshotapi_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 518 && !strcmp(detector->keywords[0], "restpack"));
    char input[160];
    snprintf(input, sizeof(input), "restpack %s", key);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    test_key_result(&results.items[0], 518, key, "key");
    br_results_clear(&results);
    results = test_scan(detector, &ctx, false, key, 48);
    CHECK(!results.len);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = -1;
    http.send_error = "dial failed";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    snprintf(input, sizeof(input), "restpack %s restpack %s", key, key);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    printf("restpackscreenshotapi: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
