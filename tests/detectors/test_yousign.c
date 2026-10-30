/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_yousign_init(const br_detector **, char **);

static char key[33];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char authorization[48];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (http->calls == 1) CHECK(!strcmp(request->url, "https://api.yousign.com/users"));
    else CHECK(!strcmp(request->url, "https://staging-api.yousign.com/users"));
    CHECK(request->nheaders == 3 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog"));
    if (strstr(request->url, "staging")) http->response.status = 200;
}

int main(void)
{
    memset(key, 'a', 32);
    key[32] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_yousign_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 342 && !strcmp(detector->name, "YouSign"));
    char input[64];
    snprintf(input, sizeof(input), "yousign %s", key);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 2);
    br_results_clear(&results);
    http.send_rc = -1;
    http.send_error = "dial failed";
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.send_rc = 0;
    http.send_error = NULL;
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    printf("yousign: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
