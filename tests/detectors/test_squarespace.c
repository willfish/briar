/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_squarespace_init(const br_detector **, char **);

static const char key[] = "A1234567-89ab-4def-8123-456789abcdef";
static const char bad[] = "B1234567-89ab-4def-8123-456789abcdef";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->url, "https://api.squarespace.com/1.0/profiles?sortField=email&sortDirection=asc&filter=isCustomer,true;hasAccount,true"));
    CHECK(request->nheaders == 3 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "YOUR_CUSTOM_APP_DESCRIPTION"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, "Bearer A1234567-89ab-4def-8123-456789abcdef"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

int main(void)
{
    CHECK(strlen(key) == 36 && strlen(bad) == 36);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_squarespace_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 264 && !strcmp(detector->name, "Squarespace"));
    char input[96];
    snprintf(input, sizeof(input), "squarespace %s", key);
    test_http http = {.inspect = inspect, .response.status = 204};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    test_key_result(&results.items[0], 264, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "squarespace %s", bad);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 1);
    snprintf(input, sizeof(input), "squarespace %s", key);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    printf("squarespace: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
