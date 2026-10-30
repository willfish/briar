/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_salesmate_init(const br_detector **, char **);

static const char key[] = "A1234567-89ab-4def-8123-456789abcdef";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->url, "https://shop.salesmate.io/apis/v3/companies/1?trackingRecentSearch=true"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "sessionToken") && !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_salesmate_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 868 && detector->max_credential_span == 1024);
    char input[96];
    snprintf(input, sizeof(input), "salesmate shop %s", key);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    test_key_result(&results.items[0], 868, key, "key");
    CHECK(json_object_object_length(results.items[0].secret_parts) == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    printf("salesmate: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
