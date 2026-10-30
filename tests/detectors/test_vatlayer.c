/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_vatlayer_init(const br_detector **, char **);

static char key[33];
static const char *body = "{\"vat_number\":\"LU26375245\"}";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char url[128];
    snprintf(url, sizeof(url),
             "https://www.apilayer.net/api/validate?access_key=%s&vat_number=LU26375245&format=1", key);
    CHECK(!strcmp(request->url, url) && request->nheaders == 1 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->headers[0].value, "TruffleHog"));
}

int main(void)
{
    memset(key, 'a', 31);
    key[31] = '1';
    key[32] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_vatlayer_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 496);
    char input[80];
    snprintf(input, sizeof(input), "vatlayer %s", key);
    test_http http = {.inspect = inspect, .response.status = 200,
                      .response.body = {(const unsigned char *)body, strlen(body)}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    const char *restricted = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
    http.response.body = (br_slice){(const unsigned char *)restricted, strlen(restricted)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    http.response.body_error = "read failed";
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    http.response.body_error = NULL;
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    printf("vatlayer: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
