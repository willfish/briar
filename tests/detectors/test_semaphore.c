/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_semaphore_init(const br_detector **, char **);

static char key[33], letters[33];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char url[96];
    snprintf(url, sizeof(url), "https://api.semaphore.co/api/v4/account?apikey=%s", key);
    CHECK(!strcmp(request->url, url) && request->timeout_ms == 5000);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].value, "application/vnd.semaphore+json; version=3"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog"));
}

int main(void)
{
    memcpy(key, "abcdefghijklmnopqrstuvwxyz012345", 33);
    memcpy(letters, "abcdefghijklmnopqrstuvwxyzabcdef", 33);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_semaphore_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 609 && !strcmp(detector->keywords[0], "semaphore.co"));
    char input[128];
    snprintf(input, sizeof(input), "semaphore %s", key);
    test_http http = {.inspect = inspect, .response.status = 200,
                      .response.body = {(const unsigned char *)"{\"account_id\":1}", 16}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 609, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "semaphore %s", letters);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    snprintf(input, sizeof(input), "semaphore.co %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    http.response.body = (br_slice){(const unsigned char *)"account_id", 10};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    http.response.body_error = "read failed";
    http.response.status = 200;
    size_t calls = http.calls;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls + 1 && http.releases == calls + 1);
    http.response.body_error = NULL;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    printf("semaphore: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
