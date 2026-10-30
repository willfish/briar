/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_tly_init(const br_detector **, char **);

static char key[61];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char authorization[80];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(!strcmp(request->url, "https://api.t.ly/api/v1/link/list"));
    CHECK(request->nheaders == 3 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog"));
}

int main(void)
{
    memset(key, 'a', 60);
    key[60] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tly_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 586 && !strcmp(detector->name, "TLy"));
    char input[160];
    snprintf(input, sizeof(input), "tly %s tly %s", key, key);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    test_key_result(&results.items[0], 586, key, "key");
    br_results_clear(&results);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    char *scan_error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &scan_error) == 0 && !scan_error && results.len == 1);
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "nil Context"));
    br_results_clear(&results);
    printf("tly: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
