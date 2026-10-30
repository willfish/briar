/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_zonkafeedback_init(const br_detector **, char **);

static char key[37];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->url, "https://app-us1.zonkafeedback.com/responses?page=1&limit=25&startDate=2020-05-02&endDate=2020-05-09"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Z-API-TOKEN"));
    CHECK(!strcmp(request->headers[0].value, key) && !strcmp(request->headers[1].value, "TruffleHog"));
}

int main(void)
{
    memset(key, 'A', 36);
    key[36] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zonkafeedback_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 236 && !strcmp(detector->keywords[0], "zonka"));
    char input[128];
    snprintf(input, sizeof(input), "zonka %s zonka %s", key, key);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified && http.calls == 2);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(strstr(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);
    char *scan_error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &scan_error) == 0 && results.len == 2 && !scan_error);
    CHECK(strstr(results.items[0].verification_error, "nil Context") && !strstr(results.items[0].verification_error, key));
    br_results_clear(&results);
    printf("zonkafeedback: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
