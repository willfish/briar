/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_walkscore_init(const br_detector **, char **);

static char key[33], expected[180];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 475);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
}

static void exercise(const br_detector *detector)
{
    char input[96];
    test_http http = {.inspect = inspect, .user = expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "walkscore %s", key);
    snprintf(expected, sizeof(expected),
             "https://transit.walkscore.com/transit/search/stops/?lat=47.6101359&lon=-122.3420567&wsapikey=%s", key);
    static const char body[] = "{\"distance\":12}";
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 1);
    br_results_clear(&out);
    http.response.body = (br_slice){(const unsigned char *)"{\"miles\":1}", 11};
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 200, .body_error = "read failed",
                                       .body = {(const unsigned char *)body, sizeof(body) - 1}};
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!out.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 500};
    http.send_rc = 1; http.send_error = "timeout"; http.calls = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.send_rc = 0; http.send_error = NULL; http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
}

int main(void)
{
    for (int i = 0; i < 32; ++i) key[i] = "abcdefghijklmnopqrstuvwxyz012345"[(size_t)i];
    key[32] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_walkscore_init(&detector, &error) == 0 && detector->type == 475);
    exercise(detector);
    return test_finish("WalkScore");
}
