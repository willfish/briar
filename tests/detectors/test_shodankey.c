/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_shodankey_init(const br_detector **, char **);

static char key[33], expected[96];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 88);
    CHECK(request->nheaders == 1 && !request->body.data);
}

static void exercise(const br_detector *detector)
{
    char input[128];
    test_http http = {.inspect = inspect, .user = expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "shodan %s shodan %s", key, key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    test_key_result(&out.items[0], 88, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "shodan %s", key);
    snprintf(expected, sizeof(expected), "https://api.shodan.io/api-info?key=%s", key);
    const char *bodies[] = {"{\"plan\":\"dev\"}", "null", "{}", "[]", "not-json", ""};
    const bool verified[] = {true, true, true, false, false, false};
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0; http.send_error = NULL;
        http.response = (br_http_response){
            .status = 200,
            .body = {(const unsigned char *)bodies[i], strlen(bodies[i])},
        };
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && out.items[0].verified == verified[i] && !out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{}", 2}, .body_error = "read failed"};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 500, .body = {(const unsigned char *)"{}", 2}};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified);
    br_results_clear(&out);
    http.send_rc = 1; http.send_error = "timeout";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.send_rc = 0; http.send_error = NULL; http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
}

int main(void)
{
    for (size_t i = 0; i < 32; ++i) key[i] = "abcdef0123456789ABCDEF"[(i) % 22];
    key[32] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shodankey_init(&detector, &error) == 0 && detector->type == 88 && detector->nkeywords == 1);
    CHECK(!strcmp(detector->keywords[0], "shodan"));
    exercise(detector);
    return test_finish("ShodanKey");
}
