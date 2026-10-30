/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_scrapingbee_init(const br_detector **, char **);

static char key[81], flat[81], expected[256];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 139);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!request->body.data);
}

static void exercise(const br_detector *detector)
{
    char input[400], gap[48];
    test_http http = {.inspect = inspect, .user = expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "scrapingbee %s scraping-bee %s", key, key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls);
    test_key_result(&out.items[0], 139, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "scraping_bee %s", flat);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "scraping bee %s", key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    memset(gap, ' ', 41); gap[41] = 0;
    snprintf(input, sizeof(input), "scrapingbee%s%s", gap, key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "scrapingbee %s", key);
    snprintf(expected, sizeof(expected),
             "https://app.scrapingbee.com/api/v1/?api_key=%s&url=https://httpbin.org/anything?json&render_js=false", key);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, "unexpected status code: 403"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0; http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && out.items[0].verified == cases[i].verified);
        if (cases[i].cause) CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, cases[i].cause));
        else CHECK(!out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
}

int main(void)
{
    for (size_t i = 0; i < 80; ++i) {
        key[i] = "ABCDEFGHIJKLMNOP"[(i) % 16];
        flat[i] = 'A';
    }
    key[80] = flat[80] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_scrapingbee_init(&detector, &error) == 0 && detector && detector->nkeywords == 4);
    CHECK(!strcmp(detector->keywords[1], "scraping bee") && detector->max_credential_span == -1);
    exercise(detector);
    return test_finish("ScrapingBee");
}
