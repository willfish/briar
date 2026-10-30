/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_repairshopr_init(const br_detector **, char **);

static char key[52], expected[128];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 702);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.sugester+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, key));
}

static void exercise(const br_detector *detector)
{
    char input[160];
    test_http http = {.inspect = inspect, .user = expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "repairshopr shop1 %s", key);
    snprintf(expected, sizeof(expected), "https://shop1.repairshopr.com/api/v1/appointment_types");
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls);
    test_key_result(&out.items[0], 702, key, "key");
    br_results_clear(&out);
    http.response = (br_http_response){.status = 200};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 500};
    http.calls = http.releases = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "repairshopr shop1 %s\nrepairshopr other2", key);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
}

int main(void)
{
    for (int i = 0; i < 51; ++i) key[i] = "abcDEF012xyz"[(size_t)i % 12];
    key[51] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_repairshopr_init(&detector, &error) == 0 && detector->type == 702 && detector->max_credential_span == 1024);
    exercise(detector);
    return test_finish("Repairshopr");
}
