/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_zipapi_init(const br_detector **, char **);

static char key[33], expected[128];
static char auths[2][160];
static size_t seen;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, (const char *)http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 599);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    if (seen < 2) snprintf(auths[seen], sizeof(auths[seen]), "%s", request->headers[1].value);
    ++seen;
}

static void exercise(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "zipapi a@bc.de b@cd.ef secret1 %s", key);
    test_http http = {.inspect = inspect, .user = expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls);
    test_key_result(&out.items[0], 599, key, "key");
    test_key_result(&out.items[1], 599, key, "key");
    br_results_clear(&out);
    snprintf(expected, sizeof(expected), "https://service.zipapi.us/zipcode/90210/?X-API-KEY=%s", key);
    http.response = (br_http_response){.status = 200};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].verified && out.items[1].verified && http.calls == 2 && seen == 2);
    CHECK(strcmp(auths[0], auths[1]));
    br_results_clear(&out);
    seen = 0;
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 401};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 403};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && !out.items[1].verified && !out.items[1].verification_error);
    br_results_clear(&out);
    http.response = (br_http_response){.status = 500};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 2 && !http.calls && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
}

int main(void)
{
    for (int i = 0; i < 32; ++i) key[i] = "abcdefghijklmnopqrstuvwxyz012345"[(size_t)i];
    key[32] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zipapi_init(&detector, &error) == 0 && detector->type == 599 && detector->max_credential_span == 1024);
    exercise(detector);
    return test_finish("ZipAPI");
}
