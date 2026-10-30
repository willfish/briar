/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <string.h>

int br_siteleaf_init(const br_detector **, char **);

static char key[33], other[33];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.siteleaf.com/v2/sites"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 263);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Basic ", 6));
    (void)http;
}

static void exercise(const br_detector *detector)
{
    char input[160], upper[33];
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "siteleaf %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls);
    test_key_result(&out.items[0], 263, key, "key");
    br_results_clear(&out);
    memset(upper, 'B', 32); upper[32] = 0;
    snprintf(input, sizeof(input), "siteleaf %s", upper);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "siteleaf %s\nsiteleaf %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 4);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "siteleaf %s", key);
    http.response = (br_http_response){.status = 200};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 1);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
}

int main(void)
{
    for (int i = 0; i < 32; ++i) {
        key[i] = 'a' + (i % 26);
        other[i] = 'A';
    }
    key[32] = other[32] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_siteleaf_init(&detector, &error) == 0 && detector->type == 263 && detector->max_credential_span == 1024);
    exercise(detector);
    return test_finish("Siteleaf");
}
