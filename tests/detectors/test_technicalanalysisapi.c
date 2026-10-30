/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_technicalanalysisapi_init(const br_detector **out, char **error);

static char key[49], seen_url[128];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && request->nheaders == 1);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 582);
    snprintf(seen_url, sizeof(seen_url), "%s", request->url);
}

int main(void)
{
    memset(key, 'A', 48);
    key[48] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_technicalanalysisapi_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 582 && !strcmp(detector->name, "TechnicalAnalysisApi"));
    CHECK(!strcmp(detector->keywords[0], "technicalanalysisapi") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description, "TechnicalAnalysisApi is a service used for technical analysis of financial markets. The API key can be used to access and retrieve market analysis data."));
    char input[96];
    snprintf(input, sizeof(input), "TECHNICALANALYSISAPI %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 582, key, "key");
    br_results_clear(&out);
    key[0] = 'a';
    snprintf(input, sizeof(input), "technicalanalysisapi %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    key[0] = 'A';

    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "technicalanalysisapi %s", key);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified);
    CHECK(!strcmp(seen_url, "https://technical-analysis-api.com/api/v1/analysis/BTC?apiKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("TechnicalAnalysisApi");
}
