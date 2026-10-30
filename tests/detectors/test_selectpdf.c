/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_selectpdf_init(const br_detector **out, char **error);

static const char key1[] = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
static const char key2[] = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char url[128];
    snprintf(url, sizeof(url), "https://selectpdf.com/api2/convert/?key=%s&url=google.com", key1);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 10000 && !request->body.len && request->nheaders == 1);
    CHECK(!strcmp(request->url, url));
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_selectpdf_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 641 && !strcmp(detector->name, "SelectPDF"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "selectpdf"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "SelectPDF is a service that allows users to convert web pages to PDF documents. SelectPDF API keys can be used to perform these conversions programmatically."));
    return detector;
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[160];
    snprintf(input, sizeof(input), "SELECTPDF%*s%s selectpdf %s", 40, "", key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 641, key1, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "selectpdf A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "selectpdf %s", key1);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("SelectPDF");
}
