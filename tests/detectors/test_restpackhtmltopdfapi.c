/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_restpackhtmltopdfapi_init(const br_detector **out, char **error);

static const char key1[] = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";
static const char key2[] = "abcDEF0123456789abcDEF0123456789abcDEF0123456789";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len);
    CHECK(!strcmp(request->url, "https://restpack.io/api/html2pdf/usage"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Access-Token") && !strcmp(request->headers[1].value, key1));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_restpackhtmltopdfapi_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 517 && !strcmp(detector->name, "RestpackHtmlToPdfAPI"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "restpack"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Restpack is a service that provides APIs for converting HTML to PDF. Restpack API keys can be used to access and utilize this service."));
    return detector;
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[180];
    snprintf(input, sizeof(input), "RESTPACK%*s%s restpack %s", 40, "", key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 517, key1, "key");
    test_key_result(&results.items[1], 517, key2, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "restpack%*s%s", 41, "", key1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "restpack %s", key1);
    test_http http = {.response = {.status = 204}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("RestpackHtmlToPdfAPI");
}
