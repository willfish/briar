/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_webscraping_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdefABCDEF0123456789";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_webscraping_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_webscraping_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 551 && !strcmp(detector->name, "Webscraping"));
    CHECK(!strcmp(detector->description,
                  "Webscraping API keys can be used to access web scraping services to extract data from websites."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "webscraping"));
    CHECK(detector->max_credential_span == -1);
    CHECK(strlen(key) == 32);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "webscraping %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 551, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "webscraping %s webscraping %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
}

static int web_status;
static const char *web_body;
static bool web_read_error;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[80];
    snprintf(url, sizeof(url), "https://api.webscrapingapi.com/v1?api_key=%s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->nheaders == 1 && request->profile == BR_HTTP_SANE);
    http->response.status = web_status;
    if (web_body) http->response.body = (br_slice){(const unsigned char *)web_body, strlen(web_body)};
    if (web_read_error) http->response.body_error = "read error";
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "webscraping %s", key);
    web_status = 400;
    web_body = "error: key `url` required.";
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    web_status = 200;
    web_body = "ok";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    web_read_error = true;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    web_read_error = false;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("webscraping");
}
