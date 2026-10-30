/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_webscraper_init(const br_detector **out, char **error);

static char key[61];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[128];
    snprintf(url, sizeof(url), "https://api.webscraper.io/api/v1/sitemaps?api_token=%s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 1);
}

int main(void)
{
    test_secret(key, 60, 2);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_webscraper_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 663 && !strcmp(detector->name, "WebScraper"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "webscraper"));
    CHECK(!br_detector_is_default(detector, NULL));

    char input[160];
    snprintf(input, sizeof(input), "webscraper %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 663, key, "key");
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("webscraper");
}
