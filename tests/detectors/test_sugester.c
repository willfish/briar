/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_sugester_init(const br_detector **out, char **error);

static const char key1[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char domain[] = "acme.example";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char url[128];
    const char *host = http->calls == 1 ? domain : key1;
    snprintf(url, sizeof(url), "https://%s.sugester.com/app/clients.json?api_token=%s", host, key1);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000 && !request->body.len);
    CHECK(!strcmp(request->url, url));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.sugester+json; version=3"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sugester_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 705 && !strcmp(detector->name, "Sugester"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "sugester"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description,
                  "Sugester is a customer support software that offers various tools for managing customer interactions. Sugester API keys can be used to access and manage data within the Sugester platform."));
    return detector;
}

int main(void)
{
    CHECK(strlen(key1) == 32);
    const br_detector *detector = descriptor();
    char input[96];
    snprintf(input, sizeof(input), "SUGESTER %s sugester %s", domain, key1);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 705, key1, "key");
    test_key_result(&results.items[1], 705, key1, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sugester%*s%s", 41, "", key1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "sugester %s sugester %s", domain, key1);
    test_http http = {.response = {.status = 204}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    http.response.status = 404;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = -1;
    http.send_error = "dial failed";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !results.items[0].verified && !results.items[0].verification_error && http.releases == 2);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("Sugester");
}
