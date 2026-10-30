/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_smartsheets_init(const br_detector **out, char **error);

static const char key26[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char key37[] = "abcdefghijklmnopqrstuvwxyz0123456789Z";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[48];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key26);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len);
    CHECK(!strcmp(request->url, "https://api.smartsheet.com/2.0/sheets"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, authorization));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_smartsheets_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 247 && !strcmp(detector->name, "Smartsheets"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "smartsheet"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Smartsheets is a platform for work management and automation. Smartsheets API keys can be used to access and modify data and automate workflows within the platform."));
    return detector;
}

int main(void)
{
    CHECK(strlen(key26) == 26 && strlen(key37) == 37);
    const br_detector *detector = descriptor();
    char input[180];
    snprintf(input, sizeof(input), "SMARTSHEET%*s%s smartsheet %s smartsheet %s", 40, "", key26, key26, key37);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 247, key26, "key");
    test_key_result(&results.items[1], 247, key37, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sheet%*s%s", 41, "", key26);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "smartsheet %s", "ABCDEFGHIJKLMNOPQRSTUVWXY");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "smartsheet %s", key26);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("Smartsheets");
}
