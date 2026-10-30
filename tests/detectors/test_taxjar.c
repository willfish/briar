/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_taxjar_init(const br_detector **out, char **error);

static const char key[] = "2jnsyu2ebcnaemws9b2rmh6w6e12i8j7";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.taxjar.com/v2/categories"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 151);
    CHECK(request->nheaders == 2);
    char authorization[48];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog taxjar-offline"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_taxjar_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 151 && !strcmp(detector->name, "Taxjar"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "taxjar"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
        "Taxjar is a sales tax API that allows businesses to automate sales tax calculations, reporting, and filings. Taxjar API keys can be used to access and manage these services."));
    CHECK(br_taxjar_init(NULL, &error) != 0 && error); free(error);
    char input[96];
    snprintf(input, sizeof(input), "taxjar token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 151, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "TAXJAR %s taxjar %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2); br_results_clear(&results);
    snprintf(input, sizeof(input), "taxjar keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "taxjar = '%s'", "2jnsyu2ebcnaemws?b2rmh6w6e12i8j7");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "taxjar %s", key);
    test_http http = {.response = {.status = 204}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "taxjar-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1); br_results_clear(&results);
    http.response.status = 401; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 1; http.send_error = "contains 2jnsyu2ebcnaemws9b2rmh6w6e12i8j7";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    return test_finish("Taxjar");
}
