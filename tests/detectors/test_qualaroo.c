/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_qualaroo_init(const br_detector **out, char **error);

static const char key[] = "w82SrLORVOsr4VMrPhDG4fih0rYGw86vxGBZch99TVvTfiSBSlpWF6f42BVtf0jI";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char authorization[80];
    snprintf(authorization, sizeof(authorization), "Basic %s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.qualaroo.com/api/v1/nudges"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 229);
    CHECK(request->nheaders == 2 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog qualaroo-offline"));
}

int main(void)
{
    CHECK(strlen(key) == 64);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_qualaroo_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 229 && !strcmp(detector->name, "Qualaroo"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "qualaroo"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
        "Qualaroo is a customer survey tool that helps in collecting feedback from users. Qualaroo API keys can be used to access and manage survey data."));
    CHECK(br_qualaroo_init(NULL, &error) != 0 && error); free(error);
    char input[220];
    snprintf(input, sizeof(input), "qualaroo token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 229, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "qualaroo %sEXTRA", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].raw.len == 64);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "qualaroo keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "qualaroo = '%s'", "w82SrLORVOsr4VMrPhDG4fih0rYGw86v?GBZch99TVvTfiSBSlpWF6f42BVtf0jI");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "QUALAROO %s qualaroo %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2); br_results_clear(&results);
    snprintf(input, sizeof(input), "qualaroo %s", key);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "qualaroo-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);
    char echoed[160];
    snprintf(echoed, sizeof(echoed), "failed for %s", key);
    http.send_rc = 1; http.send_error = echoed; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(strstr(results.items[0].verification_error, "[REDACTED]") && !strstr(results.items[0].verification_error, key));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("Qualaroo");
}
