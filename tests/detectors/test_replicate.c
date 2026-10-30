/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_replicate_init(const br_detector **out, char **error);

static const char key[] = "r8_7DTl1j7Nsy6dpc3GGwkd8qsWFl33hy4ICtNzH";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char authorization[64];
    snprintf(authorization, sizeof(authorization), "Token %s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.replicate.com/v1/predictions"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 967);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog replicate-offline"));
}

int main(void)
{
    CHECK(strlen(key) == 40);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_replicate_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 967 && !strcmp(detector->name, "Replicate"));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "replicate") && !strcmp(detector->keywords[1], "r8_"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
        "Replicate is a platform for running machine learning models in the cloud. Replicate API keys can be used to manage and run these models."));
    CHECK(br_replicate_init(NULL, &error) != 0 && error); free(error);
    char input[128];
    snprintf(input, sizeof(input), "replicate token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 967, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2); br_results_clear(&results);
    snprintf(input, sizeof(input), "replicate = '%s'", "r8_7DTl1j7Nsy6dpc3GG?kd8qsWFl33hy4ICtNzH");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s", key);
    test_http http = {.response = {.status = 204}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "replicate-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    char echoed[96];
    snprintf(echoed, sizeof(echoed), "dial %s", key);
    http.send_rc = 1; http.send_error = echoed; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && strstr(results.items[0].verification_error, "[REDACTED]"));
    CHECK(!strstr(results.items[0].verification_error, key));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); br_results_clear(&results);
    return test_finish("Replicate");
}
