/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_wepay_init(const br_detector **out, char **error);

static const char valid_key[] = "JFdESNcC4meVkWFygHV5O5FmhycSCsQnlmmXWwTKSQOJG3ERd?stTjE8m98hJU";
static const char invalid_key[] = "JFdESNcC4meVkWFygHV5O5FmhycSCsQ!lmmXWwTKSQOJG3ERd?stTjE8m98hJU";
static const char *seen_app;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(valid_key) == 62 && strlen(invalid_key) == 62);
    CHECK(br_wepay_init(&detector, &error) == 0 && detector && detector->type == 194);
    CHECK(!strcmp(detector->name, "WePay") && !strcmp(detector->keywords[0], "wepay"));
    CHECK(!strcmp(detector->description,
                  "WePay is an online payment service provider. WePay API keys can be used to "
                  "process payments and access account information."));
    CHECK(detector->max_credential_span == 1024 && detector->state && !detector->clean);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://stage-api.wepay.com/payments?type=credit_card&credit_card=4003830171874018"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 194);
    CHECK(request->nheaders == 6 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "App-Token") && !strcmp(request->headers[0].value, valid_key));
    CHECK(!strcmp(request->headers[1].name, "App-Id") && !strcmp(request->headers[1].value, seen_app));
    CHECK(!strcmp(request->headers[2].name, "Api-Version") && !strcmp(request->headers[2].value, "3.0"));
    CHECK(!strcmp(request->headers[3].name, "Accept") && !strcmp(request->headers[3].value, "application/json"));
    CHECK(!strcmp(request->headers[4].name, "Unique-Key") && !strcmp(request->headers[4].value, "Unique-Key0"));
    CHECK(!strcmp(request->headers[5].name, "User-Agent") && !strcmp(request->headers[5].value, "TruffleHog"));
}

static void run(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "wepay token - '%s'\nwepay token - '%s'\n", "135827", valid_key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 194, valid_key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "wepay token - '%s'\nwepay token - '%s'\n", "135?27", invalid_key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "111111 wepay %s 222222", valid_key);
    seen_app = "222222";
    test_http http = {.response = {.status = 204}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && results.items[0].verified);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "wepay %s", valid_key);
    seen_app = "";
    http = (test_http){.response = {.status = 401}, .inspect = inspect};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    run(descriptor());
    return test_finish("WePay");
}
