/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_tailscale_init(const br_detector **out, char **error);

static const char key[] = "tskey-rtzgayeq-RLL0xBAIXBhkYRhir0gmxHNoARkj0CqpNTj_xM2Zpm4lDxEIGsYbwO_kzlNSwrQrAOL4yacZGlBfj37e3WRRlmYfKtrgC-xmk0NNQFLQGCTPwcwQT7d6YipCXS1ScCVL8So";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.tailscale.com/api/v2/secret-scanning/verify"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(request->body.len == 4 + strlen(key) && !memcmp(request->body.data, "key=", 4));
    CHECK(!memcmp(request->body.data + 4, key, strlen(key)));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 929);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tailscale_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 929 && detector->nkeywords == 3 && !strcmp(detector->keywords[0], "tskey-"));
    CHECK(!strcmp(detector->keywords[1], "tskey-api-") && !strcmp(detector->keywords[2], "tskey-oauth-"));
    char input[400];
    snprintf(input, sizeof(input), "token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 929, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s | %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    const char *invalid = "tskey-rtzgayeq-RLL0xBAIXBhkYRhir0gmxH?oARkj0CqpNTj_xM2Zpm4l";
    results = test_scan(detector, NULL, false, invalid, strlen(invalid));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 204}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "dial refused"));
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == calls);
    return test_finish("tailscale");
}
