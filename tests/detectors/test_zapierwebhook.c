/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_zapierwebhook_init(const br_detector **out, char **error);

static const char key[] = "https://hooks.zapier.com/hooks/catch/AbCdEfGh12345678";
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[160];
    snprintf(url, sizeof(url), "https://hooks.zapier.com/hooks/catch/%s", key);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zapierwebhook_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 45 && !strcmp(detector->name, "ZapierWebhook"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "hooks.zapier.com/hooks/catch/"));
    CHECK(!br_detector_is_default(detector, NULL));

    br_results results = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 45, key, "key");
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.calls == 1);
    br_results_clear(&results);

    http.response.status = 401;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.response.status = 500;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, key, strlen(key));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("zapierwebhook");
}
