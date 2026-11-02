/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_satismeterprojectkey_init(const br_detector **out, char **error);

static char project[25];
static char token[33];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[96];
    snprintf(url, sizeof(url), "https://app.satismeter.com/api/users?project=%s", project);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->nheaders == 2);
    char expected[48];
    snprintf(expected, sizeof(expected), "Bearer %s", token);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization"))
            auth = !strcmp(request->headers[i].value, expected);
    CHECK(auth);
}

int main(void)
{
    test_secret(project, 24, 5);
    test_secret(token, 32, 6);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_satismeterprojectkey_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 230 && !strcmp(detector->name, "SatismeterProjectkey") && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "satismeter"));
    CHECK(br_detector_is_default(detector, NULL));

    char input[192];
    snprintf(input, sizeof(input), "satismeter %s %s satismeter %s %s", project, token, project, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == 24 && !memcmp(results.items[0].raw.data, project, 24));
    CHECK(results.items[0].raw_v2.len == 56 && !memcmp(results.items[0].raw_v2.data, project, 24) &&
          !memcmp(results.items[0].raw_v2.data + 24, token, 32));
    CHECK(!results.items[0].redacted);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "satismeter %s %s", project, token);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.response.status = 401;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.response.status = 500;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("satismeterprojectkey");
}
