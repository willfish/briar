/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_statuscake_init(const br_detector **out, char **error);

static char key[21];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.statuscake.com/v1/ssl"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->nheaders == 2);
    char expected[32];
    snprintf(expected, sizeof(expected), "Bearer %s", key);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization"))
            auth = !strcmp(request->headers[i].value, expected);
    CHECK(auth);
}

int main(void)
{
    test_secret(key, 20, 0);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_statuscake_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 795 && !strcmp(detector->name, "Statuscake"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "statuscake"));
    CHECK(!br_detector_is_default(detector, NULL));

    char input[160];
    snprintf(input, sizeof(input), "statuscake %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 795, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "statuscake %s statuscake %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "statuscake %s", "shortkeyshortkey12");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    test_http http = {.response = {.status = 204}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "statuscake %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.send_rc = 1;
    http.send_error = "dial failed";
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("statuscake");
}
