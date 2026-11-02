/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_todoist_init(const br_detector **out, char **error);

static char key[41];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.todoist.com/api/v1/projects"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 2);
    char expected[64];
    snprintf(expected, sizeof(expected), "Bearer %s", key);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization"))
            auth = !strcmp(request->headers[i].value, expected);
    CHECK(auth);
}

int main(void)
{
    for (int i = 0; i < 40; ++i) key[i] = "0123456789abcdefghijklmnopqrstuvwxyz"[i % 36];
    key[40] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_todoist_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 339 && !strcmp(detector->name, "Todoist"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "todoist"));
    CHECK(br_detector_is_default(detector, NULL));

    char input[160];
    snprintf(input, sizeof(input), "todoist %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 339, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "todoist %sA", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "todoist %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    http.response.status = 500;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("todoist");
}
