/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_supernotesapi_init(const br_detector **out, char **error);

static char key[44];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.supernotes.app/v1/user/"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 3);
    bool accept = false, token = false;
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Accept"))
            accept = !strcmp(request->headers[i].value, "application/json");
        if (!strcmp(request->headers[i].name, "Api-Key"))
            token = !strcmp(request->headers[i].value, key);
    }
    CHECK(accept && token);
}

int main(void)
{
    test_secret(key, 43, 3);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_supernotesapi_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 718 && !strcmp(detector->name, "SuperNotesAPI"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "supernotes"));
    CHECK(!br_detector_is_default(detector, NULL));

    char input[128];
    snprintf(input, sizeof(input), "supernotes %s\n", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 718, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "supernotes %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "supernotes %s ", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("supernotesapi");
}
