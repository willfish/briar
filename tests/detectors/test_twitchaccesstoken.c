/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_twitchaccesstoken_init(const br_detector **out, char **error);

static char key[31];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://id.twitch.tv/oauth2/validate"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 2);
    char expected[48];
    snprintf(expected, sizeof(expected), "OAuth %s", key);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization"))
            auth = !strcmp(request->headers[i].value, expected);
    CHECK(auth);
}

int main(void)
{
    for (int i = 0; i < 30; ++i) key[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[i % 36];
    key[30] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_twitchaccesstoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 1010 && !strcmp(detector->name, "TwitchAccessToken"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "twitch"));
    CHECK(br_detector_is_default(detector, NULL));

    char input[128];
    snprintf(input, sizeof(input), "twitch %s twitch %s", key, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 1010, key, "key");
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "twitch %s", key);
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
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("twitchaccesstoken");
}
