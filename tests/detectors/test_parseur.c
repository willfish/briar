/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_parseur_init(const br_detector **out, char **error);

static char key[41];
static void fill(void)
{
    for (int i = 0; i < 40; ++i) key[i] = "0123456789abcdef"[i % 16];
    key[40] = '\0';
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.parseur.com/"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->nheaders == 2);
    bool auth = false, agent = false;
    char expected[64];
    snprintf(expected, sizeof(expected), "Token %s", key);
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Authorization")) {
            auth = !strcmp(request->headers[i].value, expected);
        }
        if (!strcmp(request->headers[i].name, "User-Agent"))
            agent = !strcmp(request->headers[i].value, "TruffleHog");
    }
    CHECK(auth && agent);
}

int main(void)
{
    fill();
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_parseur_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 837 && !strcmp(detector->name, "Parseur"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "parseur"));
    CHECK(br_detector_is_default(detector, NULL));

    char input[256];
    snprintf(input, sizeof(input), "parseurx %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 837, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "PARSEURx %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "parseuri %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "parseurx %s parseurx %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);

    char far[128];
    memset(far, 'x', 41);
    far[41] = '\0';
    snprintf(input, sizeof(input), "parseurx %s %s", far, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{}", 2}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "parseurx %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);

    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.send_rc = 1;
    http.send_error = "dial failed";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "dial failed"));
    br_results_clear(&results);

    http.send_rc = 0;
    http.send_error = NULL;
    http.calls = 0;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(http.calls == 0 && results.len == 1);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    br_results empty = {0};
    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 1}, &empty, &error) != 0 && error && empty.len == 0);
    free(error);
    return test_finish("parseur");
}
