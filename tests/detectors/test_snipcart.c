/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_snipcart_init(const br_detector **out, char **error);

static const char key[] = "A7c9d2e5f6_8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y4z6b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t";
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://app.snipcart.com/api/orders"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 3);
    bool accept = false;
    char *expected = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)key, 75}, (br_slice){0}, &expected, NULL) == 0);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Accept"))
            accept = !strcmp(request->headers[i].value, "application/json");
        if (!strcmp(request->headers[i].name, "Authorization"))
            auth = !strcmp(request->headers[i].value, expected);
    }
    free(expected);
    CHECK(auth && accept);
}

int main(void)
{
    CHECK(strlen(key) == 75 && strchr(key, '_'));
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_snipcart_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 505 && !strcmp(detector->name, "Snipcart"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "snipcart"));
    CHECK(!br_detector_is_default(detector, NULL));

    char input[220];
    snprintf(input, sizeof(input), "snipcart %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    const char short_key[] = "7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u";
    snprintf(input, sizeof(input), "snipcart %s", short_key);
    br_results missed = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!missed.len);
    br_results_clear(&missed);
    snprintf(input, sizeof(input), "snipcart %s", key);
    test_key_result(&results.items[0], 505, key, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "snipcart %s snipcart %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "snipcart %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("snipcart");
}
