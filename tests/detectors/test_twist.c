/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_twist_init(const br_detector **, char **);

static char token[41];
static int oauth;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char authorization[80];
    snprintf(authorization, sizeof(authorization), oauth ? "Bearer oauth2:%s" : "Bearer %s", token);
    CHECK(!strcmp(request->url, "https://api.twist.com/api/v3/users/get_session_user"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog"));
}

int main(void)
{
    memset(token, 'a', 40);
    token[40] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_twist_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 827);
    char input[96];
    snprintf(input, sizeof(input), "twist %s", token);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    test_key_result(&results.items[0], 827, token, "key");
    br_results_clear(&results);
    oauth = 1;
    snprintf(input, sizeof(input), "twist oauth2:%s", token);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].raw.len == 40);
    br_results_clear(&results);
    oauth = 1;
    snprintf(input, sizeof(input), "twist oauth note %s", token);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 3);
    br_results_clear(&results);
    size_t calls = http.calls;
    snprintf(input, sizeof(input), "twist %s", token);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    printf("twist: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
