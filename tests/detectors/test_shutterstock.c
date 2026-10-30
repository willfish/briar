/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_shutterstock_init(const br_detector **, char **);

static char user[33], secret[17];
static char *expected_auth;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->url, "https://api.shutterstock.com/v2/images/search"));
    CHECK(request->nheaders == 3 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, expected_auth));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog"));
}

int main(void)
{
    memset(user, 'A', 32);
    user[32] = 0;
    memset(secret, 'b', 16);
    secret[16] = 0;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)user, 32},
                             (br_slice){(const unsigned char *)secret, 16}, &expected_auth, NULL) == 0);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shutterstock_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 462 && detector->max_credential_span == 1024);
    char input[96];
    snprintf(input, sizeof(input), "shutterstock %s %s", user, secret);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    test_key_result(&results.items[0], 462, secret, "key");
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    free(expected_auth);
    printf("shutterstock: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
