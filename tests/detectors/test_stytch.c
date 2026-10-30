/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_stytch_init(const br_detector **out, char **error);

static const char *token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU=";
static const char *ident = "project-live-0123456789abcdef0123456789abcdef0123";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.stytch.com/v1/users/pending"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Basic ", 6));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
}

int main(void)
{
    CHECK(strlen(token) == 48 && token[47] == '=' && strlen(ident) == 49);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_stytch_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 538 && !strcmp(detector->keywords[0], "stytch"));
    CHECK(detector->max_credential_span == 1024);
    char input[200];
    snprintf(input, sizeof(input), "stytch %s stytch %s", token, ident);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    test_key_result(&results.items[0], 538, token, "key");
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", token, ident);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    return test_finish("Stytch");
}
