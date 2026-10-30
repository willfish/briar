/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_teamgate_init(const br_detector **out, char **error);

static const char token[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char app[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

typedef struct { test_http http; int status; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.teamgate.com/v4/users"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "X-Auth-Token") && !strcmp(request->headers[0].value, token));
    CHECK(!strcmp(request->headers[1].name, "X-App-Key") && !strcmp(request->headers[1].value, app));
    http->response.status = ((probe *)http->user)->status;
}

static br_results scan_probe(const br_detector *detector, const char *input, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

int main(void)
{
    CHECK(strlen(token) == 40 && strlen(app) == 80);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_teamgate_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 319 && !strcmp(detector->keywords[0], "teamgate"));
    CHECK(detector->max_credential_span == 1024);
    char input[256];
    snprintf(input, sizeof(input), "teamgate %s teamgate %s", token, app);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 319, token, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "teamgate %s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "teamgate %s teamgate %s", token, app);
    probe ok = {.status = 200};
    results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    br_results_clear(&results);
    probe denied = {.status = 401};
    results = scan_probe(detector, input, &denied);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("teamgate");
}
