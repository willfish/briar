/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_screenshotlayer_init(const br_detector **out, char **error);

static const char key[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

typedef struct { test_http http; int status; const char *body; } probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && request && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000);
    CHECK(strstr(request->url, "access_key=") && strstr(request->url, "https://google.com"));
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    probe *p = http->user;
    http->response.status = p->status;
    http->response.body = (br_slice){(const unsigned char *)p->body, strlen(p->body)};
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
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_screenshotlayer_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 537 && !strcmp(detector->name, "ScreenshotLayer"));
    CHECK(!strcmp(detector->keywords[0], "screenshotlayer"));
    char input[96];
    snprintf(input, sizeof(input), "screenshotlayer %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 537, key, "key");
    br_results_clear(&results);
    probe ok = {.status = 200, .body = "PNG"};
    results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.releases == 1);
    br_results_clear(&results);
    probe lower = {.status = 200, .body = "png"};
    results = scan_probe(detector, input, &lower);
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    probe unread = {.status = 200, .body = "PNG"};
    unread.http.response.body_error = "short read";
    results = scan_probe(detector, input, &unread);
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("screenshotlayer");
}
