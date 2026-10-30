/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_shipday_init(const br_detector **out, char **error);

static const char key[] = "aaaaa.bbbbbCCCCCCCCCCCCCCCCCCCC";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.shipday.com/carriers"));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, "Basic aaaaa.bbbbbCCCCCCCCCCCCCCCCCCCC"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 625);
    *response = http->response;
    return http->send_rc;
}

static void release(void *user, br_http_response *response)
{
    ((test_http *)user)->releases++;
    memset(response, 0, sizeof(*response));
}

int main(void)
{
    const br_detector *d = NULL;
    CHECK(br_shipday_init(&d, NULL) == 0);
    CHECK(d->type == 625 && !strcmp(d->name, "Shipday") && !strcmp(d->keywords[0], "shipday"));
    char text[128];
    snprintf(text, sizeof(text), "shipday %s shipday %s", key, key);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 2 && results.items[0].raw.len == 31);
    br_results_clear(&results);
    const char *short_key = "shipday aaaaa.bbbbbCCCCCCCCCCCCCCCCCCC";
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)short_key, strlen(short_key)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
    test_http http = {.response = {.status = 204}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, 8 + 31}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http = (test_http){.response = {.status = 199}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, 8 + 31}, &results, NULL) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, 8 + 31}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("shipday");
}
