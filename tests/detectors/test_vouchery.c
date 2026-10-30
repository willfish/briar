/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_vouchery_init(const br_detector **out, char **error);

static const char key[] = "abcdefghijklmnopqrstuvwxyz0123456789";
static const char sub[] = "shop";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://shop.vouchery.io/api/v2.0/users"));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].value, "Bearer abcdefghijklmnopqrstuvwxyz0123456789"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 374);
    *response = http->response;
    return 0;
}

static void release(void *user, br_http_response *response)
{
    ((test_http *)user)->releases++;
    memset(response, 0, sizeof(*response));
}

int main(void)
{
    const br_detector *d = NULL;
    CHECK(br_vouchery_init(&d, NULL) == 0);
    CHECK(d->type == 374 && !strcmp(d->name, "Vouchery") && !strcmp(d->keywords[0], "vouchery") &&
          d->max_credential_span == 1024);
    char text[96];
    snprintf(text, sizeof(text), "vouchery %s vouchery %s", sub, key);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == 36 && results.items[0].raw_v2.len == 40);
    CHECK(!memcmp(results.items[0].raw_v2.data + 36, sub, 4));
    br_results_clear(&results);
    test_http http = {.response = {.status = 204}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    snprintf(text, sizeof(text), "vouchery a%%zz vouchery %s", key);
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1);
    br_results_clear(&results);
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0 && http.calls == 1);
    br_results_clear(&results);
    snprintf(text, sizeof(text), "vouchery %s vouchery %s", sub, key);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("vouchery");
}
