/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_runrunit_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdef0123456789abcdef";
static const char user[] = "123456789012345678";

static int inspect(void *user_data, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user_data;
    http->calls++;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://runrun.it/api/v1.0/users"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "App-Key") && !strcmp(request->headers[0].value, key));
    CHECK(!strcmp(request->headers[1].name, "User-Token") && !strcmp(request->headers[1].value, user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 369);
    *response = http->response;
    return http->send_rc;
}

static void release(void *user_data, br_http_response *response)
{
    ((test_http *)user_data)->releases++;
    memset(response, 0, sizeof(*response));
}

int main(void)
{
    const br_detector *d = NULL;
    CHECK(br_runrunit_init(&d, NULL) == 0);
    CHECK(d->type == 369 && !strcmp(d->name, "RunRunIt") && !strcmp(d->keywords[0], "runrunit") &&
          d->max_credential_span == 1024);
    char text[160];
    snprintf(text, sizeof(text), "runrunit %s runrunit %s", user, key);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].raw.len == 32);
    br_results_clear(&results);
    const char *short_user = "runrunit 12345678901234567 runrunit 0123456789abcdef0123456789abcdef";
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)short_user, strlen(short_user)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
    test_http http = {.response = {.status = 200}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("runrunit");
}
