/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_thinkific_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdef0123456789abcdef";
static const char marker[] = "prefix API Access is not available suffix";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.thinkific.com/api/public/v1/collections"));
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "X-Auth-API-Key") && !strcmp(request->headers[0].value, key));
    const char *subdomain = http->calls == 1 ? "myschool-s-school" : "0123456789abcdef0123456789abcdef-s-school";
    CHECK(!strcmp(request->headers[1].name, "X-Auth-Subdomain") && !strcmp(request->headers[1].value, subdomain));
    CHECK(!strcmp(request->headers[2].value, "application/json"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 589);
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
    CHECK(br_thinkific_init(&d, NULL) == 0);
    CHECK(d->type == 589 && !strcmp(d->name, "Thinkific") && !strcmp(d->keywords[0], "thinkific") &&
          d->max_credential_span == 1024);
    char text[96];
    snprintf(text, sizeof(text), "thinkific myschool thinkific %s", key);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 2 && results.items[0].raw.len == 32);
    br_results_clear(&results);
    test_http http = {.response = {.status = 403, .body = {(const unsigned char *)marker, sizeof(marker) - 1}}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    CHECK(http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    const char *plain = "no marker";
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)plain, 9}}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 2 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http = (test_http){.response = {.status = 200, .body_error = "read failed"}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0 && http.releases == 2);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("thinkific");
}
