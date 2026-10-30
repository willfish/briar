/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_uploadcare_init(const br_detector **out, char **error);

static const char priv[] = "abcdefghijklmnopqrst";
static const char pub[] = "abcdefghijklmnopqrst";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.uploadcare.com/files/"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/vnd.uploadcare-v0.5+json"));
    CHECK(!strcmp(request->headers[1].value, "Uploadcare.Simple abcdefghijklmnopqrst:abcdefghijklmnopqrst"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 722);
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
    CHECK(br_uploadcare_init(&d, NULL) == 0);
    CHECK(d->type == 722 && !strcmp(d->name, "UploadCare") && !strcmp(d->keywords[0], "uploadcare") &&
          d->max_credential_span == 1024);
    char text[80];
    snprintf(text, sizeof(text), "uploadcare %s", priv);
    (void)pub;
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].raw.len == 20 && !results.items[0].raw_v2.len);
    br_results_clear(&results);
    test_http http = {.response = {.status = 200}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("uploadcare");
}
