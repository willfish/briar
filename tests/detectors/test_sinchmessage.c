/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_sinchmessage_init(const br_detector **out, char **error);

static const char a[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char b[] = "abcdefghijklmnopqrstuvwxyz012346";
static const char body[] =
    "\n\t\t\t\t{\n\t\t\t\t\"from\": \"447537454435\",\n\t\t\t\t\"to\": [ \"639668957581\" ],\n"
    "\t\t\t\t\"body\": \"This is a test message from your Sinch account\"\n\t\t\t\t}";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    const char *key = http->calls < 2 ? a : b;
    const char *id = http->calls % 2 ? b : a;
    http->calls++;
    char url[96], authorization[48];
    snprintf(url, sizeof(url), "https://sms.api.sinch.com/xms/v1/%s/batches", id);
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].value, authorization));
    CHECK(request->body.len == 131 && !memcmp(request->body.data, body, 131));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 162);
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
    CHECK(br_sinchmessage_init(&d, NULL) == 0);
    CHECK(d->type == 162 && !strcmp(d->name, "SinchMessage") && !strcmp(d->keywords[0], "sinch") &&
          d->max_credential_span == 1024);
    CHECK(sizeof(body) - 1 == 131);
    char text[128];
    snprintf(text, sizeof(text), "sinch %s sinch %s", a, b);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 4);
    CHECK(!memcmp(results.items[0].raw.data, a, 32) && !memcmp(results.items[2].raw.data, b, 32));
    br_results_clear(&results);
    test_http http = {.response = {.status = 201}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 4 && results.items[0].verified && http.calls == 4 && http.releases == 4);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, 6 + 32}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("sinchmessage");
}
