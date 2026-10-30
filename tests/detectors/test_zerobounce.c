/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_zerobounce_init(const br_detector **out, char **error);

static const char key[] = "abcdefghijklmnopqrstuvwxyz012345";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.zerobounce.net/v2/activity?email=testemail@email.com&api_key=abcdefghijklmnopqrstuvwxyz012345"));
    CHECK(request->nheaders == 1 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 144);
    *response = http->response;
    return http->send_rc;
}

static void release(void *user, br_http_response *response)
{
    ((test_http *)user)->releases++;
    memset(response, 0, sizeof(*response));
}

static void one(const br_detector *d, test_http http, bool verified, const char *error)
{
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    char text[80];
    snprintf(text, sizeof(text), "zerobounce %s", key);
    br_results results = {0};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verified == verified && http.releases == 1);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *d = NULL;
    CHECK(br_zerobounce_init(&d, NULL) == 0);
    CHECK(d->type == 144 && !strcmp(d->name, "Zerobounce") && !strcmp(d->keywords[0], "zerobounce"));
    char text[96];
    snprintf(text, sizeof(text), "zerobounce %s zerobounce %s", key, key);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 2);
    br_results_clear(&results);
    const char *found = "activity found";
    one(d, (test_http){.response = {.status = 200, .body = {(const unsigned char *)found, strlen(found)}}}, true, NULL);
    const char *missing = "absent";
    one(d, (test_http){.response = {.status = 200, .body = {(const unsigned char *)missing, 6}}}, false, NULL);
    one(d, (test_http){.response = {.status = 200, .body_error = "read failed"}}, false, "read failed");
    one(d, (test_http){.response = {.status = 401, .body = {(const unsigned char *)found, strlen(found)}}}, false, NULL);
    one(d, (test_http){.response = {.status = 404}}, false, NULL);
    one(d, (test_http){.response = {.status = 500}}, false, "unexpected status code: 500");
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, 11 + 32}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("zerobounce");
}
