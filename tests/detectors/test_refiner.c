/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_refiner_init(const br_detector **out, char **error);

static const char key[] = "2341fb6f-71d4-dbbc-1317-98c28ceb5837";
static const char body[] = "id=Your-User-Id&event=Your%20event%20name";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.refiner.io/v1/identify-user"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].value, "Bearer 2341fb6f-71d4-dbbc-1317-98c28ceb5837"));
    CHECK(request->body.len == sizeof(body) - 1 && !memcmp(request->body.data, body, request->body.len));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 288);
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
    char *error = NULL;
    CHECK(br_refiner_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_refiner_init(&d, NULL) == 0);
    CHECK(d->type == 288 && !strcmp(d->name, "Refiner") && d->nkeywords == 1 && !strcmp(d->keywords[0], "refiner"));
    char text[160];
    snprintf(text, sizeof(text), "refiner %s refiner %s", key, key);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 2);
    CHECK(results.items[0].raw.len == 36 && !memcmp(results.items[0].raw.data, key, 36));
    br_results_clear(&results);
    const char *upper = "refiner 2341FB6F-71d4-dbbc-1317-98c28ceb5837";
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)upper, strlen(upper)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
    const char *first_a = "refiner A341fb6f-71d4-dbbc-1317-98c28ceb5837";
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)first_a, strlen(first_a)}, &results, NULL) == 0);
    CHECK(results.len == 1);
    br_results_clear(&results);
    int statuses[] = {200, 299, 199};
    for (size_t i = 0; i < 3; ++i) {
        test_http http = {.response = {.status = statuses[i]}};
        br_transport transport = {.user = &http, .send = inspect, .release = release};
        br_scan_ctx ctx = {.transport = &transport};
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, 8 + 36}, &results, NULL) == 0);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, 8 + 36}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
    br_scan_ctx bare = {0};
    CHECK(d->scan(d, &bare, true, (br_slice){(const unsigned char *)text, 8 + 36}, &results, NULL) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    return test_finish("refiner");
}
