/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_spectralops_init(const br_detector **out, char **error);

static const char token[] = "spu-abcdefghijklmnopqrstuvwxyz012345";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx;
    test_http *http = user;
    http->calls++;
    if (http->send_rc && error) *error = http->send_error ? strdup(http->send_error) : NULL;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://get.spectralops.io/api/v1/users"));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, "Bearer spu-abcdefghijklmnopqrstuvwxyz012345"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1051);
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
    CHECK(br_spectralops_init(&d, NULL) == 0);
    CHECK(d->type == 1051 && !strcmp(d->name, "SpectralOps") && !strcmp(d->keywords[0], "spu-"));
    char text[128];
    snprintf(text, sizeof(text), "%s %s", token, token);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].raw.len == 36);
    br_results_clear(&results);
    int statuses[] = {200, 401, 403, 404};
    const char *errors[] = {NULL, NULL, NULL, "unexpected HTTP response status 404"};
    for (size_t i = 0; i < 4; ++i) {
        test_http http = {.response = {.status = statuses[i]}};
        br_transport transport = {.user = &http, .send = inspect, .release = release};
        br_scan_ctx ctx = {.transport = &transport};
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)token, strlen(token)}, &results, NULL) == 0);
        CHECK(results.len == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (statuses[i] == 200));
        if (errors[i]) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, errors[i]));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char leaked[80];
    snprintf(leaked, sizeof(leaked), "dial %s", token);
    test_http http = {.send_rc = -1, .send_error = leaked};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)token, strlen(token)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verification_error && !strstr(results.items[0].verification_error, token));
    CHECK(!strcmp(results.items[0].verification_error, "dial [REDACTED]"));
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)token, strlen(token)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("spectralops");
}
