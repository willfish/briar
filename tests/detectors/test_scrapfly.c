/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_scrapfly_init(const br_detector **out, char **error);

static const char plain[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char live[] = "scp-live-abcdefghijklmnopqrstuvwxyz012345";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->nheaders == 1);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 660);
    char want[160];
    const char *token = http->calls == 0 ? plain : live;
    http->calls++;
    snprintf(want, sizeof(want), "https://api.scrapfly.io/scrape?key=%s&url=https://httpbin.org/status/200", token);
    CHECK(!strcmp(request->url, want));
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
    CHECK(br_scrapfly_init(&d, NULL) == 0);
    CHECK(d->type == 660 && !strcmp(d->name, "Scrapfly") && !strcmp(d->keywords[0], "scrapfly"));
    char text[192];
    snprintf(text, sizeof(text), "scrapfly %s scrapfly %s scrapfly scp-test-%s", plain, plain, plain);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 3);
    CHECK(results.items[2].raw.len == 41);
    br_results_clear(&results);
    snprintf(text, sizeof(text), "scrapfly %s scrapfly %s", plain, live);
    test_http http = {.response = {.status = 200}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    CHECK(http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    http = (test_http){.response = {.status = 500}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, 9 + 32}, &results, NULL) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, 9 + 32}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("scrapfly");
}
