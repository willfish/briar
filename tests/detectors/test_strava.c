/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_strava_init(const br_detector **out, char **error);

static const char id[] = "12345";
static const char secret[] = "abcdefghijklmnopqrstuvwxyz0123456789abcd";
static const char refresh[] = "abcdefghijklmnopqrstuvwxyz0123456789abce";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    const char *sec = http->calls < 2 ? secret : refresh;
    const char *tok = http->calls % 2 ? refresh : secret;
    http->calls++;
    char body[160];
    snprintf(body, sizeof(body),
             "grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s", id, sec, tok);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://www.strava.com/oauth/token"));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 476);
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
    CHECK(br_strava_init(&d, NULL) == 0);
    CHECK(d->type == 476 && !strcmp(d->name, "Strava") && !strcmp(d->keywords[0], "strava") &&
          d->max_credential_span == 1024);
    char text[192];
    snprintf(text, sizeof(text), "strava %s strava %s strava %s", id, secret, refresh);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 4);
    CHECK(results.items[0].raw.len == 5 && !memcmp(results.items[0].raw.data, id, 5));
    CHECK(results.items[0].raw_v2.len == 45 && !memcmp(results.items[0].raw_v2.data, id, 5));
    CHECK(!memcmp(results.items[0].raw_v2.data + 5, secret, 40));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "secret", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    CHECK(!json_object_object_get_ex(results.items[0].secret_parts, "refresh", &part));
    br_results_clear(&results);
    test_http http = {.response = {.status = 200}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 4 && results.items[3].verified && http.calls == 4 && http.releases == 4);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    return test_finish("strava");
}
