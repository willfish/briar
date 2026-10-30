/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_zeplin_init(const br_detector **out, char **error);

static const char *valid =
    "bv9qqMUYcE-wGLV4SGIFrlQ2OKRWMC.w18-Mpt3ZfQ3We.RrE1Cpx9-o50H5DFyPlLNhIBni20i6uelit3U5zJf-kxOY2UZjEOw3Nn1I..gsJbav9MhwiwQqITI8Z3vrOKpYLZ6vwib4bfU.NFMhmyxUUsRuOR4whWubCyV9-K7NPQwhRbKgaQJ7iWIx1eJPTD7Hzanr92YpeexiglRULihOhEQWAhbSqt87i5YQBwfQ-s06KsGMmRUgx0DyRbcoo6vzlM7FV.fS7jzWDoSxas1rMBUtp7s9p3gNY77wBdvVm6HrTCy3t85PMzjSZkN6cck44XXFo8KZ3ItVTWcvIxF.7qLTnL";

static void fill(char *out, size_t n)
{
    for (size_t i = 0; i < n; ++i) out[i] = (char)('A' + (i % 26));
    out[n] = '\0';
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = http->user;
    char authorization[sizeof("Bearer ") + 400];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.zeplin.dev/v1/users/me"));
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 155);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(valid) == 350);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zeplin_init(&detector, &error) == 0 && !error && detector->type == 155);
    CHECK(!strcmp(detector->name, "Zeplin") && !strcmp(detector->keywords[0], "zeplin"));
    CHECK(!strcmp(detector->description,
                  "Zeplin is a collaboration app for UI designers and front-end developers. Zeplin API keys can be used to access and modify project data."));
    char input[1024], other[402];
    snprintf(input, sizeof(input), "zeplin token = '%s'", valid);
    test_http http = {.inspect = inspect, .user = (void *)valid, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "zeplin-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    test_key_result(&results.items[0], 155, valid, "key");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "zeplin token = '%s' | '%s'", valid, valid);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zeplin keyword is not close to the real key in the data\n = '%s'", valid);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    fill(other, 349);
    snprintf(input, sizeof(input), "zeplin %s", other);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    fill(other, 400);
    snprintf(input, sizeof(input), "zeplin %s", other);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 155, other, "key");
    br_results_clear(&results);
    fill(other, 401);
    snprintf(input, sizeof(input), "zeplin %s", other);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "zeplin %s", valid);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);

    char leaked[400];
    snprintf(leaked, sizeof(leaked), "failed %s", valid);
    http.send_rc = -1;
    http.send_error = leaked;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "failed [REDACTED]"));
    br_results_clear(&results);

    br_results nil_results = {0};
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &nil_results, &error) == 0 && !error && nil_results.len == 1);
    CHECK(!strcmp(nil_results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil_results);
    return test_finish("Zeplin");
}
