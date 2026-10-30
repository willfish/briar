/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_sirv_init(const br_detector **out, char **error);

static const char key[] = "Ivus86]AJDk:rghv;8,o00SVP0efds5BBh453jew~mnC$K8elZI-OGU^v0AA#`>vek1cKlkipm]!n/f1xTDlUn1D";
static const char id[] = "n64cjK3Dg9Xyr2icHYypLwXl6V";
static const char key2[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.sirv.com/v2/token"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, "application/json"));
    CHECK(request->timeout_ms == 10000 && request->detector_type == 725);
    char body[160];
    snprintf(body, sizeof(body), "{\"clientId\":\"%s\",\"clientSecret\":\"%s\"}", id, key);
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sirv_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 725 && detector->max_credential_span == 1024);
    CHECK(strlen(key) == 88 && strlen(id) == 26 && strlen(key2) == 88);
    char input[320];
    snprintf(input, sizeof(input), "sirv secret %s\nsirv id %s\n", key, id);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 725, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sirv %s sirv %s sirv %s sirv %s", key, key2, id, id);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 4 && !memcmp(results.items[3].raw.data, key2, 88));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sirv %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    const char *invalid = "sirv ?vus86]AJDk:rghv;8,o00SVP0efds5BBh453jew~mnC$K8elZI-OGU^v0AA#`>vek1cKlkipm]!n/f1xTDlUn1D sirv n64cjK3Dg9Xyr2icHYypLwXl6V";
    results = test_scan(detector, NULL, false, invalid, strlen(invalid));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "sirv %s sirv %s", key, id);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == calls);
    http.send_rc = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    return test_finish("sirv");
}
