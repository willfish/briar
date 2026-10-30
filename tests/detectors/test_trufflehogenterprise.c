/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_trufflehogenterprise_init(const br_detector **out, char **error);

static const char key[] = "thog-key-946c7e0fbee2baff";
static const char secret[] = "thog-secret-8fbfc135085421e62d8f1982af17bbf6";
static const char host[] = "abc-def-ghi.a1.example.trufflehog.org";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char url[96];
    snprintf(url, sizeof(url), "https://%s/api/v1/sources", host);
    CHECK(!strcmp(request->url, url) && !strcmp(request->method, "GET") && !request->body.len);
    CHECK(request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE && request->detector_type == 922);
    CHECK(!ctx->cancelled && !strcmp(ctx->user_agent, "enterprise-offline"));
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Accept") &&
          !strcmp(request->headers[0].value, "application/vnd.trufflehogenterprise+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "X-Thog-Secret") && !strcmp(request->headers[1].value, secret));
    CHECK(!strcmp(request->headers[2].name, "X-Thog-Key") && !strcmp(request->headers[2].value, key));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") &&
          !strcmp(request->headers[3].value, "TruffleHog enterprise-offline"));
}

int main(void)
{
    CHECK(strlen(key) == 25 && strlen(secret) == 44);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_trufflehogenterprise_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 922 && !strcmp(detector->name, "TrufflehogEnterprise"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "thog"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(br_trufflehogenterprise_init(NULL, &error) != 0 && error); free(error);
    char input[240];
    snprintf(input, sizeof(input), "%s %s %s", key, secret, host);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 922, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s %s", key, key, secret, host);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2 && results.items[0].raw.len == strlen(key) && results.items[1].raw.len == strlen(key));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", key, secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);

    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{\"data\":[]}\n", 11}},
                      .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "enterprise-offline"};
    snprintf(input, sizeof(input), "%s %s %s", key, secret, host);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"ok\n", 3};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)"data\n", 5};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 200; http.send_rc = 1; http.send_error = "dial enterprise";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 0; http.send_error = NULL;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);

    unsigned char *long_line = malloc(64 * 1024 + 1);
    CHECK(long_line);
    memset(long_line, 'x', 64 * 1024 + 1);
    http.response.status = 200;
    http.response.body = (br_slice){long_line, 64 * 1024 + 1};
    http.calls = http.releases = 0;
    error = NULL;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "bufio.Scanner: token too long") && !results.len && http.calls == 1);
    free(error); free(long_line);
    http.response.body = (br_slice){(const unsigned char *)"ok\n", 3};
    http.response.body_error = "read failed";
    http.calls = http.releases = 0;
    error = NULL;
    rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                        &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "read failed") && !results.len);
    free(error);
    http.response.body = (br_slice){(const unsigned char *)"data\n", 5};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    return test_finish("TrufflehogEnterprise");
}
