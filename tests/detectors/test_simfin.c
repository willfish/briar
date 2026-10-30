/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_simfin_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[96];
    snprintf(url, sizeof(url), "https://simfin.com/api/v2/companies/list?api-key=%s", (char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 851);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_simfin_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 851 && !strcmp(detector->name, "SimFin"));
    CHECK(!strcmp(detector->keywords[0], "simfin"));
    char key[33], input[80];
    test_secret(key, 32, 6);
    key[0] = 'A';
    snprintf(input, sizeof(input), "simfin %s", key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 851, key, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "simfin %s\nsimfin %s", key, key);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "simfin %s", key);
    const char *ok = "{\"companies\":[]}";
    const char *bad_body = "{\"error\":\"nope\"}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)ok, strlen(ok)}},
                      .inspect = inspect_request, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results verified = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(verified.len == 1 && verified.items[0].verified);
    br_results_clear(&verified);
    http.response.body = (br_slice){(const unsigned char *)bad_body, strlen(bad_body)};
    http.calls = http.releases = 0;
    br_results rejected = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(rejected.len == 1 && !rejected.items[0].verified);
    br_results_clear(&rejected);
    http.response.status = 500;
    http.response.body = (br_slice){(const unsigned char *)ok, strlen(ok)};
    http.calls = http.releases = 0;
    br_results status = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(status.len == 1 && !status.items[0].verified);
    br_results_clear(&status);
    http.response.status = 200;
    http.response.body_error = "read failed";
    http.calls = http.releases = 0;
    br_results skipped_read = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(skipped_read.len == 0 && http.calls == 1);
    br_results_clear(&skipped_read);
    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 0);
    br_results_clear(&nil);
    return test_finish("SimFin");
}
