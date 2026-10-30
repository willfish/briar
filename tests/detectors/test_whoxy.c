/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_whoxy_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[96];
    snprintf(url, sizeof(url), "https://api.whoxy.com/?key=%s&account=balance", (char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 482);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_whoxy_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 482 && !strcmp(detector->keywords[0], "whoxy"));
    char key[34], input[80];
    test_secret(key, 33, 7);
    snprintf(input, sizeof(input), "whoxy %s", key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 482, key, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "whoxy %s\nwhoxy %s", key, key);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);
    snprintf(input, sizeof(input), "whoxy %s", key);
    const char *ok = "{\"status\": 1}";
    const char *tight = "{\"status\":1}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)ok, strlen(ok)}},
                      .inspect = inspect_request, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results verified = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(verified.len == 1 && verified.items[0].verified);
    br_results_clear(&verified);
    http.response.body = (br_slice){(const unsigned char *)tight, strlen(tight)};
    http.calls = http.releases = 0;
    br_results tight_result = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(tight_result.len == 1 && !tight_result.items[0].verified);
    br_results_clear(&tight_result);
    http.response.body = (br_slice){(const unsigned char *)ok, strlen(ok)};
    http.response.body_error = "read failed";
    http.calls = http.releases = 0;
    br_results skipped = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 0);
    br_results_clear(&nil);
    return test_finish("Whoxy");
}
