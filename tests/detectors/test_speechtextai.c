/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_speechtextai_init(const br_detector **out, char **error);

static const char key[] = "51bb70d3ab4f9e0ecd17ec0a6f8ed289";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    char url[128];
    snprintf(url, sizeof(url),
             "https://api.speechtext.ai/recognize?key=%s&language=en-US&punctuation=true&format=m4a", key);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/octet-stream"));
    CHECK(request->timeout_ms == 5000 && request->detector_type == 849 && !request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_speechtextai_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 849 && !strcmp(detector->keywords[0], "speechtext"));
    char input[160];
    snprintf(input, sizeof(input), "speechtextai token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 849, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "speechtext %s | %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    const char *invalid = "speechtext G1bb70d3ab4f9e0ecd17ec0a6f8ed289";
    results = test_scan(detector, NULL, false, invalid, strlen(invalid));
    CHECK(results.len == 0);

    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key_bytes(&prior, 1, (br_slice){(const unsigned char *)"keep", 4}, "key") == 0);
    CHECK(br_results_push(&kept, &prior) == 0);
    snprintf(input, sizeof(input), "speechtext %s", key);
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept, &error));
    CHECK(error && !strcmp(error, "runtime error: invalid memory address or nil pointer dereference"));
    CHECK(kept.len == 1);
    free(error);
    br_results_clear(&kept);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    return test_finish("speechtextai");
}
