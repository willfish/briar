/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_zerotier_init(const br_detector **out, char **error);

static const char key[] = "AiO4lTwWm7vdj2D0Zf3xdQbQNN3tSyJB";
static int fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char *copy = malloc((size_t)len + 1);
    CHECK(copy);
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.zerotier.com/api/v1/network"));
    CHECK(request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE && request->detector_type == 948);
    CHECK(request->nheaders == 2 && !request->body.len);
    char want[48];
    snprintf(want, sizeof(want), "token %s", key);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, want));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zerotier_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 948 && !strcmp(detector->name, "ZeroTier") && !strcmp(detector->keywords[0], "zerotier"));
    CHECK(strlen(key) == 32 && detector->max_credential_span == -1);
    char input[160];
    snprintf(input, sizeof(input), "zerotier token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 948, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zerotier %s | %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zerotier %s zerotier %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "zerotier%*s%s", gap, "", key);
        results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == (gap == 40 ? 1u : 0u));
        br_results_clear(&results);
    }
    const char *invalid = "zerotier AiO4lTwWm7vdj2D0?f3xdQbQNN3tSyJB";
    results = test_scan(detector, NULL, false, invalid, strlen(invalid));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "zerotier %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial AiO4lTwWm7vdj2D0Zf3xdQbQNN3tSyJB refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!strcmp(results.items[0].verification_error, "dial [REDACTED] refused"));
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 0 && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && results.len == 1 && http.calls == 0);
    free(error);
    br_results_clear(&results);
    return test_finish("zerotier");
}
