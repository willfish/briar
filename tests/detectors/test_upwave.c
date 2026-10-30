/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_upwave_init(const br_detector **out, char **error);

static const char key[] = "mgepiy2lx8tttu5h45efviri2ngz83y0";
static const char other[] = "abcdefghijklmnopqrstuvwxyz012345";
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

static void expect_one(const br_detector *detector, const char *text, const char *want)
{
    br_results results = test_scan(detector, NULL, false, text, strlen(text));
    CHECK(results.len == (want ? 1u : 0u));
    if (want) test_key_result(&results.items[0], 679, want, "key");
    br_results_clear(&results);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.upwave.io/workspaces/"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 679);
    CHECK(!request->body.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    char want[48];
    snprintf(want, sizeof(want), "Token %s", key);
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, want));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_upwave_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 679 && !strcmp(detector->name, "Upwave") && !strcmp(detector->keywords[0], "upwave"));
    CHECK(detector->max_credential_span == -1 && strstr(detector->description, "project management"));
    char input[192];
    snprintf(input, sizeof(input), "upwave token = '%s'", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "UPWAVE %s", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "upwave %s | %s", key, key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "upwave %s upwave %s", key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "upwave%*s%s", gap, "", key);
        expect_one(detector, input, gap == 40 ? key : NULL);
    }
    expect_one(detector, key, NULL);
    expect_one(detector, "upwave mgepiy2lx8tttu5h?5efviri2ngz83y0", NULL);
    expect_one(detector, "upwave keyword is not close to the real key in the data\n = 'mgepiy2lx8tttu5h45efviri2ngz83y0'", NULL);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "upwave %s", key);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 300;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "timeout";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 0);
    br_results_clear(&results);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 7, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && results.len == 1 && !http.calls);
    free(error);
    br_results_clear(&results);
    return test_finish("upwave");
}
