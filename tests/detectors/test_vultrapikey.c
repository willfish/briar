/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_vultrapikey_init(const br_detector **out, char **error);

static const char key[] = "F7CTEQ0FK6XSPCSG24XMBULREVNG4AL3RTQK";
static const char other[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
    if (want) test_key_result(&results.items[0], 116, want, "key");
    br_results_clear(&results);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.vultr.com/v2/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 116);
    CHECK(!request->body.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    char want[48];
    snprintf(want, sizeof(want), "Bearer %s", key);
    CHECK(!strcmp(request->headers[0].value, want));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_vultrapikey_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_vultrapikey_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_vultrapikey_init(&detector, &error) == 0);
    CHECK(detector->type == 116 && detector->version == 0 && !strcmp(detector->name, "VultrApiKey"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "vultr"));
    CHECK(detector->max_credential_span == -1 && strstr(detector->description, "cloud service provider"));

    char input[256];
    snprintf(input, sizeof(input), "vultr token = '%s'", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "VULTR token = '%s'", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "vultr token = '%s' | '%s'", key, key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "vultr %s vultr %s", key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 116, key, "key");
    test_key_result(&results.items[1], 116, other, "key");
    br_results_clear(&results);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "vultr%*s%s", gap, "", key);
        expect_one(detector, input, gap == 40 ? key : NULL);
    }
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "vultr F7CTEQ0FK6?SPCSG24XMBULREVNG4AL3RTQK");
    expect_one(detector, input, NULL);
    expect_one(detector, "vultr keyword is not close to the real key in the data\n = 'F7CTEQ0FK6XSPCSG24XMBULREVNG4AL3RTQK'", NULL);
    snprintf(input, sizeof(input), "vultr %s_", key);
    expect_one(detector, input, NULL);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "vultr %s", key);
    const int codes[] = {199, 200, 299, 300};
    for (size_t i = 0; i < 4; ++i) {
        http.response.status = codes[i];
        http.calls = http.releases = 0;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (codes[i] >= 200 && codes[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    http.send_rc = 1;
    http.send_error = "connection refused";
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 0;
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 0);
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 0 && !results.items[0].verified);
    br_results_clear(&results);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 7, "prior", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot create VultrApiKey result") && http.calls == 0 && results.len == 1);
    free(error);
    br_results_clear(&results);
    return test_finish("vultrapikey");
}
