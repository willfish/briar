/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_planyo_init(const br_detector **out, char **error);

static const char key[] = "big57xmqvemmsopa2s7s3805oo70dzxk7subgcao8zerjg89ze8walz5si63x7";
static const char other[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
    if (want) test_key_result(&results.items[0], 614, want, "key");
    br_results_clear(&results);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char url[160];
    snprintf(url, sizeof(url), "https://www.planyo.com/rest/?method=get_site_info&api_key=%s", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 614);
    CHECK(!request->body.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.planyo+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
}

static br_results verify_with(const br_detector *detector, test_http *http, const char *input, const char *body, int status)
{
    http->response = (br_http_response){.status = status, .body = {(const unsigned char *)body, body ? strlen(body) : 0}};
    http->calls = http->releases = 0;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_planyo_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 614 && !strcmp(detector->name, "Planyo") && !strcmp(detector->keywords[0], "planyo"));
    CHECK(strlen(key) == 62 && strlen(other) == 62);
    char input[256];
    snprintf(input, sizeof(input), "planyo token = '%s'", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "Planyo %s | %s", key, key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "planyo %s planyo %s", key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "planyo%*s%s", gap, "", key);
        expect_one(detector, input, gap == 40 ? key : NULL);
    }
    expect_one(detector, "planyo big57xmqvemmsopa2s7s3805oo70dzx?7subgcao8zerjg89ze8walz5si63x7", NULL);
    expect_one(detector, "planyo keyword is not close to the real key in the data\n = 'big57xmqvemmsopa2s7s3805oo70dzxk7subgcao8zerjg89ze8walz5si63x7'", NULL);

    test_http http = {.inspect = inspect};
    snprintf(input, sizeof(input), "planyo %s", key);
    results = verify_with(detector, &http, input, "{\"data\":1}", 200);
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    results = verify_with(detector, &http, input, "Your Planyo site has expired", 299);
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    results = verify_with(detector, &http, input, "metadata", 200);
    CHECK(results.items[0].verified);
    br_results_clear(&results);
    results = verify_with(detector, &http, input, "Data", 200);
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    results = verify_with(detector, &http, input, "data", 199);
    CHECK(!results.items[0].verified);
    br_results_clear(&results);
    http.response = (br_http_response){.status = 200, .body_error = "unexpected EOF"};
    http.calls = http.releases = 0;
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial failed";
    http.response.body_error = NULL;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 0);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 3, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot create Planyo result") && results.len == 1);
    free(error);
    br_results_clear(&results);
    return test_finish("planyo");
}
