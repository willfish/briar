/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_sumologickey_init(const br_detector **, char **);
extern int br_sumologickey_set_configured_endpoints(const char *const *, size_t, char **);
extern void br_sumologickey_set_cloud_endpoint(const char *);
extern void br_sumologickey_use_cloud_endpoint(bool);
extern void br_sumologickey_use_found_endpoints(bool);
extern size_t br_sumologickey_configured_count(void);
extern const char *br_sumologickey_configured_at(size_t);

static char id[15], key[65];
static const char *expect_url;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->url, expect_url));
    CHECK(request->nheaders == 2 && !strncmp(request->headers[0].value, "Basic ", 6));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog") && request->timeout_ms == 5000);
    (void)http;
}

static const char *extra(const br_result *result, const char *name)
{
    br_json *item = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &item)) return NULL;
    return json_object_get_string(item);
}

int main(void)
{
    memcpy(id, "suABCDEFGHIJKL", 15);
    memset(key, 'a', 64);
    key[64] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sumologickey_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 123 && detector->max_credential_span == 1024 && !strcmp(detector->cloud_endpoint, "api.sumologic.com"));
    CHECK(br_sumologickey_set_configured_endpoints(NULL, 0, &error) != 0 && error);
    free(error);
    error = NULL;
    const char *endpoints[] = {"one.example", "one.example", "two.example"};
    CHECK(br_sumologickey_set_configured_endpoints(endpoints, 3, &error) == 0 && !error);
    CHECK(br_sumologickey_configured_count() == 2 && !strcmp(br_sumologickey_configured_at(1), "two.example"));
    br_sumologickey_set_cloud_endpoint("ignored.example");
    br_sumologickey_use_cloud_endpoint(true);
    br_sumologickey_use_found_endpoints(true);
    char input[192];
    snprintf(input, sizeof(input), "sumo %s %s", id, key);
    expect_url = "https://api.sumologic.com/api/v1/users";
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(results.items[0].raw_v2.data && strstr((char *)results.items[0].raw_v2.data, "\"url\":\"api.sumologic.com\""));
    CHECK(!strcmp(extra(&results.items[0], "rotation_guide"), "https://howtorotate.com/docs/tutorials/sumologic/"));
    br_results_clear(&results);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].raw_v2.data && !strstr((char *)results.items[0].raw_v2.data, "url"));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sumo %s %s api.eu.sumologic.com", id, key);
    expect_url = "https://api.eu.sumologic.com/api/v1/users";
    http.response.status = 200;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls >= 1);
    CHECK(strstr((char *)results.items[0].raw_v2.data, "api.eu.sumologic.com"));
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(strstr((char *)results.items[0].raw_v2.data, "api.eu.sumologic.com"));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sumo %s %s", key, key);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].raw_v2.data);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sumo %s %s", id, key);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.calls == calls);
    br_results_clear(&results);
    printf("sumologickey: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
