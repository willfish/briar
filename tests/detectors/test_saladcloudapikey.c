/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_saladcloudapikey_init(const br_detector **out, char **error);

static const char key[] = "salad_cloud_org_zYLYVpmHJ3oksnZ0l9RHJCf1ib2QvJOJztWukwYjtjB1kDIGP";
static const char user[] = "salad_cloud_user_HZdqHUSBFLJI7LZjo1UcDORHIdi8wet37OMP01YTep82tdimF";
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
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.salad.com/api/public"));
    CHECK(request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE && request->detector_type == 1001);
    CHECK(request->nheaders == 2 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Salad-Api-Key") && !strcmp(request->headers[0].value, key));
}

static void expect_guide(const br_result *result)
{
    struct json_object *guide = NULL;
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, "rotation_guide", &guide));
    CHECK(!strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/saladcloudapikey/"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_saladcloudapikey_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1001 && !strcmp(detector->name, "SaladCloudApiKey"));
    CHECK(!strcmp(detector->keywords[0], "salad_cloud_") && detector->max_credential_span == -1);
    char input[256];
    snprintf(input, sizeof(input), "api_key = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].raw.len == strlen(key));
    expect_guide(&results.items[0]);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", user, user);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", key, user);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, "salad_cloud_", 12);
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 204}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].extra_data && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 0 && !results.items[0].extra_data);
    CHECK(!strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && results.len == 1);
    free(error);
    br_results_clear(&results);
    return test_finish("saladcloudapikey");
}
