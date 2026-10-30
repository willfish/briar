/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_shippo_init(const br_detector **out, char **error);

static const char live[] = "shippo_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char test_key[] = "shippo_test_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.goshippo.com/shippo-accounts?page=1&results=1"));
    CHECK(request->timeout_ms == 5000 && request->profile == BR_HTTP_SANE && request->detector_type == 1060);
    CHECK(request->nheaders == 2 && !request->body.len);
    char want[80];
    snprintf(want, sizeof(want), "ShippoToken %s", live);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, want));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shippo_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1060 && !strcmp(detector->name, "Shippo") && detector->nkeywords == 2);
    CHECK(!strcmp(detector->keywords[0], "shippo_live_") && !strcmp(detector->keywords[1], "shippo_test_"));
    CHECK(detector->max_credential_span == -1 && strlen(live) == 52);
    char input[256];
    snprintf(input, sizeof(input), "token=%s", live);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].redacted, "shippo_live_..."));
    CHECK(results.items[0].raw.len == 52 && !results.items[0].extra_data);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s", test_key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].redacted, "shippo_test_..."));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", live, live);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", live, test_key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    CHECK(!strcmp(results.items[0].redacted, "shippo_live_...") && !strcmp(results.items[1].redacted, "shippo_test_..."));
    br_results_clear(&results);
    const char *short_live = "shippo_live_aaa";
    const char *upper = "shippo_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    results = test_scan(detector, NULL, false, short_live, strlen(short_live));
    CHECK(results.len == 0);
    results = test_scan(detector, NULL, false, upper, strlen(upper));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s", live);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    for (int status = 401; status <= 403; status += 2) {
        http.response.status = status;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 0 && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    CHECK(!strcmp(results.items[0].redacted, "shippo_live_..."));
    br_results_clear(&results);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && results.len == 1 && http.calls == 0);
    free(error);
    br_results_clear(&results);
    return test_finish("shippo");
}
