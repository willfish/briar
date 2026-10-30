/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_telnyx_init(const br_detector **out, char **error);

static char key[59], other[59];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    test_secret(key, 58, 1);
    test_secret(other, 58, 6);
    memmove(key + 3, key, 55);
    memcpy(key, "KEY", 3);
    key[58] = 0;
    memmove(other + 3, other, 55);
    memcpy(other, "KEY", 3);
    other[58] = 0;
    CHECK(br_telnyx_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_telnyx_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_telnyx_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 610 && !strcmp(detector->name, "Telnyx"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "telnyx"));
    CHECK(!strcmp(detector->description, "Telnyx is a communications platform offering voice, messaging, and other communication services. Telnyx keys can be used to access and manage these services."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_keys(const br_detector *detector, const char *input, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 610, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512];
    const char *one[] = {key}, *both[] = {key, other}, *dups[] = {key, key};
    snprintf(input, sizeof(input), "telnyx %s", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "TELNYX %s", key);
    expect_keys(detector, input, one, 1);
    expect_keys(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "telnyx%*s%s", 40, "", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "telnyx%*s%s", 41, "", key);
    expect_keys(detector, input, NULL, 0);
    char bad[59];
    memcpy(bad, key, sizeof(bad));
    bad[4] = '!';
    snprintf(input, sizeof(input), "telnyx %s", bad);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "telnyx %s\ntelnyx %s", key, key);
    expect_keys(detector, input, dups, 2);
    snprintf(input, sizeof(input), "telnyx %s\ntelnyx %s", key, other);
    expect_keys(detector, input, both, 2);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *expected = http->user;
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.telnyx.com/v2/messaging_profiles"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 610);
    CHECK(!request->body.len && !request->dedup_key.len && request->nheaders == 3);
    char authorization[160];
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/vnd.telnyx+json; version=3"));
    snprintf(authorization, sizeof(authorization), "Bearer %s", expected);
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

static void verification(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "telnyx %s", key);
    const int codes[] = {199, 200, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        test_http http = {.response = {.status = codes[i], .body_error = "ignored"}, .inspect = inspect, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 610, key, "key");
        CHECK(results.items[0].verified == (codes[i] >= 200 && codes[i] < 300) && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    test_http http = {.inspect = inspect, .user = key, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Telnyx");
}
