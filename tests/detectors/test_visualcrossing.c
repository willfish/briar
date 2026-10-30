/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_visualcrossing_init(const br_detector **out, char **error);

static char key[26], other[26];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    test_secret(key, 25, 1);
    test_secret(other, 25, 6);
    for (char *p = key; *p; ++p) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);
    for (char *p = other; *p; ++p) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);
    CHECK(br_visualcrossing_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_visualcrossing_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_visualcrossing_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 419 && !strcmp(detector->name, "VisualCrossing"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "visualcrossing"));
    CHECK(!strcmp(detector->description, "Visual Crossing provides weather data services. Visual Crossing API keys can be used to access weather data and services."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_keys(const br_detector *detector, const char *input, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 419, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512];
    const char *one[] = {key}, *both[] = {key, other}, *dups[] = {key, key};
    snprintf(input, sizeof(input), "visualcrossing %s", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "VISUALCROSSING %s", key);
    expect_keys(detector, input, one, 1);
    expect_keys(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "visualcrossing%*s%s", 40, "", key);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "visualcrossing%*s%s", 41, "", key);
    expect_keys(detector, input, NULL, 0);
    char bad[26];
    memcpy(bad, key, sizeof(bad));
    bad[4] = 'a';
    snprintf(input, sizeof(input), "visualcrossing %s", bad);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "visualcrossing %s\nvisualcrossing %s", key, key);
    expect_keys(detector, input, dups, 2);
    snprintf(input, sizeof(input), "visualcrossing %s\nvisualcrossing %s", key, other);
    expect_keys(detector, input, both, 2);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *expected = http->user;
    CHECK(ctx && !strcmp(request->method, "GET"));
        char url[124];
    snprintf(url, sizeof(url), "https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/LA?key=%s", expected); CHECK(!strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 419);
    CHECK(!request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

static void verification(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "visualcrossing %s", key);
    const int codes[] = {199, 200, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        test_http http = {.response = {.status = codes[i], .body_error = "ignored"}, .inspect = inspect, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 419, key, "key");
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
    return test_finish("VisualCrossing");
}
