/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_serphouse_init(const br_detector **out, char **error);

static char key[61], other[61];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    test_secret(key, 60, 0);
    test_secret(other, 60, 4);
    key[0] = 'A';
    other[3] = 'Z';
    CHECK(br_serphouse_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_serphouse_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_serphouse_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 613 && !strcmp(detector->name, "Serphouse") && !strcmp(detector->keywords[0], "serphouse"));
    CHECK(!strcmp(detector->description,
                  "Serphouse is a service that provides search engine result page data. "
                  "Serphouse API keys can be used to access this data and perform various operations on it."));
    CHECK(detector->max_credential_span == -1 && detector->state && !detector->clean && !detector->validate_endpoints);
    return detector;
}

static void expect_keys(const br_detector *detector, const void *input, size_t len,
                        const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 613, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512];
    const char *one[] = {key};
    const char *both[] = {key, other};
    snprintf(input, sizeof(input), "serphouse %s", key);
    expect_keys(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "SERPHOUSE=%s", key);
    expect_keys(detector, input, strlen(input), one, 1);
    expect_keys(detector, key, 60, NULL, 0);
    snprintf(input, sizeof(input), "serphouse%*s%s", 40, "", key);
    expect_keys(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "serphouse%*s%s", 41, "", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "serphouse _%s", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "serphouse %s_", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    char bad[61];
    memcpy(bad, key, 61);
    bad[10] = '-';
    snprintf(input, sizeof(input), "serphouse %s", bad);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "serphouse %s\nserphouse %s", key, key);
    const char *dups[] = {key, key};
    expect_keys(detector, input, strlen(input), dups, 2);
    snprintf(input, sizeof(input), "serphouse %s\nserphouse %s", key, other);
    expect_keys(detector, input, strlen(input), both, 2);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *expected = http->user;
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, "https://api.serphouse.com/account/info"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 613);
    CHECK(!request->body.len && !request->dedup_key.len && request->nheaders == 3);
    char authorization[68];
    snprintf(authorization, sizeof(authorization), "Bearer %s", expected);
    CHECK(!strcmp(request->headers[0].name, "Accept") &&
          !strcmp(request->headers[0].value, "application/vnd.serphouse+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "serphouse %s", key);
    const int codes[] = {199, 200, 204, 299, 300, 401, 403, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        test_http http = {.response = {.status = codes[i], .body_error = "ignored"},
                          .inspect = inspect, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 613, key, "key");
        CHECK(results.items[0].verified == (codes[i] >= 200 && codes[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = "boom",
                      .inspect = inspect, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Serphouse");
}
