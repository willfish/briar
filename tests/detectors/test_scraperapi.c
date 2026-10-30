/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_scraperapi_init(const br_detector **out, char **error);

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_scraperapi_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector && detector->type == 412 && detector->version == 0);
    CHECK(!strcmp(detector->name, "ScraperAPI"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "ScraperAPI is a service that allows users to scrape websites efficiently. "
        "ScraperAPI keys can be used to access and scrape data from various websites."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "scraperapi"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_scraperapi_init(&again, NULL) == 0 && again == detector);
    CHECK(br_scraperapi_init(NULL, &error) != 0 && error != NULL);
    free(error);
    CHECK(br_scraperapi_init(NULL, NULL) != 0);
    return detector;
}

static void expect_keys(const br_detector *detector, const void *input, size_t len,
                        const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 412, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[33], second[33], input[512];
    test_secret(key, 32, 0);
    test_secret(second, 32, 3);
    const char *keys[] = {key, second};
    const struct { const char *format; size_t count; } cases[] = {
        {"scraperapi = '%s'", 1},
        {"SCRAPERAPI: %s", 1},
        {"prefixscraperapisuffix=%s", 1},
        {"%s", 0},
        {"%s scraperapi", 0},
        {"scraperapi%s", 0},
        {"scraperapi _%s", 0},
        {"scraperapi %s_", 0},
        {"scraperapi %.31s", 0},
        {"scraperapi %sq", 0},
        {"scraperapi\r%s", 1},
        {"scraperapi\n%s", 1},
        {"scraperapi %s\nscraperapi %s", 2},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, second);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_keys(detector, input, (size_t)len, keys, cases[i].count);
    }
    expect_keys(detector, NULL, 0, NULL, 0);
    const char *duplicates[] = {key, key};
    snprintf(input, sizeof(input), "scraperapi %s\nscraperapi %s", key, key);
    expect_keys(detector, input, strlen(input), duplicates, 2);

    char upper[33];
    memcpy(upper, key, 33);
    upper[0] = 'A';
    snprintf(input, sizeof(input), "scraperapi %s", upper);
    expect_keys(detector, input, strlen(input), NULL, 0);

    memcpy(input, "scraperapi", 10);
    size_t at = 10;
    for (size_t gap = 40; gap <= 41; ++gap) {
        at = 10;
        for (size_t j = 0; j < gap; ++j) input[at++] = ' ';
        memcpy(input + at, key, 32);
        expect_keys(detector, input, at + 32, keys, gap == 40 ? 1 : 0);
    }
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const char *key = http->user;
    char url[128];
    snprintf(url, sizeof(url), "https://api.scraperapi.com?api_key=%s&url=google.com", key);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 15000);
    CHECK(request->detector_type == 412);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog"));
}

static void test_verification(const br_detector *detector)
{
    char key[33], input[96];
    test_secret(key, 32, 1);
    snprintf(input, sizeof(input), "scraperapi %s", key);
    const struct { int status, send_rc; bool verified; } cases[] = {
        {200, 0, true}, {299, 0, true}, {300, 0, false}, {401, 0, false},
        {500, 0, false}, {200, 1, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body_error = "unread"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_rc ? "dial failed" : NULL,
            .inspect = inspect_request, .user = key,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 412, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results skipped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);

    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results idle = test_scan(detector, &ctx, true, "scraperapi none", 15);
    CHECK(idle.len == 0 && http.calls == 0);
    br_results_clear(&idle);
    br_results unverified = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(unverified.len == 1 && http.calls == 0 && !unverified.items[0].verified);
    br_results_clear(&unverified);

    char *error = NULL;
    br_results out = {0};
    CHECK(detector->scan(detector, &ctx, false, (br_slice){NULL, 1}, &out, &error) != 0 && error);
    free(error);
    CHECK(detector->scan(NULL, &ctx, false, (br_slice){0}, &out, NULL) != 0);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    return test_finish("ScraperAPI");
}
