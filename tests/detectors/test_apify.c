/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct {
    const char *keys[2];
    size_t len;
    bool seen[2];
} expected_requests;

static void make_key(char key[47], size_t shift)
{
    memcpy(key, "apify_api_", 10);
    test_secret(key + 10, 36, shift);
    key[10] = 'B';
    key[22] = '-';
    key[36] = 'Z';
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apify_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 391 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Apify"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Apify is a platform for web scraping and automation. Apify API keys can be "
        "used to access and control Apify actors and tasks."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apify"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_apify_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_apify_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_apify_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_apify_init(NULL, NULL) != 0);
    return detector;
}

static void expect_key(const br_detector *detector, const br_scan_ctx *ctx,
                       const void *input, size_t len, const char *key, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    if (count) {
        CHECK(count == 1);
        test_key_result(&results.items[0], 391, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[47], changed[47], input[256];
    make_key(key, 0);
    CHECK(strlen(key) == 46);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"%s", 1},
        {"'%s'", 1},
        {"x%s", 0},
        {"_%s", 0},
        {"%s_", 0},
        {"%sQ", 0},
        {"%.45s", 0},
        {"\xc3\xa9%s\xc3\xa9", 1},
        {"%s\r\n%s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_key(detector, &ctx, input, (size_t)len, key, cases[i].count);
    }
    expect_key(detector, &ctx, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "apify %s", key + 10);
    expect_key(detector, &ctx, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[0] = 'A';
    expect_key(detector, &ctx, changed, strlen(changed), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[20] = '/';
    expect_key(detector, &ctx, changed, strlen(changed), NULL, 0);
    changed[20] = '_';
    expect_key(detector, &ctx, changed, strlen(changed), NULL, 0);

    /* A payload-leading hyphen is inside the token, not at its word boundary. */
    memcpy(changed, key, sizeof(changed));
    changed[10] = '-';
    expect_key(detector, &ctx, changed, strlen(changed), changed, 1);
    memcpy(changed, key, sizeof(changed));
    changed[45] = '-';
    expect_key(detector, &ctx, changed, strlen(changed), NULL, 0);
    snprintf(input, sizeof(input), "%sQ", changed);
    expect_key(detector, &ctx, input, strlen(input), changed, 1);

    input[0] = '\0';
    memcpy(input + 1, key, 46);
    expect_key(detector, &ctx, input, 47, key, 1);
    memset(key + 10, 'a', 36);
    expect_key(detector, &ctx, key, strlen(key), key, 1);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(expected->len <= sizeof(expected->keys) / sizeof(expected->keys[0]));
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    size_t i = 0;
    for (; i < expected->len; ++i) {
        char url[160];
        snprintf(url, sizeof(url),
                 "https://api.apify.com/v2/acts?token=%s&my=true&offset=10&limit=99&desc=true",
                 expected->keys[i]);
        if (!strcmp(request->url, url)) break;
    }
    CHECK(i < expected->len && !expected->seen[i]);
    expected->seen[i] = true;
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 391);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ?
                  "TruffleHog apify-test" : "TruffleHog"));
}

static void test_unique_keys(const br_detector *detector)
{
    char first[47], second[47], input[256];
    make_key(first, 0);
    make_key(second, 9);
    snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", first, second, first, second);
    for (int verify = 0; verify <= 1; ++verify) {
        expected_requests expected = {.keys = {first, second}, .len = 2};
        test_http http = {
            .response = {.status = 200, .body_error = "ignored body read failure"},
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 2 && http.calls == (verify ? 2u : 0u) && http.releases == http.calls);
        bool seen[2] = {0};
        /* Source map iteration is unordered; require both unique keys once. */
        for (size_t i = 0; i < results.len; ++i) {
            const br_result *result = &results.items[i];
            CHECK(result->raw.data && result->raw.len == 46);
            size_t j = !memcmp(result->raw.data, first, 46) ? 0 : 1;
            CHECK(!seen[j]);
            seen[j] = true;
            test_key_result(result, 391, expected.keys[j], "key");
            CHECK(result->verified == (bool)verify && !result->verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_verification(const br_detector *detector)
{
    char key[47], sensitive[160];
    make_key(key, 0);
    snprintf(sensitive, sizeof(sensitive), "token %s failed; again %s", key, key);
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {404, 0, NULL, false, "unexpected status code: 404"},
        {429, 0, NULL, false, "unexpected status code: 429"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, 1, "context canceled", false, "context canceled"},
        {200, 1, sensitive, false, sensitive},
        {200, 1, NULL, false, "HTTP transport failed"},
    };
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.keys = {key}, .len = 1};
        test_http http = {
            .response = {.status = cases[i].status,
                         .body = {body, sizeof(body)}, .body_error = sensitive},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "apify-test"};
        br_results results = test_scan(detector, &ctx, true, key, strlen(key));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        test_key_result(result, 391, key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error);
            /* Compare the source's unredacted error policy without logging causes. */
            CHECK(!strcmp(result->verification_error, cases[i].error));
        } else {
            CHECK(!result->verification_error);
        }
        br_results_clear(&results);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const char unrelated[] = "apify has no token here";
    br_results results = test_scan(detector, &ctx, true, unrelated, sizeof(unrelated) - 1);
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_unique_keys(detector);
    test_verification(detector);
    return test_finish("Apify");
}
