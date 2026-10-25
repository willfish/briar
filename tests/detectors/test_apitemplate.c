/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct {
    const char *keys[2];
    size_t len;
    bool seen[2];
} expected_requests;

static void make_key(char key[40], size_t shift)
{
    test_secret(key, 39, shift);
    key[0] = 'B';
    key[20] = 'Z';
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apitemplate_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 768 && detector->version == 0);
    CHECK(!strcmp(detector->name, "APITemplate"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "APITemplate is a service used to generate documents and images from templates. "
        "APITemplate API keys can be used to access and generate these documents and images."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apitemplate"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_apitemplate_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_apitemplate_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_apitemplate_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_apitemplate_init(NULL, NULL) != 0);
    return detector;
}

static void expect_key(const br_detector *detector, const br_scan_ctx *ctx,
                       const void *input, size_t len, const char *key, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    if (count) {
        CHECK(count == 1);
        test_key_result(&results.items[0], 768, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[40], changed[40], input[256];
    make_key(key, 0);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"apitemplate = '%s'", 1},
        {"APITEMPLATE: %s", 1},
        {"prefixapitemplatesuffix=%s", 1},
        {"%s", 0},
        {"%s apitemplate", 0},
        {"apitemplate%s", 0},
        {"apitemplate _%s", 0},
        {"apitemplate %s_", 0},
        {"apitemplate %.38s", 0},
        {"apitemplate %sQ", 0},
        {"apitemplate\r\n%s", 1},
        {"apitemplate %s\napitemplate %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_key(detector, &ctx, input, (size_t)len, key, cases[i].count);
    }
    expect_key(detector, &ctx, NULL, 0, NULL, 0);
    const char prefix[] = "apitemplate";
    size_t prefix_len = sizeof(prefix) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key, sizeof(key));
        expect_key(detector, &ctx, input, strlen(input), key, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, 39);
    expect_key(detector, &ctx, input, sizeof(prefix) + 39, key, 1);
    memcpy(changed, key, sizeof(changed));
    changed[19] = '-';
    snprintf(input, sizeof(input), "apitemplate %s", changed);
    expect_key(detector, &ctx, input, strlen(input), NULL, 0);
    changed[19] = '_';
    snprintf(input, sizeof(input), "apitemplate %s", changed);
    expect_key(detector, &ctx, input, strlen(input), NULL, 0);
    memset(key, 'a', 39);
    snprintf(input, sizeof(input), "apitemplate %s", key);
    expect_key(detector, &ctx, input, strlen(input), key, 1);
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
    CHECK(!strcmp(request->url, "https://api.apitemplate.io/v1/list-templates"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 768);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    size_t content = 0, auth = 0, agent = 0;
    for (size_t h = 0; h < request->nheaders; ++h) {
        const br_header *header = &request->headers[h];
        if (!strcmp(header->name, "Content-Type")) {
            ++content;
            CHECK(!strcmp(header->value, "application/json"));
        } else if (!strcmp(header->name, "X-API-KEY")) {
            ++auth;
            size_t i = 0;
            for (; i < expected->len; ++i)
                if (!strcmp(header->value, expected->keys[i])) break;
            CHECK(i < expected->len && !expected->seen[i]);
            expected->seen[i] = true;
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ?
                          "TruffleHog apitemplate-test" : "TruffleHog"));
        } else {
            CHECK(!"unexpected APITemplate request header");
        }
    }
    CHECK(content == 1 && auth == 1 && agent == 1);
}

static void test_unique_keys(const br_detector *detector)
{
    char first[40], second[40], input[256];
    make_key(first, 0);
    make_key(second, 9);
    snprintf(input, sizeof(input), "apitemplate %s\napitemplate %s\napitemplate %s\napitemplate %s",
             first, second, first, second);
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
            CHECK(result->raw.data && result->raw.len == 39);
            size_t j = !memcmp(result->raw.data, first, 39) ? 0 : 1;
            CHECK(!seen[j]);
            seen[j] = true;
            test_key_result(result, 768, expected.keys[j], "key");
            CHECK(result->verified == (bool)verify && !result->verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_verification(const br_detector *detector)
{
    char key[40], input[96], sensitive[160];
    make_key(key, 0);
    snprintf(input, sizeof(input), "apitemplate %s", key);
    snprintf(sensitive, sizeof(sensitive), "key %s failed; again %s", key, key);
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
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "apitemplate-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        test_key_result(result, 768, key, "key");
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
    br_results results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_unique_keys(detector);
    test_verification(detector);
    return test_finish("APITemplate");
}
