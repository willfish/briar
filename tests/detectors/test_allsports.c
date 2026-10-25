/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct {
    const char *keys[2];
    size_t len;
    bool seen[2];
} expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_allsports_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 473 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Allsports"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Allsports API keys can be used to access and interact with the Allsports API, "
        "allowing retrieval of sports data and other related operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "allsports"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_allsports_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_allsports_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_allsports_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_allsports_init(NULL, NULL) != 0);
    return detector;
}

static void expect_key(const br_detector *detector, const br_scan_ctx *ctx,
                       const void *input, size_t len, const char *key, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    if (count) {
        CHECK(count == 1);
        test_key_result(&results.items[0], 473, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[65], changed[65], input[256];
    test_secret(key, 64, 0);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"allsports = '%s'", 1},
        {"ALLSPORTS: %s", 1},
        {"prefixallsportssuffix=%s", 1},
        {"%s", 0},
        {"%s allsports", 0},
        {"allsports%s", 0},
        {"allsports _%s", 0},
        {"allsports %s_", 0},
        {"allsports %.63s", 0},
        {"allsports %sq", 0},
        {"allsports Z%.63s", 0},
        {"allsports\r\n%s", 1},
        {"allsports %s\nallsports %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_key(detector, &ctx, input, (size_t)len, key, cases[i].count);
    }
    expect_key(detector, &ctx, NULL, 0, NULL, 0);
    const char prefix[] = "allsports";
    size_t prefix_len = sizeof(prefix) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key, sizeof(key));
        expect_key(detector, &ctx, input, strlen(input), key, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, 64);
    expect_key(detector, &ctx, input, sizeof(prefix) + 64, key, 1);
    memcpy(changed, key, sizeof(changed));
    changed[32] = '-';
    snprintf(input, sizeof(input), "allsports %s", changed);
    expect_key(detector, &ctx, input, strlen(input), NULL, 0);
    memset(key, 'a', 64);
    snprintf(input, sizeof(input), "allsports %s", key);
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
    size_t i = 0;
    for (; i < expected->len; ++i) {
        char url[160];
        snprintf(url, sizeof(url),
                 "https://apiv2.allsportsapi.com/football/?met=Countries&APIkey=%s", expected->keys[i]);
        if (!strcmp(request->url, url)) break;
    }
    CHECK(i < expected->len && !expected->seen[i]);
    expected->seen[i] = true;
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 473);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    /* Upstream adds neither authentication headers nor Accept. */
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ?
                  "TruffleHog allsports-test" : "TruffleHog"));
}

static void test_unique_keys(const br_detector *detector)
{
    char first[65], second[65], input[320];
    test_secret(first, 64, 0);
    test_secret(second, 64, 11);
    snprintf(input, sizeof(input), "allsports %s\nallsports %s\nallsports %s\nallsports %s",
             first, second, first, second);
    for (int verify = 0; verify <= 1; ++verify) {
        expected_requests expected = {.keys = {first, second}, .len = 2};
        test_http http = {
            .response = {.status = 200}, .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 2 && http.calls == (verify ? 2u : 0u) && http.releases == http.calls);
        bool seen[2] = {0};
        /* Upstream iterates a map, so require the unique set without imposing order. */
        for (size_t i = 0; i < results.len; ++i) {
            const br_result *result = &results.items[i];
            CHECK(result->raw.data && result->raw.len == 64);
            size_t j = !memcmp(result->raw.data, first, 64) ? 0 : 1;
            CHECK(!seen[j]);
            seen[j] = true;
            test_key_result(result, 473, expected.keys[j], "key");
            CHECK(result->verified == (bool)verify && !result->verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_verification(const br_detector *detector)
{
    char key[65], input[128], sensitive_error[160];
    test_secret(key, 64, 0);
    snprintf(input, sizeof(input), "allsports %s", key);
    snprintf(sensitive_error, sizeof(sensitive_error), "response for APIkey=%s failed", key);
    const unsigned char marker[] = "Wrong login credentials";
    const unsigned char surrounded[] = "prefixWrong login credentialssuffix";
    const unsigned char after_nul[] = "accepted\0Wrong login credentials";
    const unsigned char wrong_case[] = "wrong login credentials WRONG LOGIN CREDENTIALS";
    const unsigned char incomplete[] = "Wrong login credential";
    const unsigned char binary[] = {0, 0xff, 'o', 'k'};
    const struct {
        int status;
        br_slice body;
        const char *body_error;
        int send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {.status = 200, .verified = true},
        {.status = 200, .body = {binary, sizeof(binary)}, .verified = true},
        {.status = 200, .body = {marker, sizeof(marker) - 1}},
        {.status = 200, .body = {surrounded, sizeof(surrounded) - 1}},
        {.status = 200, .body = {after_nul, sizeof(after_nul) - 1}},
        {.status = 200, .body = {wrong_case, sizeof(wrong_case) - 1}, .verified = true},
        {.status = 200, .body = {incomplete, sizeof(incomplete) - 1}, .verified = true},
        {.status = 200, .body = {binary, sizeof(binary)},
         .body_error = sensitive_error, .error = sensitive_error},
        {.status = 200, .body = {marker, sizeof(marker) - 1},
         .body_error = "partial body read failed", .error = "partial body read failed"},
        {.status = 401, .body = {marker, sizeof(marker) - 1}, .body_error = sensitive_error},
        {.status = 403, .body = {marker, sizeof(marker) - 1}, .body_error = sensitive_error},
        {.status = 201, .body_error = sensitive_error, .error = "unexpected status code: 201"},
        {.status = 429, .body_error = sensitive_error, .error = "unexpected status code: 429"},
        {.status = 500, .body_error = sensitive_error, .error = "unexpected status code: 500"},
        {.status = 200, .send_rc = 1,
         .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = 1,
         .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = 1, .send_error = sensitive_error, .error = sensitive_error},
        {.status = 200, .send_rc = 1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.keys = {key}, .len = 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = cases[i].body,
                         .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "allsports-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        test_key_result(result, 473, key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error);
            /* Source omits secret arguments; compare without logging the cause. */
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
    return test_finish("Allsports");
}
