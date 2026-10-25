/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

#include <ctype.h>
#include <time.h>

typedef struct {
    const char *keys[2];
    size_t len;
    bool seen[2];
    uint32_t timeout_limit; /* Zero requires the detector's full 10-second timeout. */
} expected_requests;

static void make_key(char key[33], size_t shift)
{
    test_secret(key, 32, shift);
    for (size_t i = 0; i < 32; ++i) key[i] = (char)toupper((unsigned char)key[i]);
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aletheiaapi_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 522 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AletheiaApi"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "AletheiaApi is a service providing financial data. "
        "AletheiaApi keys can be used to access this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "aletheiaapi"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_aletheiaapi_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_aletheiaapi_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_aletheiaapi_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_aletheiaapi_init(NULL, NULL) != 0);
    return detector;
}

static void expect_key(const br_detector *detector, const br_scan_ctx *ctx,
                       const void *input, size_t len, const char *key, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    if (count) {
        CHECK(count == 1);
        test_key_result(&results.items[0], 522, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[33], changed[33], input[256];
    make_key(key, 0);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"aletheiaapi = '%s'", 1},
        {"ALETHEIAAPI: %s", 1},
        {"prefixaletheiaapisuffix=%s", 1},
        {"%s", 0},
        {"%s aletheiaapi", 0},
        {"aletheiaapi%s", 0},
        {"aletheiaapi _%s", 0},
        {"aletheiaapi %s_", 0},
        {"aletheiaapi %.31s", 0},
        {"aletheiaapi %sQ", 0},
        {"aletheiaapi a%.31s", 0},
        {"aletheiaapi\r\n%s", 1},
        {"aletheiaapi %s\naletheiaapi %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_key(detector, &ctx, input, (size_t)len, key, cases[i].count);
    }
    expect_key(detector, &ctx, NULL, 0, NULL, 0);
    const char prefix[] = "aletheiaapi";
    size_t prefix_len = sizeof(prefix) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key, sizeof(key));
        expect_key(detector, &ctx, input, strlen(input), key, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, 32);
    expect_key(detector, &ctx, input, sizeof(prefix) + 32, key, 1);

    memcpy(changed, key, sizeof(changed));
    changed[16] = '-';
    snprintf(input, sizeof(input), "aletheiaapi %s", changed);
    expect_key(detector, &ctx, input, strlen(input), NULL, 0);
    for (size_t i = 0; i < 32; ++i) changed[i] = (char)tolower((unsigned char)key[i]);
    snprintf(input, sizeof(input), "aletheiaapi %s", changed);
    expect_key(detector, &ctx, input, strlen(input), NULL, 0);
    memset(key, 'A', 32);
    snprintf(input, sizeof(input), "aletheiaapi %s", key);
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
    CHECK(!strcmp(request->url, "https://api.aletheiaapi.com/StockData?symbol=msft&summary=true"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 522);
    if (expected->timeout_limit) {
        CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    } else {
        CHECK(request->timeout_ms == 10000);
    }
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t key_headers = 0, agent_headers = 0;
    for (size_t h = 0; h < request->nheaders; ++h) {
        const br_header *header = &request->headers[h];
        if (!strcmp(header->name, "Key")) {
            ++key_headers;
            size_t i = 0;
            for (; i < expected->len; ++i)
                if (!strcmp(header->value, expected->keys[i])) break;
            CHECK(i < expected->len && !expected->seen[i]);
            expected->seen[i] = true;
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent_headers;
            CHECK(!strcmp(header->value, ctx->user_agent ?
                          "TruffleHog aletheia-test" : "TruffleHog"));
        } else {
            CHECK(!"unexpected AletheiaApi request header");
        }
    }
    CHECK(key_headers == 1 && agent_headers == 1);
}

static void test_unique_keys(const br_detector *detector)
{
    char first[33], second[33], input[256];
    make_key(first, 0);
    make_key(second, 11);
    snprintf(input, sizeof(input), "aletheiaapi %s\naletheiaapi %s\naletheiaapi %s\naletheiaapi %s",
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
        /* Map iteration has no defined order; require both unique keys once. */
        for (size_t i = 0; i < results.len; ++i) {
            const br_result *result = &results.items[i];
            CHECK(result->raw.data && result->raw.len == 32);
            size_t j = !memcmp(result->raw.data, first, 32) ? 0 : 1;
            CHECK(!seen[j]);
            seen[j] = true;
            test_key_result(result, 522, expected.keys[j], "key");
            CHECK(result->verified == (bool)verify && !result->verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_verification(const br_detector *detector)
{
    char key[33], input[96], sensitive_error[128];
    make_key(key, 0);
    snprintf(input, sizeof(input), "aletheiaapi %s", key);
    snprintf(sensitive_error, sizeof(sensitive_error), "Key=%s failed; key again=%s", key, key);
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
        {429, 0, NULL, false, "unexpected status code: 429"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, 1, "context canceled", false, "context canceled"},
        {200, 1, sensitive_error, false, sensitive_error},
        {200, 1, NULL, false, "HTTP transport failed"},
    };
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.keys = {key}, .len = 1};
        test_http http = {
            .response = {.status = cases[i].status,
                         .body = {body, sizeof(body)}, .body_error = sensitive_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "aletheia-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        test_key_result(result, 522, key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error);
            /* Upstream omits secret arguments; compare without logging the cause. */
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

static void test_context_deadline(const br_detector *detector)
{
    char key[33], input[96];
    make_key(key, 0);
    snprintf(input, sizeof(input), "aletheiaapi %s", key);
    expected_requests expected = {.keys = {key}, .len = 1, .timeout_limit = 3000};
    test_http http = {
        .response = {.status = 200}, .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    br_scan_ctx ctx = {
        .transport = &transport,
        .deadline_monotonic_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 +
                                 expected.timeout_limit,
    };
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], 522, key, "key");
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    ctx.deadline_monotonic_ms = 1;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
    test_key_result(&results.items[0], 522, key, "key");
    CHECK(!results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "context deadline exceeded"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_unique_keys(detector);
    test_verification(detector);
    test_context_deadline(detector);
    return test_finish("AletheiaApi");
}
