/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[33], other_key[33];
typedef struct {
    const char *const *keys;
    size_t count;
    uint32_t timeout_limit;
} expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aviationstack_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 564 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AviationStack") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AviationStack is a service providing real-time flight status and aviation data. "
        "The API key can be used to access this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "aviationstack"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_aviationstack_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_aviationstack_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_aviationstack_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_aviationstack_init(NULL, NULL) != 0);
    return detector;
}

static void expect_results(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           const void *input, size_t len, const char *const *keys, size_t count,
                           bool verified, const char *error)
{
    br_results results = test_scan(detector, ctx, verify, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 564, keys[i], "key");
        CHECK(results.items[i].verified == verified);
        if (error) {
            CHECK(results.items[i].verification_error);
            CHECK(!strcmp(results.items[i].verification_error, error));
            CHECK(!strstr(results.items[i].verification_error, keys[i]));
        } else CHECK(!results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[33];
    const char *one[] = {key};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"aviationstack = '%s'", 1}, {"AVIATIONSTACK: %s", 1},
        {"prefixAVIATIONSTACKsuffix=%s", 1},
        {"%s", 0}, {"%s aviationstack", 0}, {"aviationstack%s", 0},
        {"aviationstack _%s", 0}, {"aviationstack %s_", 0},
        {"aviationstack %sQ", 0}, {"aviationstack %.31s", 0},
        {"aviationstack\r\n%s", 1}, {"aviationstack %s %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, other_key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_results(detector, &ctx, false, input, (size_t)len, one, cases[i].count, false, NULL);
    }
    expect_results(detector, &ctx, false, NULL, 0, NULL, 0, false, NULL);
    const char prefix[] = "aviationstack";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, key, sizeof(key));
        expect_results(detector, &ctx, false, input, strlen(input), one, gap == 40 ? 1 : 0, false, NULL);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, 32);
    expect_results(detector, &ctx, false, input, sizeof(prefix) + 32, one, 1, false, NULL);
    memcpy(changed, key, sizeof(changed));
    changed[12] = 'Z';
    snprintf(input, sizeof(input), "aviationstack %s", changed);
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0, false, NULL);
    changed[12] = '-';
    snprintf(input, sizeof(input), "aviationstack %s", changed);
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0, false, NULL);
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "aviationstack %s", changed);
    expect_results(detector, &ctx, false, input, strlen(input), low_entropy, 1, false, NULL);
    const char *three[] = {key, other_key, key};
    snprintf(input, sizeof(input), "aviationstack %s\naviationstack %s\naviationstack %s", key, other_key, key);
    expect_results(detector, &ctx, false, input, strlen(input), three, 3, false, NULL);
    CHECK(!http.calls && !http.releases);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    char url[128];
    snprintf(url, sizeof(url), "https://api.aviationstack.com/v1/flights?access_key=%s",
             expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 564);
    if (expected->timeout_limit) {
        CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
        CHECK(request->timeout_ms < 10000);
    } else CHECK(request->timeout_ms == 10000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* Only the shared User-Agent, no provider headers. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ?
                  "TruffleHog aviationstack-test" : "TruffleHog"));
}

static void test_occurrences(const br_detector *detector)
{
    char input[160];
    const char *keys[] = {key, other_key, key};
    expected_requests expected = {.keys = keys, .count = 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored drain failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "aviationstack %s\naviationstack %s\naviationstack %s", key, other_key, key);
    expect_results(detector, &ctx, true, input, strlen(input), keys, 3, true, NULL);
    CHECK(http.calls == 3 && http.releases == 3);
}

static void test_verification(const br_detector *detector)
{
    char input[64], sensitive[160];
    snprintf(input, sizeof(input), "aviationstack %s", key);
    snprintf(sensitive, sizeof(sensitive), "request access_key=%s failed; again %s", key, key);
    const char *redacted = "request access_key=[REDACTED] failed; again [REDACTED]";
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    const struct {
        int status, send_rc;
        const char *body_error, *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {.status = 200, .verified = true},
        {.status = 200, .body_error = sensitive, .verified = true},
        {.status = 401, .body_error = sensitive},
        {.status = 201, .body_error = sensitive, .error = "unexpected status code: 201"},
        {.status = 204, .body_error = sensitive, .error = "unexpected status code: 204"},
        {.status = 403, .body_error = sensitive, .error = "unexpected status code: 403"},
        {.status = 404, .body_error = sensitive, .error = "unexpected status code: 404"},
        {.status = 429, .body_error = sensitive, .error = "unexpected status code: 429"},
        {.status = 500, .body_error = sensitive, .error = "unexpected status code: 500"},
        {.status = 200, .send_rc = 1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = 1,
         .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = 1, .send_error = sensitive, .error = redacted},
        {.status = 200, .send_rc = 1, .error = "HTTP transport failed"},
    };
    const char *one[] = {key};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.keys = one, .count = 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "aviationstack-test"};
        expect_results(detector, &ctx, true, input, strlen(input), one, 1,
                       cases[i].verified, cases[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_results(detector, &ctx, true, key, strlen(key), NULL, 0, false, NULL);
    CHECK(!http.calls && !http.releases);
}

static void test_deadline_clamp(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "aviationstack %s", key);
    const char *one[] = {key};
    expected_requests expected = {.keys = one, .count = 1, .timeout_limit = 3000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_results(detector, &ctx, true, input, strlen(input), one, 1, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);

    ctx.deadline_monotonic_ms = 1;
    http.calls = http.releases = 0;
    expect_results(detector, &ctx, true, input, strlen(input), one, 1, false, "context deadline exceeded");
    CHECK(!http.calls && http.releases == 1);

    /* Removing the deadline restores this request's full ten seconds. */
    ctx.deadline_monotonic_ms = 0;
    expected.timeout_limit = 0;
    http.calls = http.releases = 0;
    expect_results(detector, &ctx, true, input, strlen(input), one, 1, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
}

int main(void)
{
    test_secret(key, 32, 0);
    key[31] = 'z'; /* Lowercase alphanumeric, not hexadecimal-only. */
    test_secret(other_key, 32, 9);
    other_key[31] = 'g';
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_occurrences(detector);
    test_verification(detector);
    test_deadline_clamp(detector);
    return test_finish("AviationStack");
}
