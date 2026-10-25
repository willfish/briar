/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

#include <time.h>

static void check_findings(const br_results *results, const char *const *keys, size_t count,
                            bool verified, const char *error)
{
    CHECK(results->len == count);
    /* Source iteration uses a unique-key map, whose order is unspecified. */
    for (size_t i = 0; i < count; ++i) {
        const br_result *result = NULL;
        for (size_t j = 0; j < results->len; ++j) {
            if (results->items[j].raw.len == 64 && !memcmp(results->items[j].raw.data, keys[i], 64)) {
                CHECK(!result);
                result = &results->items[j];
            }
        }
        CHECK(result);
        test_key_result(result, 637, keys[i], "key");
        CHECK(result->verified == verified);
        if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
        else CHECK(!result->verification_error);
    }
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apimatic_init(&detector, &error) == 0 && !error && detector);
    const void *pattern = detector->state;
    CHECK(br_apimatic_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(detector->type == 637 && detector->version == 0);
    CHECK(!strcmp(detector->name, "APIMatic") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "APIMatic provides tools for generating SDKs, API documentation, and code "
                  "snippets. APIMatic credentials can be used to access and manage these "
                  "tools and services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apimatic"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_apimatic_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_apimatic_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    check_findings(&results, keys, count, false, NULL);
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[256], changed[65];
    const char *one[] = {key};
    snprintf(input, sizeof(input), "apikey %s", key);
    CHECK(!strstr(input, "apimatic")); /* Direct extraction is broader than engine dispatch. */
    expect_extraction(detector, input, strlen(input), one, 1);
    const struct { const char *format; bool matches; } cases[] = {
        {"apimatic = '%s'", true}, {"preAPIMATICsuffix:%s", true},
        {"preAPIKEYsuffix:%s", true},
        {"%s", false}, {"%s apimatic", false}, {"apimatic%s", false},
        {"apikey _%s", false}, {"apikey %s_", false},
        {"apikey X%s", false}, {"apikey %sX", false},
        {"apikey %.63s", false},
        {"apikey\r%s", true}, {"apikey\n%s", true}, {"apikey\r\n%s", true},
        {"apikey \xc3\xa9%s\xc3\xa9", true}, /* ASCII word boundaries. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "apikey", 6);
        memset(input + 6, '-', gap);
        memcpy(input + 6 + gap, key, 65);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + 6, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    const char invalid[] = {'/', '+', '=', '.', '%', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[48] = invalid[i];
        snprintf(input, sizeof(input), "apikey %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }

    memcpy(changed, key, sizeof(changed));
    const char *edge[] = {changed};
    changed[0] = '-';
    snprintf(input, sizeof(input), "apimatic%s", changed);
    expect_extraction(detector, input, strlen(input), edge, 1); /* Word-to-hyphen boundary. */
    snprintf(input, sizeof(input), "apimatic %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    changed[0] = '_';
    snprintf(input, sizeof(input), "apimatic %s", changed);
    expect_extraction(detector, input, strlen(input), edge, 1); /* Underscore is a word character. */
    snprintf(input, sizeof(input), "apimatic%s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[63] = '-';
    snprintf(input, sizeof(input), "apikey %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "apikey %sX", changed);
    expect_extraction(detector, input, strlen(input), edge, 1); /* Hyphen-to-word boundary. */
    changed[63] = '_';
    snprintf(input, sizeof(input), "apikey %s", changed);
    expect_extraction(detector, input, strlen(input), edge, 1);
    memset(changed, 'a', 64);
    changed[64] = '\0';
    snprintf(input, sizeof(input), "apikey %s", changed);
    expect_extraction(detector, input, strlen(input), edge, 1); /* No local entropy filter. */

    snprintf(input, sizeof(input), "apimatic %s\napikey %s\napikey %s", key, other, key);
    const char *unique[] = {other, key};
    expect_extraction(detector, input, strlen(input), unique, 2);
    snprintf(input, sizeof(input), "apikey %s %s", key, other);
    expect_extraction(detector, input, strlen(input), one, 1);
    memcpy(input, "apikey\0", 7);
    memcpy(input + 7, key, 64);
    expect_extraction(detector, input, 71, one, 1);
}

typedef struct {
    const char *const *keys;
    size_t count;
    uint32_t timeout_limit;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.apimatic.io/code-generations"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 637);
    if (expected->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    else CHECK(request->timeout_ms == 10000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    size_t matches = 0;
    for (size_t i = 0; i < expected->count; ++i) {
        char authorization[76];
        snprintf(authorization, sizeof(authorization), "X-Auth-Key %s", expected->keys[i]);
        if (!strcmp(request->headers[0].value, authorization)) ++matches;
    }
    CHECK(matches == 1);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog apimatic-test"));
}

static void test_verification(const br_detector *detector, const char *key, const char *other)
{
    char input[256], cause[192];
    snprintf(input, sizeof(input), "apikey %s", key);
    snprintf(cause, sizeof(cause), "key=%s repeated=%s", key, key);
    const char *one[] = {key};
    expected_requests expected = {one, 1, 0};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL}, {401, 0, NULL, false, NULL}, {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {404, 0, NULL, false, "unexpected status code: 404"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, NULL, false, "HTTP transport failed"},
        {200, -1, cause, false, cause}, /* Source omits secret-redaction arguments. */
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = "ignored body-read failure"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "apimatic-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1);
        check_findings(&results, one, 1, cases[i].verified, cases[i].error);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "apimatic %s\napikey %s\napikey %s", key, other, key);
    const char *unique[] = {key, other};
    expected = (expected_requests){unique, 2, 0};
    test_http http = {.response = {.status = 500}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apimatic-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 2 && http.releases == 2);
    check_findings(&results, unique, 2, false, "unexpected status code: 500");
    br_results_clear(&results);
    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "apikey", 6);
    check_findings(&results, NULL, 0, false, NULL);
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "apikey %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    check_findings(&results, one, 1, false, "HTTP transport not installed");
    br_results_clear(&results);
}

static void test_deadline_clamp(const br_detector *detector, const char *key)
{
    char input[96];
    snprintf(input, sizeof(input), "apikey %s", key);
    const char *one[] = {key};
    expected_requests expected = {one, 1, 3000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apimatic-test", .deadline_monotonic_ms = deadline};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    check_findings(&results, one, 1, true, NULL);
    br_results_clear(&results);

    ctx.deadline_monotonic_ms = 1;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!http.calls && http.releases == 1);
    check_findings(&results, one, 1, false, "context deadline exceeded");
    br_results_clear(&results);

    /* A clamped request does not change the timeout of a subsequent request. */
    ctx.deadline_monotonic_ms = 0;
    expected.timeout_limit = 0;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1);
    check_findings(&results, one, 1, true, NULL);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *pattern = detector->state;
    char key[65], other[65];
    test_secret(key, 64, 0);
    test_secret(other, 64, 9);
    key[0] = 'B'; key[16] = '_'; key[32] = '-'; key[63] = 'Z';
    other[0] = 'C'; other[16] = '-'; other[32] = '_'; other[63] = 'Y';
    test_extraction(detector, key, other);
    test_verification(detector, key, other);
    test_deadline_clamp(detector, key);
    const br_detector *again = NULL;
    CHECK(br_apimatic_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    return test_finish("APIMatic");
}
