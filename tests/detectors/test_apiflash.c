/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static void check_findings(const br_results *results, const char *const *keys, size_t count,
                            bool verified, const char *error)
{
    CHECK(results->len == count);
    /* Source findings come from an unordered unique-key map. */
    for (size_t i = 0; i < count; ++i) {
        const br_result *result = NULL;
        for (size_t j = 0; j < results->len; ++j) {
            if (results->items[j].raw.len == 32 && !memcmp(results->items[j].raw.data, keys[i], 32)) {
                CHECK(!result);
                result = &results->items[j];
            }
        }
        CHECK(result);
        test_key_result(result, 401, keys[i], "key");
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
    CHECK(br_apiflash_init(&detector, &error) == 0 && !error && detector);
    const void *pattern = detector->state;
    CHECK(br_apiflash_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(detector->type == 401 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Apiflash") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Apiflash is a screenshot API service. Apiflash keys can be used to access "
                  "and utilize the screenshot API service."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apiflash"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_apiflash_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_apiflash_init(NULL, NULL) != 0);
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
    const char *one[] = {key};
    char input[256], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"apiflash = '%s'", true}, {"preAPIFlashsuffix:%s", true},
        {"%s", false}, {"%s apiflash", false}, {"apiflash%s", false},
        {"apiflash _%s", false}, {"apiflash %s_", false},
        {"apiflash x%s", false}, {"apiflash %sx", false},
        {"apiflash %.31s", false},
        {"apiflash\r%s", true}, {"apiflash\n%s", true}, {"apiflash\r\n%s", true},
        {"apiflash \xc3\xa9%s\xc3\xa9", true}, /* ASCII word boundaries. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "apiflash", 8);
        memset(input + 8, '-', gap);
        memcpy(input + 8 + gap, key, 33);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + 8, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        size_t at = 8;
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        memcpy(input + at, key, 33);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    const char invalid[] = {'A', 'Z', '_', '-', '%', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[16] = invalid[i];
        snprintf(input, sizeof(input), "APIFLASH %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "apiflash %s", changed);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "apiflash %s", changed);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);

    snprintf(input, sizeof(input), "apiflash %s\napiflash %s\napiflash %s", key, other, key);
    const char *unique[] = {other, key};
    expect_extraction(detector, input, strlen(input), unique, 2);
    snprintf(input, sizeof(input), "apiflash %s %s", key, other);
    expect_extraction(detector, input, strlen(input), one, 1);
    memcpy(input, "apiflash\0", 9);
    memcpy(input + 9, key, 32);
    expect_extraction(detector, input, 41, one, 1);
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(!strcmp(request->method, "GET"));
    size_t matches = 0;
    for (size_t i = 0; i < expected->count; ++i) {
        char url[192];
        snprintf(url, sizeof(url),
                 "https://api.apiflash.com/v1/urltoimage?url=http://google.com&access_key=%s&wait_until=page_loaded",
                 expected->keys[i]);
        if (!strcmp(request->url, url)) ++matches;
    }
    CHECK(matches == 1);
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 401);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* No detector headers: only the shared User-Agent. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog apiflash-test"));
}

static void test_verification(const br_detector *detector, const char *key, const char *other)
{
    char input[256], transport_error[128];
    snprintf(input, sizeof(input), "apiflash %s", key);
    snprintf(transport_error, sizeof(transport_error), "key=%s repeated=%s", key, key);
    const char *one[] = {key};
    expected_requests expected = {one, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL}, {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, "unexpected status code: 403"},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context canceled", false, NULL},
        {200, -1, "context deadline exceeded", false, NULL},
        {200, -1, NULL, false, NULL},
        {200, -1, transport_error, false, NULL},
        /* Injected simulation only, not proof of native PUBLIC policy support. */
        {200, 1, "unsupported: native curl HTTP client profile", false, NULL},
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
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "apiflash-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1);
        check_findings(&results, one, 1, cases[i].verified, cases[i].error);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "apiflash %s\napiflash %s\napiflash %s", key, other, key);
    const char *unique[] = {key, other};
    expected = (expected_requests){unique, 2};
    test_http http = {.response = {.status = 403}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apiflash-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 2 && http.releases == 2);
    check_findings(&results, unique, 2, false, "unexpected status code: 403");
    br_results_clear(&results);

    http.calls = http.releases = 0;
    http.send_rc = -1;
    http.send_error = transport_error;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 2 && http.releases == 2);
    check_findings(&results, unique, 2, false, NULL);
    br_results_clear(&results);
    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "apiflash", 8);
    check_findings(&results, NULL, 0, false, NULL);
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);
}

static bool cancelled(void *user)
{
    ++*(size_t *)user;
    return true;
}

static void test_preflight_errors(const br_detector *detector, const char *key)
{
    char input[64];
    snprintf(input, sizeof(input), "apiflash %s", key);
    const char *one[] = {key};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        size_t checks = 0;
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : NULL, .cancel_user = &checks,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
        };
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        check_findings(&results, one, 1, false, NULL);
        CHECK(!http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(mode != 1 || checks > 0);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *pattern = detector->state;
    char key[33], other[33];
    test_secret(key, 32, 0);
    test_secret(other, 32, 9);
    test_extraction(detector, key, other);
    test_verification(detector, key, other);
    test_preflight_errors(detector, key);
    const br_detector *again = NULL;
    CHECK(br_apiflash_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    return test_finish("Apiflash");
}
