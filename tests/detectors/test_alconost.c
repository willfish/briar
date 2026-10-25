/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic username; the request golden encodes this value followed by ':'. */
static const char key[] = "abcdefghijklmnopqrstuvwxyz012345";

static void check_findings(const br_results *results, const char *const *keys, size_t count,
                            bool verified, const char *error)
{
    CHECK(results->len == count);
    /* Upstream emits a unique-key map, not a defined finding order. */
    for (size_t i = 0; i < count; ++i) {
        const br_result *result = NULL;
        for (size_t j = 0; j < results->len; ++j) {
            if (results->items[j].raw.len == 32 && !memcmp(results->items[j].raw.data, keys[i], 32)) {
                CHECK(!result);
                result = &results->items[j];
            }
        }
        CHECK(result);
        test_key_result(result, 301, keys[i], "key");
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
    CHECK(br_alconost_init(&detector, &error) == 0 && !error && detector);
    const void *pattern = detector->state;
    CHECK(br_alconost_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(detector->type == 301 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Alconost") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Alconost is a translation and localization service. Alconost API keys can "
                  "be used to access and modify translation data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "alconost"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_alconost_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_alconost_init(NULL, NULL) != 0);
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

static void test_extraction(const br_detector *detector, const char *other)
{
    const char *one[] = {key};
    char input[256], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"alconost = '%s'", true},
        {"preAlCoNoStsuffix:%s", true},
        {"%s", false}, {"%s alconost", false},
        {"alconost%s", false},
        {"alconost _%s", false}, {"alconost %s_", false},
        {"alconost x%s", false}, {"alconost %sx", false},
        {"alconost %.31s", false},
        {"alconost\r%s", true}, {"alconost\n%s", true},
        {"alconost\r\n%s", true},
        {"alconost \xc3\xa9%s\xc3\xa9", true}, /* Word boundaries remain ASCII. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "alconost", 8);
        memset(input + 8, '-', gap);
        memcpy(input + 8 + gap, key, sizeof(key));
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + 8, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    /* [0-9Aa-z] contains uppercase A, not the range A-Z or A-z. */
    memcpy(changed, key, sizeof(changed));
    changed[16] = 'A';
    const char *uppercase_a[] = {changed};
    snprintf(input, sizeof(input), "ALCONOST %s", changed);
    expect_extraction(detector, input, strlen(input), uppercase_a, 1);
    const char invalid[] = {'B', 'Z', '[', '_', '-', '%'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        changed[16] = invalid[i];
        snprintf(input, sizeof(input), "ALCONOST %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    memset(changed, 'A', 32);
    changed[32] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "alconost %s", changed);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);
    memset(changed, 'a', 32);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "alconost %s", changed);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);

    snprintf(input, sizeof(input), "alconost %s\nalconost %s\nalconost %s", key, other, key);
    const char *unique[] = {other, key};
    expect_extraction(detector, input, strlen(input), unique, 2);
    snprintf(input, sizeof(input), "alconost %s %s", key, other);
    expect_extraction(detector, input, strlen(input), one, 1);
    memcpy(input, "alconost\0", 9);
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
    CHECK(!strcmp(request->url, "https://nitro.alconost.com/api/v1/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 301);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    size_t matches = 0;
    for (size_t i = 0; i < expected->count; ++i) {
        char *auth = NULL, *error = NULL;
        CHECK(br_http_basic_auth((br_slice){(const unsigned char *)expected->keys[i], 32},
                                 (br_slice){0}, &auth, &error) == 0 && auth && !error);
        if (!strcmp(request->headers[1].value, auth)) {
            ++matches;
            if (!strcmp(expected->keys[i], key)) {
                CHECK(!strcmp(request->headers[1].value,
                              "Basic YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU6"));
            }
        }
        free(auth);
    }
    CHECK(matches == 1);
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog alconost-test"));
}

static void test_verification(const br_detector *detector, const char *other)
{
    char input[256], transport_error[128];
    snprintf(input, sizeof(input), "alconost %s", key);
    snprintf(transport_error, sizeof(transport_error), "key=%s repeated=%s", key, key);
    const char *one[] = {key};
    expected_requests expected = {one, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, NULL, false, "HTTP transport failed"},
        /* SetVerificationError receives no secrets: candidate text stays intact. */
        {200, -1, transport_error, false, transport_error},
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
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "alconost-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1);
        check_findings(&results, one, 1, cases[i].verified, cases[i].error);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "alconost %s\nalconost %s\nalconost %s", key, other, key);
    const char *unique[] = {key, other};
    expected = (expected_requests){unique, 2};
    test_http http = {.response = {.status = 500}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "alconost-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 2 && http.releases == 2);
    check_findings(&results, unique, 2, false, "unexpected status code: 500");
    br_results_clear(&results);

    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "alconost", 8);
    check_findings(&results, NULL, 0, false, NULL);
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "alconost %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    check_findings(&results, one, 1, false, "HTTP transport not installed");
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *pattern = detector->state;
    char other[33];
    test_secret(other, 32, 9);
    test_extraction(detector, other);
    test_verification(detector, other);
    const br_detector *again = NULL;
    CHECK(br_alconost_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    return test_finish("Alconost");
}
