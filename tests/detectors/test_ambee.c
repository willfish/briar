/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic lowercase-hex keys; never sent through a real transport. */
static const char key[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char other[] =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

static void check_findings(const br_results *results, const char *const *keys, size_t count,
                            bool verified, const char *error)
{
    CHECK(results->len == count);
    /* Upstream's unique-key map does not define finding order. */
    for (size_t i = 0; i < count; ++i) {
        const br_result *result = NULL;
        for (size_t j = 0; j < results->len; ++j) {
            if (results->items[j].raw.len == 64 && !memcmp(results->items[j].raw.data, keys[i], 64)) {
                CHECK(!result);
                result = &results->items[j];
            }
        }
        CHECK(result);
        test_key_result(result, 457, keys[i], "key");
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
    CHECK(br_ambee_init(&detector, &error) == 0 && !error && detector);
    const void *pattern = detector->state;
    CHECK(br_ambee_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(detector->type == 457 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Ambee") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Ambee provides environmental and climate data APIs. Ambee API keys can "
                  "be used to access this data for various applications such as weather "
                  "forecasting, air quality monitoring, and more."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ambee"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_ambee_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_ambee_init(NULL, NULL) != 0);
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

static void test_extraction(const br_detector *detector)
{
    const char *one[] = {key};
    char input[256], changed[65];
    const struct { const char *format; bool matches; } cases[] = {
        {"ambee = '%s'", true},
        {"prefixAMBEEsuffix:%s", true},
        {"%s", false}, {"%s ambee", false},
        {"ambee%s", false},
        {"ambee _%s", false}, {"ambee %s_", false},
        {"ambee f%s", false}, {"ambee %sf", false},
        {"ambee %.63s", false},
        {"ambee\r%s", true}, {"ambee\n%s", true}, {"ambee\r\n%s", true},
        {"ambee \xc3\xa9%s\xc3\xa9", true}, /* ASCII word boundaries. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ambee", 5);
        memset(input + 5, '-', gap);
        memcpy(input + 5 + gap, key, sizeof(key));
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + 5, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);

        size_t at = 5;
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        memcpy(input + at, key, sizeof(key));
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    const char invalid[] = {'A', 'F', 'g', 'z', '_', '-', '%', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[32] = invalid[i];
        snprintf(input, sizeof(input), "AMBEE %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    memset(changed, 'a', 64);
    changed[64] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "ambee %s", changed);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);

    snprintf(input, sizeof(input), "ambee %s\nambee %s\nAMBEE %s", key, other, key);
    const char *unique[] = {other, key};
    expect_extraction(detector, input, strlen(input), unique, 2);
    snprintf(input, sizeof(input), "ambee %s %s", key, other);
    expect_extraction(detector, input, strlen(input), one, 1);
    memcpy(input, "ambee\0", 6);
    memcpy(input + 6, key, 64);
    expect_extraction(detector, input, 70, one, 1);
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.ambeedata.com/latest/by-lat-lng?lat=12&lng=77"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 457);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "x-api-key"));
    size_t matches = 0;
    for (size_t i = 0; i < expected->count; ++i)
        if (!strcmp(request->headers[1].value, expected->keys[i])) ++matches;
    CHECK(matches == 1);
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog ambee-test"));
}

static void test_verification(const br_detector *detector)
{
    char input[256], transport_error[192];
    snprintf(input, sizeof(input), "ambee %s", key);
    snprintf(transport_error, sizeof(transport_error), "key=%s repeated=%s", key, key);
    const char *one[] = {key};
    expected_requests expected = {one, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {404, 0, NULL, false, "unexpected status code: 404"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, NULL, false, "HTTP transport failed"},
        /* Source omits secret arguments, so repeated candidate text is not redacted. */
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
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "ambee-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1);
        check_findings(&results, one, 1, cases[i].verified, cases[i].error);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "ambee %s\nambee %s\nambee %s", key, other, key);
    const char *unique[] = {key, other};
    expected = (expected_requests){unique, 2};
    test_http http = {.response = {.status = 500}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "ambee-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 2 && http.releases == 2); /* Deduplicate before verifying; keep indeterminate findings. */
    check_findings(&results, unique, 2, false, "unexpected status code: 500");
    br_results_clear(&results);

    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "ambee", 5);
    check_findings(&results, NULL, 0, false, NULL);
    CHECK(!http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "ambee %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    check_findings(&results, one, 1, false, "HTTP transport not installed");
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *pattern = detector->state;
    CHECK(strlen(key) == 64 && strlen(other) == 64);
    test_extraction(detector);
    test_verification(detector);
    const br_detector *again = NULL;
    CHECK(br_ambee_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    return test_finish("Ambee");
}
