/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_adafruitio_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_adafruitio_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 390 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AdafruitIO") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Adafruit IO is a cloud service used for IoT applications. Adafruit IO keys can be used to access and control data and devices connected to the platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "aio_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count);
    CHECK(!http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 390, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    const char *one[] = {key};
    char input[256], changed[33];
    const struct { const char *before, *after; bool matches; } boundaries[] = {
        {"", "", true}, /* No separate provider keyword is required. */
        {" \t'", "'\r\n", true},
        {"x", "", false}, {"_", "", false}, {"0", "", false},
        {"", "x", false}, {"", "_", false}, {"", "0", false},
        {"\xc3\xa9", "\xc3\xa9", true}, /* Word boundaries are ASCII. */
    };
    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i) {
        snprintf(input, sizeof(input), "%s%s%s", boundaries[i].before, key, boundaries[i].after);
        expect_extraction(detector, input, strlen(input), one, boundaries[i].matches ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    expect_extraction(detector, "AdafruitIO aio_", strlen("AdafruitIO aio_"), NULL, 0);
    expect_extraction(detector, key, 31, NULL, 0);
    for (size_t i = 0; i < 3; ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[i] = (char)(changed[i] - ('a' - 'A'));
        expect_extraction(detector, changed, 32, NULL, 0);
    }
    const char invalid[] = {'_', '-', '%', ' ', '\r', '\n'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[15] = invalid[i];
        expect_extraction(detector, changed, 32, NULL, 0);
    }
    snprintf(input, sizeof(input), "%s\r\n%s %s", other, key, other);
    const char *ordered[] = {other, key, other};
    expect_extraction(detector, input, strlen(input), ordered, 3);

    memcpy(input, key, 32);
    input[32] = '\0';
    memcpy(input + 33, other, 32);
    const char *binary[] = {key, other};
    expect_extraction(detector, input, 65, binary, 2);

    memcpy(changed, "aio_", 4);
    memset(changed + 4, 'a', 28);
    changed[32] = '\0';
    const char *low_entropy[] = {changed};
    expect_extraction(detector, changed, 32, low_entropy, 1);
    memcpy(changed + 4, "example", 7);
    expect_extraction(detector, changed, 32, low_entropy, 1);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const char *agent;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    char url[128];
    snprintf(url, sizeof(url), "https://io.adafruit.com/api/v2/ladybugtest/feeds/?x-aio-key=%s",
             expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->url, url));
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 390);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, expected->agent));
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    const char *one[] = {key};
    expected_requests expected = {one, 1, "TruffleHog detector-test"};
    const struct {
        int status;
        const char *body_error, *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, NULL, NULL, true, NULL},
        {401, NULL, NULL, false, NULL},
        {403, NULL, NULL, false, "unexpected HTTP response status 403"},
        {500, NULL, NULL, false, "unexpected HTTP response status 500"},
        {201, NULL, NULL, false, "unexpected HTTP response status 201"},
        {200, "ignored body-read failure", NULL, true, NULL},
        {401, "ignored body-read failure", NULL, false, NULL},
        {500, "ignored body-read failure", NULL, false, "unexpected HTTP response status 500"},
        {200, NULL, "context canceled", false, "context canceled"},
        {200, NULL, "context deadline exceeded", false, "context deadline exceeded"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = cases[i].body_error},
            .send_error = cases[i].send_error, .send_rc = cases[i].send_error ? -1 : 0,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "detector-test"};
        br_results results = test_scan(detector, &ctx, true, key, strlen(key));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 390, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(results.items[0].verification_error);
            CHECK(!strcmp(results.items[0].verification_error, cases[i].error));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    char input[128], transport_error[256];
    snprintf(input, sizeof(input), "%s\n%s\n%s", other, key, other);
    const char *ordered[] = {other, key, other};
    expected = (expected_requests){ordered, 3, "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 390, ordered[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s\n%s", key, key);
    const char *duplicates[] = {key, key};
    expected = (expected_requests){duplicates, 2, "TruffleHog"};
    snprintf(transport_error, sizeof(transport_error),
             "Get https://io.adafruit.com/api/v2/ladybugtest/feeds/?x-aio-key=%s: timeout for %s", key, key);
    http = (test_http){.send_rc = -1, .send_error = transport_error,
                       .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 390, key, "key");
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error,
            "Get https://io.adafruit.com/api/v2/ladybugtest/feeds/?x-aio-key=[REDACTED]: timeout for [REDACTED]"));
    }
    br_results_clear(&results);

    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "aio_", 4);
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);

    br_scan_ctx offline = {0};
    results = test_scan(detector, &offline, true, key, strlen(key));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 390, key, "key");
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[33] = "aio_", other[33] = "aio_";
    test_secret(key + 4, 28, 0);
    test_secret(other + 4, 28, 11);
    key[4] = 'B';
    other[4] = 'M';
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("AdafruitIO");
}
