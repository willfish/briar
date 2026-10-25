/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apimetrics_init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(br_apimetrics_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 1004 && detector->version == 0);
    CHECK(!strcmp(detector->name, "ApiMetrics") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "ApiMetrics is a tool for monitoring the performance of APIs. ApiMetrics keys can be used to access and manage API monitors."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apimetrics"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const char *input,
                              const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 1004, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[192], changed[33], padding[42];
    const char *one[] = {key};
    CHECK(strlen(key) == 32 && key[0] == 'B' && other[0] == 'b');
    CHECK(!strcmp(key + 1, other + 1)); /* Distinct keys differ only in case. */
    snprintf(input, sizeof(input), "preAPImEtRiCSsuffix:'%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s apimetrics", key);
    expect_extraction(detector, input, NULL, 0);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "apimetrics%.*s%s", gap, padding, key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *separators[] = {"\r", "\n", "\r\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        snprintf(input, sizeof(input), "apimetrics%s%s", separators[i], key);
        expect_extraction(detector, input, one, 1);
    }
    const char *invalid_forms[] = {
        "apimetrics%s", "apimetrics _%s", "apimetrics %s_", "apimetrics %.31s", "apimetrics %sz",
    };
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    const char invalid_chars[] = {'_', '-'};
    for (size_t i = 0; i < sizeof(invalid_chars); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[16] = invalid_chars[i];
        snprintf(input, sizeof(input), "APIMETRICS %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    memset(changed, 'Z', 32);
    changed[32] = '\0';
    const char *altered[] = {changed};
    snprintf(input, sizeof(input), "apimetrics %s", changed);
    expect_extraction(detector, input, altered, 1);
    memset(changed, '7', 32);
    snprintf(input, sizeof(input), "apimetrics %s", changed);
    expect_extraction(detector, input, altered, 1);

    snprintf(input, sizeof(input), "apimetrics %s\napimetrics %s\napimetrics %s", other, key, other);
    const char *unique[] = {other, key};
    expect_extraction(detector, input, unique, 2);
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://client.apimetrics.io/api/2/calls/"));
    CHECK(request->detector_type == 1004 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog apimetrics-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                const char *key, bool verified, const char *error)
{
    char input[64];
    snprintf(input, sizeof(input), "apimetrics %s", key);
    const char *keys[] = {key};
    expected_requests expected = {keys, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apimetrics-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 1004, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    const struct {
        int status;
        const char *body_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, NULL, true, NULL}, {200, "ignored drain failure", true, NULL},
        {401, "ignored drain failure", false, NULL}, {403, "ignored drain failure", false, NULL},
        {201, "ignored drain failure", false, "unexpected status code: 201"},
        {404, "ignored drain failure", false, "unexpected status code: 404"},
        {500, "ignored drain failure", false, "unexpected status code: 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = cases[i].body_error}};
        expect_verification(detector, &http, key, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, key, false, send_errors[i]);
    }
    /* Synthetic only: upstream passes no key argument for error redaction. */
    char sensitive_error[128];
    snprintf(sensitive_error, sizeof(sensitive_error), "Bearer %s failed: %s", key, key);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, key, false, sensitive_error);
    http.send_error = NULL;
    expect_verification(detector, &http, key, false, "HTTP transport failed");

    char input[192];
    snprintf(input, sizeof(input), "apimetrics %s\napimetrics %s\napimetrics %s", other, key, other);
    const char *keys[] = {other, key};
    expected_requests expected = {keys, 2};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apimetrics-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 1004, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "apimetrics %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 1004, key, "key");
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[33], other[33];
    test_secret(key, 32, 0);
    key[0] = 'B';
    key[10] = 'G';
    key[20] = 'N';
    key[31] = 'S';
    memcpy(other, key, sizeof(other));
    other[0] = 'b';
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("ApiMetrics");
}
