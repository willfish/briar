/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[65], other[65];

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_appsynergy_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_appsynergy_init(&detector, &error) == 0 && !error && detector);
    const void *compiled = detector->state;
    CHECK(br_appsynergy_init(&again, &error) == 0 && !error && again == detector);
    CHECK(compiled && again->state == compiled);
    CHECK(detector->type == 646 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AppSynergy") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AppSynergy is a platform for building cloud applications. "
        "AppSynergy API keys can be used to access and manage applications and data within the platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "appsynergy"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 646, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[65];
    const char *one[] = {key};
    snprintf(input, sizeof(input), "appsynergy = '%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s appsynergy", key);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "preAPPSYNERGYsuffix:%s", key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "appsynergy\r\n%s", key);
    expect_extraction(detector, input, one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "appsynergy");
        memset(input + at, '-', gap);
        memcpy(input + at + gap, key, 65);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const struct { const char *before, *after; } edges[] = {{"_", ""}, {"x", ""}, {"", "_"}, {"", "q"}};
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "appsynergy %s%s%s", edges[i].before, key, edges[i].after);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "appsynergy %.63s", key);
    expect_extraction(detector, input, NULL, 0);
    const char invalid[] = {'A', '-', '_', '/', '='};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[20] = invalid[i];
        snprintf(input, sizeof(input), "appsynergy %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "appsynergy %s\nappsynergy %s\nappsynergy %s", other, key, other);
    const char *ordered[] = {other, key, other};
    expect_extraction(detector, input, ordered, 3);
    memset(changed, 'a', 64);
    changed[64] = '\0';
    const char *unfiltered[] = {changed};
    snprintf(input, sizeof(input), "appsynergy %s", changed);
    expect_extraction(detector, input, unfiltered, 1);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "appsynergy %s", changed);
    expect_extraction(detector, input, unfiltered, 1);
}

typedef struct { const char *const *keys; size_t count; } requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    char url[160];
    snprintf(url, sizeof(url), "https://www.appsynergy.com/api?action=HTML2PDF&apiKey=%s", expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 646);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* No Content-Type, despite the literal JSON payload. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog appsynergy-test"));
    static const unsigned char payload[] =
        "{\"html\":\"<html><body><h1>Hello World</h1></body></html>\",\"filename\":\"HelloWorld.pdf\"}";
    CHECK(request->body.len == sizeof(payload) - 1 && request->body.data);
    CHECK(!memcmp(request->body.data, payload, sizeof(payload) - 1));
}

static void verification(const br_detector *detector)
{
    static const unsigned char marker[] = "Invalid API Key";
    static const unsigned char binary[] = "prefix\0not JSON: Invalid API Key suffix";
    static const unsigned char wrong_case[] = "invalid API Key";
    static const unsigned char truncated[] = "Invalid API Ke";
    const char *missing = "status bad request invalid api key message not found: 400";
    const struct {
        int status, send_rc;
        br_slice body;
        const char *body_error, *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {.status = 200, .body = {binary, sizeof(binary) - 1}, .body_error = "ignored", .verified = true},
        {.status = 401, .body_error = "ignored"},
        {.status = 400, .body = {marker, sizeof(marker) - 1}},
        {.status = 400, .body = {binary, sizeof(binary) - 1}},
        {.status = 400, .body = {wrong_case, sizeof(wrong_case) - 1}, .error = missing},
        {.status = 400, .body = {truncated, sizeof(truncated) - 1}, .error = missing},
        {.status = 400, .error = missing},
        {.status = 400, .body = {marker, sizeof(marker) - 1}, .body_error = "body read failed", .error = "body read failed"},
        {.status = 403, .body = {marker, sizeof(marker) - 1}, .body_error = "ignored", .error = "unexpected status code: 403"},
        {.status = 201, .body_error = "ignored", .error = "unexpected status code: 201"},
        {.status = 500, .body_error = "ignored", .error = "unexpected status code: 500"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
    };
    char input[256];
    snprintf(input, sizeof(input), "appsynergy %s\nappsynergy %s", key, key);
    const char *duplicates[] = {key, key};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        requests expected = {duplicates, 2};
        test_http http = {
            .response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "appsynergy-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        for (size_t r = 0; r < results.len; ++r) {
            test_key_result(&results.items[r], 646, key, "key");
            CHECK(results.items[r].verified == cases[i].verified);
            if (cases[i].error) CHECK(results.items[r].verification_error && !strcmp(results.items[r].verification_error, cases[i].error));
            else CHECK(!results.items[r].verification_error);
        }
        br_results_clear(&results);
    }
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 2);
    for (size_t r = 0; r < results.len; ++r) {
        test_key_result(&results.items[r], 646, key, "key");
        CHECK(!results.items[r].verified && results.items[r].verification_error);
        CHECK(!strcmp(results.items[r].verification_error, "HTTP transport not installed"));
    }
    br_results_clear(&results);
}

static void ordered_verification_and_redaction(const br_detector *detector)
{
    char input[512], cause[320], for_key[256], for_other[256];
    snprintf(input, sizeof(input), "appsynergy %s\nappsynergy %s\nappsynergy %s", other, key, other);
    snprintf(cause, sizeof(cause), "request key=%s repeated=%s other=%s", key, key, other);
    snprintf(for_key, sizeof(for_key), "request key=[REDACTED] repeated=[REDACTED] other=%s", other);
    snprintf(for_other, sizeof(for_other), "request key=%s repeated=%s other=[REDACTED]", key, key);
    const char *ordered[] = {other, key, other};
    static const unsigned char body[] = "\0Invalid API Key";
    for (int mode = 0; mode < 3; ++mode) {
        requests expected = {ordered, 3};
        test_http http = {
            .response = {.status = mode == 2 ? 400 : 200, .body = {body, sizeof(body) - 1}, .body_error = cause},
            .send_rc = mode == 1 ? -1 : 0, .send_error = mode == 1 ? cause : NULL,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "appsynergy-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t r = 0; r < results.len; ++r) {
            test_key_result(&results.items[r], 646, ordered[r], "key");
            CHECK(results.items[r].verified == (mode == 0));
            if (mode) {
                CHECK(results.items[r].verification_error);
                CHECK(!strcmp(results.items[r].verification_error, r == 1 ? for_key : for_other));
                CHECK(!strstr(results.items[r].verification_error, ordered[r]));
            } else CHECK(!results.items[r].verification_error);
        }
        br_results_clear(&results);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, "appsynergy", 10);
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 64, 0);
    test_secret(other, 64, 9);
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    ordered_verification_and_redaction(detector);
    return test_finish("AppSynergy");
}
