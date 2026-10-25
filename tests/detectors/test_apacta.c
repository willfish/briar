/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apacta_init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(br_apacta_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 632 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Apacta") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Apacta is a project management tool designed for the construction industry. Apacta API keys can be used to access and manage project data within the Apacta platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apacta"));
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
        test_key_result(&results.items[i], 632, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[192], changed[37], padding[42];
    const char *one[] = {key}, *altered[] = {changed};
    CHECK(strlen(key) == 36 && strchr(key, 'g') && !strchr(key, '-')); /* Not UUID grammar. */
    snprintf(input, sizeof(input), "preAPACTAsuffix:'%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s apacta", key);
    expect_extraction(detector, input, NULL, 0);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "apacta%.*s%s", gap, padding, key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *separators[] = {"\r", "\n", "\r\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        snprintf(input, sizeof(input), "apacta%s%s", separators[i], key);
        expect_extraction(detector, input, one, 1);
    }
    const char *invalid_forms[] = {"apacta%s", "apacta _%s", "apacta %s_", "apacta %.35s", "apacta %sz"};
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[8] = 'A';
    snprintf(input, sizeof(input), "APACTA %s", changed);
    expect_extraction(detector, input, NULL, 0);
    changed[8] = '-';
    changed[9] = '-';
    snprintf(input, sizeof(input), "apacta %s", changed);
    expect_extraction(detector, input, altered, 1);

    /* A leading/trailing hyphen needs a word character OUTSIDE the capture
     * to satisfy the corresponding word boundary. It is not a UUID check. */
    memcpy(changed, key, sizeof(changed));
    changed[0] = '-';
    snprintf(input, sizeof(input), "apacta %s", changed);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "apacta q%s", changed);
    expect_extraction(detector, input, altered, 1);
    memcpy(changed, key, sizeof(changed));
    changed[35] = '-';
    snprintf(input, sizeof(input), "apacta %s", changed);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "apacta %sZ", changed);
    expect_extraction(detector, input, altered, 1);
    memset(changed, '-', 36);
    snprintf(input, sizeof(input), "apacta q%sZ", changed);
    expect_extraction(detector, input, altered, 1);
    memset(changed, 'a', 36);
    snprintf(input, sizeof(input), "apacta %s", changed);
    expect_extraction(detector, input, altered, 1);

    snprintf(input, sizeof(input), "apacta %s\napacta %s\napacta %s", other, key, other);
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
    char url[128];
    snprintf(url, sizeof(url), "https://app.apacta.com/api/v1/time_entries?api_key=%s",
             expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->url, url) && !strcmp(request->method, "GET"));
    CHECK(request->detector_type == 632 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* Only the shared User-Agent, no invented API headers. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog apacta-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                const char *key, const char *input,
                                bool verified, const char *error)
{
    const char *keys[] = {key};
    expected_requests expected = {keys, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apacta-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 632, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    char input[192];
    snprintf(input, sizeof(input), "apacta %s", key);
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
        expect_verification(detector, &http, key, input, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, key, input, false, send_errors[i]);
    }
    /* Synthetic only: even the URL's key is left unchanged by upstream's omitted secret args. */
    char sensitive_error[256];
    snprintf(sensitive_error, sizeof(sensitive_error),
             "Get \"https://app.apacta.com/api/v1/time_entries?api_key=%s\": timeout for %s", key, key);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, key, input, false, sensitive_error);
    http.send_error = NULL;
    expect_verification(detector, &http, key, input, false, "HTTP transport failed");

    char hyphens[37];
    memset(hyphens, '-', 36);
    hyphens[36] = '\0';
    snprintf(input, sizeof(input), "apacta q%sZ", hyphens);
    http = (test_http){.response = {.status = 200}};
    expect_verification(detector, &http, hyphens, input, true, NULL);

    snprintf(input, sizeof(input), "apacta %s\napacta %s\napacta %s", other, key, other);
    const char *keys[] = {other, key};
    expected_requests expected = {keys, 2};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apacta-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 632, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "apacta %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 632, key, "key");
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[37], other[37];
    test_secret(key, 36, 0);
    test_secret(other, 36, 11);
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("Apacta");
}
