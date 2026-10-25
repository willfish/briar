/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *key, *host; } credential;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aha_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_aha_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 802 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Aha") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Aha is a product management software suite. Aha API keys can be used to access and modify product data and workflows."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "aha.io"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_detector_is_default(detector, NULL));
    return detector;
}

static void check_pair(const br_result *result, credential expected)
{
    size_t key_len = strlen(expected.key), host_len = strlen(expected.host);
    CHECK(result->detector_type == 802 && !result->detector_name);
    CHECK(result->raw.len == key_len && !memcmp(result->raw.data, expected.key, key_len));
    CHECK(result->raw_v2.len == key_len + host_len);
    CHECK(!memcmp(result->raw_v2.data, expected.key, key_len));
    CHECK(!memcmp(result->raw_v2.data + key_len, expected.host, host_len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(!strcmp(json_object_get_string(part), expected.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "url", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(!strcmp(json_object_get_string(part), expected.host));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const char *input,
                              const credential *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[1536], changed[65];
    const credential one[] = {{key, "first.aha.io"}}, fallback[] = {{key, "aha.io"}};
    snprintf(input, sizeof(input), "prefixAHAsuffix:'%s'\r\nfirst.aha.io", key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "aha = '%s'", key);
    expect_extraction(detector, input, fallback, 1); /* Prefix is aha, not aha.io. */
    snprintf(input, sizeof(input), "first.aha.io\naha %s", key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "aha %s\naha.io\nfirst.aha.io", key);
    expect_extraction(detector, input, one, 1); /* A found host excludes the fallback. */
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, "first.aha.io", NULL, 0);
    snprintf(input, sizeof(input), "%s\nfirst.aha.io", key);
    expect_extraction(detector, input, NULL, 0);

    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "aha%.*s%s\nfirst.aha.io", gap,
                 "-----------------------------------------", key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *invalid_forms[] = {
        "aha _%s\nfirst.aha.io", "aha %s_\nfirst.aha.io",
        "aha %.63s\nfirst.aha.io", "aha %sf\nfirst.aha.io",
    };
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[16] = 'A';
    snprintf(input, sizeof(input), "aha %s\nfirst.aha.io", changed);
    expect_extraction(detector, input, NULL, 0);
    changed[16] = 'g';
    snprintf(input, sizeof(input), "aha %s\nfirst.aha.io", changed);
    expect_extraction(detector, input, NULL, 0);

    const struct { const char *input, *captured; } hosts[] = {
        {"a.aha.io", "aha.io"}, {"ab.aha.io", "ab.aha.io"},
        {"MiXeD.aha.io", "MiXeD.aha.io"}, {"ab.AHA.IO", "aha.io"},
        {"two-part.aha.io", "two-part.aha.io"}, {"ab-.aha.io", "aha.io"},
        {"-ab.aha.io", "ab.aha.io"}, {"_ab.aha.io", "aha.io"},
        {"prefix.ab.aha.io", "ab.aha.io"},
        {"ab.aha.io.suffix.invalid", "ab.aha.io"}, {"ab.aha.ioTAIL", "ab.aha.io"},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        const credential found[] = {{key, hosts[i].captured}};
        snprintf(input, sizeof(input), "aha %s\n%s", key, hosts[i].input);
        expect_extraction(detector, input, found, 1);
    }
    for (size_t len = 63; len <= 64; ++len) {
        char host[72];
        memset(host, 'b', len);
        memcpy(host + len, ".aha.io", 8);
        const credential found[] = {{key, len == 63 ? host : "aha.io"}};
        snprintf(input, sizeof(input), "aha %s\n%s", key, host);
        expect_extraction(detector, input, found, 1);
    }
    snprintf(input, sizeof(input), "aha %s\n%1100s\nfirst.aha.io", key, "");
    expect_extraction(detector, input, one, 1); /* Span metadata does not limit FromData. */

    memset(changed, 'a', 64);
    changed[64] = '\0';
    const credential low_entropy[] = {{changed, "aha.io"}};
    snprintf(input, sizeof(input), "aha %s", changed);
    expect_extraction(detector, input, low_entropy, 1);

    snprintf(input, sizeof(input), "MiXeD.aha.io\naha %s\nfirst.aha.io\naha %s\naha %s\nMiXeD.aha.io",
             other, key, other);
    const credential product[] = {
        {other, "MiXeD.aha.io"}, {other, "first.aha.io"},
        {key, "MiXeD.aha.io"}, {key, "first.aha.io"},
        {other, "MiXeD.aha.io"}, {other, "first.aha.io"},
    };
    expect_extraction(detector, input, product, 6);
    snprintf(input, sizeof(input), "aha %s\nMiXeD.aha.io\nmixed.aha.io", key);
    const credential case_distinct[] = {{key, "MiXeD.aha.io"}, {key, "mixed.aha.io"}};
    expect_extraction(detector, input, case_distinct, 2);
}

typedef struct { const credential *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const credential pair = expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    char url[128];
    snprintf(url, sizeof(url), "https://%s/api/v1/me", pair.host);
    CHECK(!strcmp(request->url, url) && !strcmp(request->method, "GET"));
    CHECK(request->detector_type == 802 && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.aha+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[1].value + 7, pair.key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog aha-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                credential pair, bool verified, const char *error)
{
    char input[160];
    snprintf(input, sizeof(input), "aha %s\n%s", pair.key, pair.host);
    expected_requests expected = {&pair, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "aha-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_pair(&results.items[0], pair);
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
        CHECK(!strstr(results.items[0].verification_error, pair.key));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    const credential pair = {key, "first.aha.io"};
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL}, {404, false, NULL},
        {201, false, "unexpected HTTP response status 201"},
        {429, false, "unexpected HTTP response status 429"},
        {500, false, "unexpected HTTP response status 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = "ignored body-read failure"}};
        expect_verification(detector, &http, pair, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200}};
    expect_verification(detector, &http, (credential){key, "aha.io"}, true, NULL);
    char max_host[71];
    memset(max_host, 'b', 63);
    memcpy(max_host + 63, ".aha.io", 8);
    expect_verification(detector, &http, (credential){key, max_host}, true, NULL);

    http.send_rc = -1;
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, pair, false, send_errors[i]);
    }
    char sensitive_error[192];
    snprintf(sensitive_error, sizeof(sensitive_error), "request %s for %s failed: %s", key, pair.host, key);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, pair, false,
                        "request [REDACTED] for first.aha.io failed: [REDACTED]");
    http.send_error = NULL;
    expect_verification(detector, &http, pair, false, "HTTP transport failed");

    const credential product[] = {
        {other, "MiXeD.aha.io"}, {other, "first.aha.io"},
        {key, "MiXeD.aha.io"}, {key, "first.aha.io"},
        {other, "MiXeD.aha.io"}, {other, "first.aha.io"},
    };
    expected_requests expected = {product, 6};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "aha-test"};
    char input[512];
    snprintf(input, sizeof(input), "MiXeD.aha.io\naha %s\nfirst.aha.io\naha %s\naha %s\nMiXeD.aha.io",
             other, key, other);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 6 && http.calls == 6 && http.releases == 6);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], product[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, "first.aha.io", strlen("first.aha.io"));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const char *key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    CHECK(strlen(key) == 64 && strlen(other) == 64);
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("Aha");
}
