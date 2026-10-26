/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static const char endpoint[] = "https://Ab.Cd.ReG.batch.azure.com";
#define REQUEST_URL "https://Ab.Cd.ReG.batch.azure.com/applications?api-version=2020-09-01.12.0"
static const char full64[] = "ACVKb5S53gMoTXKXvOEGK1B1mr/kCS5TeJ3C5wwxVnugxeoPNFl+o8jtEjdcgabL8BU6X4SpzvMYPWKHrNH2Gw==";
static const char full66[] = "ADVqn9QJPnOo3RJHfLHmG1CFuu8kWY7D+C1il8wBNmug1Qo/dKneE0h9succUYa78CVaj8T5LmOYzQI3bKHWC0B1";
static char prefix4[89], empty_key[89], all_a[89];
static const char unsupported[] = "unsupported: Azure Batch endpoint outside native ASCII DNS subset";
static const char date[] = "Tue, 02 Jan 2024 03:04:05 GMT";

/* Fixed provider clock only. No HTTP, DNS or credential discovery is installed. */
time_t time(time_t *out)
{
    time_t now = (time_t)1704164645;
    if (out) *out = now;
    return now;
}

typedef struct {
    br_slice endpoint;
    const char *key;
    bool verified;
    const char *error;
} expected_result;

static br_slice text(const char *value)
{
    return (br_slice){(const unsigned char *)value, strlen(value)};
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azure_batch_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 957 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AzureBatch") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Azure Batch is a cloud service that provides large-scale parallel and "
        "high-performance computing (HPC) applications efficiently in the cloud. "
        "Azure Batch account keys can be used to manage and control access to these resources."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".batch.azure.com"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint && detector->false_positive);
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, NULL, &reason));
    CHECK(reason && !reason[0]);
    free(reason);
    CHECK(!detector->false_positive(detector, NULL, NULL));
    const void *patterns = detector->state;
    CHECK(br_azure_batch_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == patterns);
    CHECK(br_azure_batch_init(&again, NULL) == 0 && again == detector);
    CHECK(br_azure_batch_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_azure_batch_init(NULL, NULL) != 0);
    return detector;
}

static void check_part(br_json *parts, const char *name, br_slice expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(parts, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len);
    CHECK(!memcmp(json_object_get_string(value), expected.data, expected.len));
}

static void check_result(const br_result *result, const expected_result *expected)
{
    CHECK(result->detector_type == 957 && !result->detector_name);
    CHECK(result->raw.len == expected->endpoint.len &&
          !memcmp(result->raw.data, expected->endpoint.data, expected->endpoint.len));
    CHECK(result->raw_v2.len == expected->endpoint.len + 88);
    CHECK(!memcmp(result->raw_v2.data, expected->endpoint.data, expected->endpoint.len));
    CHECK(!memcmp(result->raw_v2.data + expected->endpoint.len, expected->key, 88));
    /* Allocated endpoint storage retains NUL bytes, although ABI1 exposes
     * Redacted as a C string and cannot express its complete embedded-NUL length. */
    CHECK(result->redacted && !memcmp(result->redacted, expected->endpoint.data, expected->endpoint.len));
    CHECK(result->redacted[expected->endpoint.len] == '\0');
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_part(result->secret_parts, "url", expected->endpoint);
    check_part(result->secret_parts, "account_key", text(expected->key));
    CHECK(result->verified == expected->verified);
    if (expected->error) {
        CHECK(result->verification_error && !strcmp(result->verification_error, expected->error));
    } else CHECK(!result->verification_error);
    CHECK(!result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_results(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           const void *input, size_t len, const expected_result *expected, size_t count)
{
    br_results results = test_scan(detector, ctx, verify, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&results.items[i], &expected[i]);
    br_results_clear(&results);
}

static void scan_pair(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice url, const char *key, const expected_result *expected, size_t count)
{
    unsigned char input[1024];
    size_t key_len = strlen(key);
    CHECK(url.len + 1 + key_len <= sizeof(input));
    memcpy(input, url.data, url.len);
    input[url.len] = '\n';
    memcpy(input + url.len + 1, key, key_len);
    expect_results(detector, ctx, verify, input, url.len + 1 + key_len, expected, count);
}

static void test_extraction(const br_detector *detector)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expected_result one = {.endpoint = text(endpoint), .key = full64};
    scan_pair(detector, &ctx, false, text(endpoint), full64, &one, 1);
    expect_results(detector, &ctx, false, NULL, 0, NULL, 0);
    expect_results(detector, &ctx, true, full64, 88, NULL, 0);
    expect_results(detector, &ctx, true, endpoint, strlen(endpoint), NULL, 0);
    char input[2048], changed[177];
    memcpy(changed, full64, 87);
    changed[87] = '\0';
    scan_pair(detector, &ctx, false, text(endpoint), changed, NULL, 0);
    snprintf(changed, sizeof(changed), "%sA", full64);
    scan_pair(detector, &ctx, false, text(endpoint), changed, &one, 1); /* No right boundary. */
    snprintf(changed, sizeof(changed), "_%s_", full64);
    scan_pair(detector, &ctx, false, text(endpoint), changed, &one, 1); /* No left boundary. */
    snprintf(changed, sizeof(changed), "%.44s\r\n%s", full64, full64 + 44);
    scan_pair(detector, &ctx, false, text(endpoint), changed, NULL, 0);
    memset(changed, 'A', 176);
    changed[176] = '\0';
    const expected_result repeated[] = {
        {.endpoint = text(endpoint), .key = all_a}, {.endpoint = text(endpoint), .key = all_a},
    };
    scan_pair(detector, &ctx, false, text(endpoint), changed, repeated, 2);
    one.key = empty_key;
    scan_pair(detector, &ctx, false, text(endpoint), empty_key, &one, 1);
    one.key = full64;
    snprintf(input, sizeof(input), "%s.evil\n%s", endpoint, full64);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1); /* URL has no suffix boundary. */
    scan_pair(detector, &ctx, false, text("HTTPS://Ab.Cd.ReG.batch.azure.com"), full64, NULL, 0);

    char max_url[128];
    memcpy(max_url, "https://", 8);
    memset(max_url + 8, 'a', 50);
    max_url[58] = '.';
    memset(max_url + 59, 'b', 50);
    memcpy(max_url + 109, ".batch.azure.com", sizeof(".batch.azure.com"));
    one.endpoint = text(max_url);
    scan_pair(detector, &ctx, false, text(max_url), full64, &one, 1);
    char too_long[128];
    memcpy(too_long, "https://", 8);
    memset(too_long + 8, 'a', 51);
    memcpy(too_long + 59, ".r.batch.azure.com", sizeof(".r.batch.azure.com"));
    scan_pair(detector, &ctx, false, text(too_long), full64, NULL, 0);

    static const unsigned char nul_url[] = "https://a\0b.r.batch.azure.com";
    static const unsigned char unicode_url[] = "https://caf\xc3\xa9.r.batch.azure.com";
    const br_slice binary_urls[] = {{nul_url, sizeof(nul_url) - 1}, {unicode_url, sizeof(unicode_url) - 1}};
    for (size_t i = 0; i < sizeof(binary_urls) / sizeof(binary_urls[0]); ++i) {
        one.endpoint = binary_urls[i];
        scan_pair(detector, &ctx, false, binary_urls[i], full64, &one, 1);
        one.error = unsupported;
        http.response.status = 200; /* Rejected before even a fake success can be observed. */
        scan_pair(detector, &ctx, true, binary_urls[i], full64, &one, 1);
        one.error = NULL;
    }
    const char *unsupported_urls[] = {
        "https://a b.r.batch.azure.com", "https://a/path.r.batch.azure.com",
        "https://a%20b.r.batch.azure.com", "https://user@a.r.batch.azure.com",
    };
    for (size_t i = 0; i < sizeof(unsupported_urls) / sizeof(unsupported_urls[0]); ++i) {
        one.endpoint = text(unsupported_urls[i]);
        scan_pair(detector, &ctx, false, one.endpoint, full64, &one, 1);
        one.error = unsupported;
        scan_pair(detector, &ctx, true, one.endpoint, full64, &one, 1);
        one.error = NULL;
    }
    one.endpoint = text(endpoint);
    size_t at = strlen(endpoint);
    memcpy(input, endpoint, at);
    memset(input + at, '\n', 1100);
    memcpy(input + at + 1100, full64, 88);
    expect_results(detector, &ctx, false, input, at + 1100 + 88, &one, 1);
    CHECK(!http.calls && !http.releases);
}

typedef struct { const char *endpoint, *authorization; int status; } expected_request;
typedef struct { const expected_request *items; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls);
    const expected_request *entry = &expected->items[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    char url[256];
    snprintf(url, sizeof(url), "%s/applications?api-version=2020-09-01.12.0", entry->endpoint);
    CHECK(!strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 957);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    size_t content_type = 0, authorization = 0, dated = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Content-Type")) {
            ++content_type;
            CHECK(!strcmp(header->value, "application/json"));
        } else if (!strcmp(header->name, "Authorization")) {
            ++authorization;
            CHECK(!strcmp(header->value, entry->authorization));
        } else if (!strcmp(header->name, "Date")) {
            ++dated;
            CHECK(!strcmp(header->value, date));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog azure-batch-test" : "TruffleHog"));
        } else CHECK(!"unexpected Azure Batch request header");
    }
    CHECK(content_type == 1 && authorization == 1 && dated == 1 && agent == 1);
    if (entry->status) http->response.status = entry->status;
}

static void test_signing_goldens(const br_detector *detector)
{
    /* Independent Python stdlib HMAC goldens. Prefix4 is NONZERO, because
     * zero-only HMAC keys of up to one block would equal the empty-key result. */
    const struct { const char *key, *authorization; } cases[] = {
        {full64, "SharedKey Ab.Cd:INvLl7+JcAtx9AkpJCHTazcXjPjUsS6ekaMSIl9ac0U="},
        {full66, "SharedKey Ab.Cd:CSj85OwJ/C9Eqmuxf8s3nmpNy9nnxXZkrtLi0nCmLGE="},
        {prefix4, "SharedKey Ab.Cd:sa50i2oabQbR8QCIJc5x/62RV9GQ/baDhMMHEVR31bY="},
        {empty_key, "SharedKey Ab.Cd:2vGzI6z/FNagiQHkPrLLWzJVaK6j8Bu/3IuLyYUgbh0="},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_request request = {endpoint, cases[i].authorization, 0};
        expected_requests requests = {&request, 1};
        test_http http = {.response = {.status = 200, .body_error = "ignored body: no such host"},
                          .inspect = inspect_request, .user = &requests};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "azure-batch-test"};
        expected_result result = {.endpoint = text(endpoint), .key = cases[i].key, .verified = true};
        scan_pair(detector, &ctx, true, text(endpoint), cases[i].key, &result, 1);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static void test_occurrences_and_break(const br_detector *detector)
{
    const char *urls[] = {"https://First.r.batch.azure.com", "https://Second.r.batch.azure.com",
                          "https://First.r.batch.azure.com"};
    const char *keys[] = {full64, prefix4, empty_key};
    char input[512];
    size_t at = 0;
    for (size_t i = 0; i < 3; ++i) at += (size_t)snprintf(input + at, sizeof(input) - at, "%s\n", urls[i]);
    for (size_t i = 0; i < 3; ++i) at += (size_t)snprintf(input + at, sizeof(input) - at, "%s\n", keys[i]);
    expected_result all[9];
    for (size_t u = 0; u < 3; ++u)
        for (size_t k = 0; k < 3; ++k) all[u * 3 + k] = (expected_result){.endpoint = text(urls[u]), .key = keys[k]};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_results(detector, &ctx, false, input, at, all, 9);
    CHECK(!http.calls && !http.releases);
    const expected_request request_list[] = {
        {urls[0], "SharedKey First:m1Ak8hm1VZLr5yvmpnRV5j9hn0kvm7lSsAIQHs9DQcw=", 403},
        {urls[0], "SharedKey First:YJFaZPQ5P9r3g1nVabDvtTpHNBlXof3rgEKkfdfHDJ0=", 200},
        {urls[1], "SharedKey Second:R2q/N3UJN7ACjoorjXVKp6xdxiKO0629UV0RNnE45zM=", 403},
        {urls[1], "SharedKey Second:RxlpczI3ZLFu4+F0kGISnwkLVhP3B91KLrI880SS6hs=", 200},
        {urls[2], "SharedKey First:m1Ak8hm1VZLr5yvmpnRV5j9hn0kvm7lSsAIQHs9DQcw=", 403},
        {urls[2], "SharedKey First:YJFaZPQ5P9r3g1nVabDvtTpHNBlXof3rgEKkfdfHDJ0=", 200},
    };
    expected_requests requests = {request_list, 6};
    http = (test_http){.response = {.body_error = "ignored drain failure"},
                       .inspect = inspect_request, .user = &requests};
    expected_result stopped[6];
    for (size_t u = 0; u < 3; ++u) {
        stopped[u * 2] = (expected_result){.endpoint = text(urls[u]), .key = full64};
        stopped[u * 2 + 1] = (expected_result){.endpoint = text(urls[u]), .key = prefix4, .verified = true};
    }
    expect_results(detector, &ctx, true, input, at, stopped, 6);
    CHECK(http.calls == 6 && http.releases == 6);
}

static void test_status_and_errors(const br_detector *detector)
{
    char sensitive[128];
    snprintf(sensitive, sizeof(sensitive), "synthetic key=%s failed", full64);
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL}, {403, 0, NULL, false, NULL},
        {401, 0, NULL, false, "unexpected status code 401 for " REQUEST_URL},
        {201, 0, NULL, false, "unexpected status code 201 for " REQUEST_URL},
        {500, 0, NULL, false, "unexpected status code 500 for " REQUEST_URL},
        {200, 1, "lookup synthetic: no such host", false, NULL},
        {200, 1, "lookup synthetic: No such host", false, "lookup synthetic: No such host"},
        {200, 1, sensitive, false, sensitive}, /* Deliberately NOT redacted, as upstream. */
        {200, 1, "context canceled", false, "context canceled"},
        {200, 1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, 1, NULL, false, "HTTP transport failed"},
        {200, 1, "unsupported: synthetic PUBLIC transport", false, "unsupported: synthetic PUBLIC transport"},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_request request = {endpoint, "SharedKey Ab.Cd:INvLl7+JcAtx9AkpJCHTazcXjPjUsS6ekaMSIl9ac0U=", 0};
        expected_requests requests = {&request, 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = "ignored body: no such host"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &requests,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expected_result result = {.endpoint = text(endpoint), .key = full64,
                                  .verified = cases[i].verified, .error = cases[i].error};
        scan_pair(detector, &ctx, true, text(endpoint), full64, &result, 1);
        CHECK(http.calls == 1 && http.releases == 1);
        result = (expected_result){.endpoint = text(endpoint), .key = full64};
        scan_pair(detector, &ctx, false, text(endpoint), full64, &result, 1);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

int main(void)
{
    CHECK(strlen(full64) == 88 && strlen(full66) == 88);
    memcpy(prefix4, "AQIDBA==", 8);
    memset(prefix4 + 8, 'A', 80);
    prefix4[88] = '\0';
    memset(empty_key, '=', 88);
    empty_key[88] = '\0';
    memset(all_a, 'A', 88);
    all_a[88] = '\0';
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_signing_goldens(detector);
    test_occurrences_and_break(detector);
    test_status_and_errors(detector);
    return test_finish("AzureBatch");
}
