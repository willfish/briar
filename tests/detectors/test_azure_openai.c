/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static const char key[] = "0123456789abcdef0123456789abcdef";
static const char other_key[] = "abcdef0123456789abcdef0123456789";
static const char host[] = "MiXeD-Fixture.OpenAI.Azure.COM";
static const int64_t ttl_ns = 12LL * 60 * 60 * 1000000000;
static int64_t test_now_ns = 1700000000000000000LL;

int timespec_get(struct timespec *time, int base)
{
    if (base != TIME_UTC) return 0;
    time->tv_sec = (time_t)(test_now_ns / 1000000000);
    time->tv_nsec = (long)(test_now_ns % 1000000000);
    return TIME_UTC;
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azure_openai_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_azure_openai_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 1007 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AzureOpenAI") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Azure OpenAI provides various AI models and services. The API keys can be used to access and interact with these models and services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".openai.azure.com"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, const char *selected_host)
{
    CHECK(result->detector_type == 1007 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, secret, 32));
    char redacted[14];
    snprintf(redacted, sizeof(redacted), "%.3s...%s", secret, secret + 25);
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), secret));
    if (selected_host) {
        CHECK(result->raw_v2.data && result->raw_v2.len == 33 + strlen(selected_host));
        CHECK(!memcmp(result->raw_v2.data, secret, 32) && result->raw_v2.data[32] == ':');
        CHECK(!memcmp(result->raw_v2.data + 33, selected_host, strlen(selected_host)));
    } else CHECK(!result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void expect_no_verify(const br_detector *detector, const char *input, const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_result(&results.items[i], keys[i], NULL); /* NEVER attach a URL without verification. */
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[33], padding[42];
    const char *one[] = {key};
    const char *prefixes[] = {"apikey", "api_key", "API.KEY", "Api-Key", "openaikey", "OPENAI_KEY", "openai-key", "openai.key"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s", prefixes[i], key);
        expect_no_verify(detector, input, one, 1); /* A host is not required by FromData. */
    }
    expect_no_verify(detector, "", NULL, 0);
    expect_no_verify(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s %s", host, key);
    expect_no_verify(detector, input, NULL, 0); /* Dispatch keyword is NOT the key prefix regex. */
    snprintf(input, sizeof(input), "api key %s", key);
    expect_no_verify(detector, input, NULL, 0);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "api_key%.*s%s", gap, padding, key);
        expect_no_verify(detector, input, one, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "API_KEY\r\n%s", key);
    expect_no_verify(detector, input, one, 1);
    const char *invalid[] = {"api_key%s", "api_key _%s", "api_key %s_", "api_key %.31s", "api_key %sa"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        snprintf(input, sizeof(input), invalid[i], key);
        expect_no_verify(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(key));
    changed[12] = 'A';
    snprintf(input, sizeof(input), "API_KEY %s", changed);
    expect_no_verify(detector, input, NULL, 0);
    changed[12] = 'g';
    snprintf(input, sizeof(input), "api_key %s", changed);
    expect_no_verify(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "api_key %s\n%s", key, host);
    expect_no_verify(detector, input, one, 1);
    snprintf(input, sizeof(input), "api_key %s\napi_key %s\napi_key %s\n%s", key, other_key, key, host);
    const char *unique[] = {key, other_key};
    expect_no_verify(detector, input, unique, 2);
}

typedef struct {
    const char *keys[2], *hosts[2];
    size_t nkeys, nhosts, seen[2][2];
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1007 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Api-Key"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog azure-openai-test"));
    size_t k = 0, h = 0;
    while (k < expected->nkeys && strcmp(request->headers[0].value, expected->keys[k])) ++k;
    for (; h < expected->nhosts; ++h) {
        size_t size = strlen(expected->hosts[h]) + sizeof("https:///openai/deployments?api-version=2023-03-15-preview");
        char *url = malloc(size);
        CHECK(url);
        snprintf(url, size, "https://%s/openai/deployments?api-version=2023-03-15-preview", expected->hosts[h]);
        bool matches = !strcmp(url, request->url);
        free(url);
        if (matches) break;
    }
    CHECK(k < expected->nkeys && h < expected->nhosts);
    ++expected->seen[k][h];
}

static void verify_single(const br_detector *detector, test_http *http, const char *service,
                           bool verified, const char *error)
{
    size_t size = strlen(service) + strlen(key) + sizeof("api_key \n");
    char *input = malloc(size);
    CHECK(input);
    snprintf(input, size, "api_key %s\n%s", key, service);
    requests expected = {.keys = {key}, .hosts = {service}, .nkeys = 1, .nhosts = 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "azure-openai-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1 && expected.seen[0][0] == 1);
    check_result(&results.items[0], key, service);
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    free(input);
}

static void typed_json(const br_detector *detector)
{
    const struct { const char *body; bool verified; const char *error; } cases[] = {
        {"{\"object\":\"list\",\"data\":[{\"id\":\"synthetic\"}]}", true, NULL},
        {"{\"object\":\"anything\",\"data\":[]}", true, NULL},
        {"{\"object\":\"list\",\"data\":[null,{}, {\"id\":null}]}", true, NULL},
        {"{\"OBJECT\":\"list\",\"DATA\":[{\"ID\":\"x\"}]}", true, NULL},
        {"{\"object\":\"list\",\"object\":null}", true, NULL},
        {"{\"object\":\"list\",\"object\":\"\"}", false, NULL},
        {"{\"object\":\"\\u0000\"}", true, NULL},
        {"{\"object\":\"list\",\"data\":null}", true, NULL},
        {"{\"data\":[{\"id\":\"first\"}],\"DATA\":[null,{\"id\":null}],\"object\":\"list\"}", true, NULL},
        {"{\"object\":\"list\",\"unknown\":1e10000,\"data\":[{\"ignored\":999999999999999999999999999999999999}]}", true, NULL},
        {"{}", false, NULL}, {"null", false, NULL}, {"{\"data\":[{\"id\":\"x\"}]}", false, NULL},
        {"not JSON", false, NULL}, {"", false, NULL}, {"{\"object\":\"list\"} trailing", false, NULL},
        {"{\"object\":\"list\"}{\"object\":\"list\"}", false, NULL},
        {"[]", false, "json: cannot unmarshal array into Go value of type azure_openai.deploymentsResponse"},
        {"{\"object\":7}", false, "json: cannot unmarshal number into Go struct field deploymentsResponse.object of type string"},
        {"{\"object\":7,\"object\":\"list\"}", false, "json: cannot unmarshal number into Go struct field deploymentsResponse.object of type string"},
        {"{\"object\":\"list\",\"data\":{}}", false, "json: cannot unmarshal object into Go struct field deploymentsResponse.data of type []azure_openai.deployment"},
        {"{\"object\":\"list\",\"data\":[1]}", false, "json: cannot unmarshal number into Go struct field deploymentsResponse.data of type azure_openai.deployment"},
        {"{\"object\":\"list\",\"data\":[{\"id\":1}]}", false, "json: cannot unmarshal number into Go struct field deployment.data.id of type string"},
        {"{\"object\":\"list\",\"data\":[{\"id\":false,\"ID\":\"fixed\"}]}", false, "json: cannot unmarshal bool into Go struct field deployment.data.id of type string"},
        {"{\"data\":[{\"id\":{} }],\"data\":null,\"object\":\"list\"}", false, "json: cannot unmarshal object into Go struct field deployment.data.id of type string"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = 200,
            .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}}};
        verify_single(detector, &http, host, cases[i].verified, cases[i].error);
    }
}

static void verification(const br_detector *detector)
{
    char status_error[256];
    const int statuses[] = {401, 403, 500};
    for (size_t i = 0; i < 3; ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}};
        snprintf(status_error, sizeof(status_error),
            "unexpected response status %d for https://%s/openai/deployments?api-version=2023-03-15-preview", statuses[i], host);
        verify_single(detector, &http, host, false, statuses[i] == 401 ? NULL : status_error);
    }
    const char body[] = "{\"object\":\"list\"}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}, .body_error = "read failed"}};
    verify_single(detector, &http, host, false, "read failed"); /* ReadAll failure wins even with a complete valid document. */
    http = (test_http){.send_rc = -1, .send_error = "context canceled"};
    verify_single(detector, &http, host, false, "context canceled");
    http.send_error = NULL;
    verify_single(detector, &http, host, false, "HTTP transport failed");
    char cause[384], redacted[384];
    snprintf(cause, sizeof(cause), "key=%s host=%s again=%s other=%s", key, host, key, other_key);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] host=%s again=[REDACTED] other=%s", host, other_key);
    http.send_error = cause;
    verify_single(detector, &http, host, false, redacted);

    const char dns_host[] = "single-dns.openai.azure.com";
    http.send_error = "lookup synthetic: no such host";
    verify_single(detector, &http, dns_host, false, http.send_error);
    verify_single(detector, &http, dns_host, false, http.send_error); /* Single-host DNS was NOT cached. */
    char input[256];
    snprintf(input, sizeof(input), "api_key %s\n%s", key, host);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_result(&results.items[0], key, host);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void host_loop(const br_detector *detector)
{
    const char *services[] = {"first-loop.openai.azure.com", "Second-Loop.OpenAI.Azure.COM"};
    char input[256];
    snprintf(input, sizeof(input), "api_key %s\napi_key %s\n%s\n%s\n%s", key, other_key, services[0], services[1], services[0]);
    requests expected = {.keys = {key, other_key}, .hosts = {services[0], services[1]}, .nkeys = 2, .nhosts = 2};
    test_http http = {.response = {.status = 401}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "azure-openai-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < 2; ++i) {
        check_result(&results.items[i], i ? other_key : key, NULL);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results); /* Multiple ordinary failures do NOT select the last visited host. */
    const char bad_type[] = "{\"object\":3}";
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)bad_type, sizeof(bad_type) - 1}},
                       .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < 2; ++i) CHECK(!results.items[i].verification_error && !results.items[i].raw_v2.data);
    br_results_clear(&results);
    const char good[] = "{\"object\":\"list\"}";
    expected = (requests){.keys = {key, other_key}, .hosts = {services[0], services[1]}, .nkeys = 2, .nhosts = 2};
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)good, sizeof(good) - 1}},
                       .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) {
        check_result(&results.items[i], i ? other_key : key, services[0]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
        CHECK(expected.seen[i][0] == 1 && !expected.seen[i][1]);
    }
    br_results_clear(&results); /* Success stops THIS key, but does not consume the host for later keys. */
    http.calls = http.releases = 0;
    snprintf(input, sizeof(input), "api_key %s\napi_key %s", key, other_key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !http.calls && !http.releases);
    for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], i ? other_key : key, NULL);
    br_results_clear(&results);
}

static void cache_branch_order(const br_detector *detector)
{
    const char *services[] = {"cache-a.openai.azure.com", "cache-b.openai.azure.com"};
    char input[256];
    snprintf(input, sizeof(input), "api_key %s\napi_key %s\n%s\n%s", key, other_key, services[0], services[1]);
    requests expected = {.keys = {key, other_key}, .hosts = {services[0], services[1]}, .nkeys = 2, .nhosts = 2};
    test_http http = {.send_rc = -1, .send_error = "lookup synthetic: no such host", .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "azure-openai-test"};
    int64_t start = test_now_ns;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 3 && http.releases == 3);
    CHECK(expected.seen[0][0] == 1 && expected.seen[0][1] == 1 && !expected.seen[1][0] && expected.seen[1][1] == 1);
    for (size_t i = 0; i < 2; ++i) {
        check_result(&results.items[i], i ? other_key : key, services[1]);
        CHECK(!results.items[i].verified && results.items[i].verification_error &&
              !strcmp(results.items[i].verification_error, "lookup synthetic: no such host"));
    }
    br_results_clear(&results); /* Deleting the first DNS host shrinks the shared set across keys. */
    const char *keys[] = {key, other_key};
    expect_no_verify(detector, input, keys, 2);
    snprintf(input, sizeof(input), "api_key %s\n%s", key, services[0]);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !http.calls && !http.releases);
    check_result(&results.items[0], key, NULL);
    CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    test_now_ns = start + ttl_ns;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !http.calls && !http.releases && !results.items[0].raw_v2.data);
    br_results_clear(&results); /* Exact expiry instant is still present. */
    ++test_now_ns;
    expected = (requests){.keys = {key}, .hosts = {services[0]}, .nkeys = 1, .nhosts = 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, services[0]);
    CHECK(results.items[0].verification_error);
    br_results_clear(&results); /* Now single-host DNS is retained and not cached again. */
}

static void case_sensitive_presence(const br_detector *detector)
{
    const char upper[] = "CacheCase.OpenAI.Azure.COM", lower[] = "cachecase.openai.azure.com";
    char input[192];
    snprintf(input, sizeof(input), "api_key %s\n%s\ncase-sentinel.openai.azure.com", key, upper);
    test_http http = {.send_rc = -1, .send_error = "no such host"};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "api_key %s\n%s", key, upper);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !http.calls && !http.releases && !results.items[0].raw_v2.data);
    br_results_clear(&results);
    verify_single(detector, &http, lower, false, "no such host"); /* Capture spelling is also the cache key. */
}

static void long_host(const br_detector *detector)
{
    size_t label_len = 2048;
    char *service = malloc(label_len + sizeof(".OpenAI.Azure.COM"));
    CHECK(service);
    memset(service, 'z', label_len);
    service[0] = 'Z';
    memcpy(service + label_len, ".OpenAI.Azure.COM", sizeof(".OpenAI.Azure.COM"));
    const char body[] = "{\"object\":\"list\"}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}}};
    verify_single(detector, &http, service, true, NULL);
    size_t size = strlen(service) + sizeof("unexpected response status 500 for https:///openai/deployments?api-version=2023-03-15-preview");
    char *error = malloc(size);
    CHECK(error);
    snprintf(error, size, "unexpected response status 500 for https://%s/openai/deployments?api-version=2023-03-15-preview", service);
    http = (test_http){.response = {.status = 500}};
    verify_single(detector, &http, service, false, error);
    free(error);
    free(service);
}

int main(void)
{
    const br_detector *detector = detector_init();
    extraction(detector);
    typed_json(detector);
    verification(detector);
    host_loop(detector);
    cache_branch_order(detector);
    case_sensitive_presence(detector);
    long_host(detector);
    return test_finish("AzureOpenAI");
}
