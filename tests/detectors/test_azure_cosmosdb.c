/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <time.h>

static char key[89], other_key[89], padded_key[89];
static const char doc_host[] = "synthetic-cosmos.documents.azure.com";
static const char table_host[] = "synthetic-cosmos.table.cosmos.azure.com";
static const char date_zero[] = "Thu, 01 Jan 1970 00:00:00 GMT";
/* Independent Python stdlib HMAC-SHA256/base64/quote_plus goldens, not computed
 * with production helpers. Artificial binary keys are 64 zero/one bytes. */
static const char *const golden_auth[2][2] = {
    {"type=master&ver=1.0&sig=JqrsvRTl5IJDbaystZVfFdvac3jA4yb9new1nF5rpWI%3D",
     "type=master&ver=1.0&sig=rOM7i%2Bh0nDiHAimQxxKwOEqhiAqq%2Blujg9b83KN8JJM%3D"},
    {"SharedKeyLite synthetic-cosmos.table.cosmos.azure.com:ty/mdxSnF7YdGrYFq0lfDs8yGJ+KnkriuOBrGWgqqRo=",
     "SharedKeyLite synthetic-cosmos.table.cosmos.azure.com:y5PpzzKaTp4XPeuznjF0dXWIBjkbC/sK9RpdkjAZpNI="},
};
static const int64_t ttl_ns = 12LL * 60 * 60 * 1000000000;
static int64_t test_now_ns;
static bool advance_after_next_clock;

int timespec_get(struct timespec *time, int base)
{
    if (base != TIME_UTC) return 0;
    time->tv_sec = (time_t)(test_now_ns / 1000000000);
    time->tv_nsec = (long)(test_now_ns % 1000000000);
    if (advance_after_next_clock) {
        advance_after_next_clock = false;
        test_now_ns += ttl_ns + 1;
    }
    return TIME_UTC;
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azure_cosmosdb_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_azure_cosmosdb_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 971 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AzureCosmosDBKeyIdentifiable") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Azure Cosmos DB is a globally distributed, multi-model database service offered by Microsoft. "
        "CosmosDB keys and connection string are used to connect with Cosmos DB."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], ".documents.azure.com") &&
          !strcmp(detector->keywords[1], ".table.cosmos.azure.com"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, const char *host, bool did_verify)
{
    char raw_v2[256];
    snprintf(raw_v2, sizeof(raw_v2), "key: %s account_url: %s", secret, host);
    CHECK(result->detector_type == 971 && !result->detector_name);
    CHECK(result->raw.len == 88 && !memcmp(result->raw.data, secret, 88));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, strlen(raw_v2)));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), secret));
    CHECK(json_object_object_get_ex(result->secret_parts, "account_url", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), host));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == (did_verify ? 1 : 0));
    if (did_verify) {
        CHECK(json_object_object_get_ex(result->extra_data, "DB Type", &value));
        CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value),
            strstr(host, ".table.cosmos.azure.com") ? "Table" : "Document"));
    }
    CHECK(!result->redacted && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void expect_one(const br_detector *detector, const char *input, const char *secret, const char *host)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (secret ? 1u : 0u) && !http.calls && !http.releases);
    if (secret) {
        check_result(&results.items[0], secret, host, false);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[90], label[46], host[96];
    snprintf(input, sizeof(input), "%s %s", key, doc_host);
    expect_one(detector, input, key, doc_host);
    expect_one(detector, "", NULL, NULL);
    expect_one(detector, key, NULL, NULL);
    expect_one(detector, doc_host, NULL, NULL);
    snprintf(input, sizeof(input), "x%sx %s.evil", key, doc_host);
    expect_one(detector, input, key, doc_host); /* Neither pattern has added boundaries. */
    snprintf(input, sizeof(input), "%s= %s", key, doc_host);
    expect_one(detector, input, key, doc_host); /* Input suffix is outside the captured 88 bytes. */
    memset(changed, 'A', 85);
    memcpy(changed + 85, "==", 3);
    snprintf(input, sizeof(input), "%s %s", changed, doc_host);
    expect_one(detector, input, NULL, NULL);
    const char invalid[] = {'+', '/', '_'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key));
        changed[40] = invalid[i];
        snprintf(input, sizeof(input), "%s %s", changed, doc_host);
        expect_one(detector, input, NULL, NULL);
    }
    const struct { const char *source, *captured; } hosts[] = {
        {"aa.documents.azure.com", NULL}, {"abc.documents.azure.com", "abc.documents.azure.com"},
        {"---.documents.azure.com", "---.documents.azure.com"},
        {"_abc.documents.azure.com", "abc.documents.azure.com"},
        {"UPPERabc.documents.azure.com", "abc.documents.azure.com"},
        {"ABC.documents.azure.com", NULL}, {"abc.Documents.azure.com", NULL},
        {"abc.table.cosmos.azure.com", "abc.table.cosmos.azure.com"},
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s", key, hosts[i].source);
        expect_one(detector, input, hosts[i].captured ? key : NULL, hosts[i].captured);
    }
    memset(label, 'a', 45);
    label[45] = '\0';
    snprintf(input, sizeof(input), "%s %s.documents.azure.com", key, label);
    snprintf(host, sizeof(host), "%s.documents.azure.com", label + 1);
    expect_one(detector, input, key, host); /* Overlong labels yield a 44-byte suffix, not strict DNS rejection. */
    snprintf(input, sizeof(input), "%s %s %s %s", key, doc_host, key, doc_host);
    expect_one(detector, input, key, doc_host);
}

typedef struct {
    const char *hosts[2], *authorization[2][2];
    size_t nhosts, nkeys, seen[2][2];
    const br_scan_ctx *original;
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx != expected->original && ctx->transport && ctx->transport->user == http);
    CHECK(!ctx->cancelled && !ctx->cancel_user && !ctx->deadline_monotonic_ms);
    CHECK(ctx->user_agent == expected->original->user_agent && ctx->endpoints == expected->original->endpoints &&
          ctx->options == expected->original->options);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 971 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    size_t h = 0;
    char url[128];
    for (; h < expected->nhosts; ++h) {
        snprintf(url, sizeof(url), "https://%s:443/%s", expected->hosts[h],
            strstr(expected->hosts[h], ".table.cosmos.azure.com") ? "Tables" : "dbs");
        if (!strcmp(request->url, url)) break;
    }
    CHECK(h < expected->nhosts);
    bool table = strstr(expected->hosts[h], ".table.cosmos.azure.com") != NULL;
    CHECK(request->nheaders == (table ? 5u : 4u));
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    size_t k = 0;
    while (k < expected->nkeys && strcmp(request->headers[0].value, expected->authorization[h][k])) ++k;
    CHECK(k < expected->nkeys);
    ++expected->seen[h][k];
    CHECK(!strcmp(request->headers[1].name, "x-ms-date") && !strcmp(request->headers[1].value, date_zero));
    CHECK(!strcmp(request->headers[2].name, "x-ms-version") &&
          !strcmp(request->headers[2].value, table ? "2019-02-02" : "2018-12-31"));
    if (table) CHECK(!strcmp(request->headers[3].name, "Accept") && !strcmp(request->headers[3].value, "application/json"));
    CHECK(!strcmp(request->headers[request->nheaders - 1].name, "User-Agent") &&
          !strcmp(request->headers[request->nheaders - 1].value, "TruffleHog cosmos-test"));
}

static bool always_cancel(void *user)
{
    ++*(size_t *)user;
    return true;
}

static void verify_case(const br_detector *detector, const char *secret, bool table,
                        test_http *http, bool verified, const char *error)
{
    const char *host = table ? table_host : doc_host;
    char input[256];
    snprintf(input, sizeof(input), "%s %s", secret, host);
    requests expected = {.hosts = {host}, .authorization = {{golden_auth[table ? 1 : 0][0]}}, .nhosts = 1, .nkeys = 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_endpoints endpoints = {0};
    br_json *options = json_object_new_object();
    CHECK(options);
    size_t cancel_calls = 0;
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "cosmos-test", .endpoints = &endpoints, .options = options,
        .deadline_monotonic_ms = 1, .cancelled = always_cancel, .cancel_user = &cancel_calls};
    expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1 && expected.seen[0][0] == 1);
    CHECK(!cancel_calls && ctx.cancelled == always_cancel && ctx.cancel_user == &cancel_calls && ctx.deadline_monotonic_ms == 1);
    check_result(&results.items[0], secret, host, true);
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    json_object_put(options);
}

static void verification(const br_detector *detector)
{
    const struct { bool table; int status; bool verified; const char *error; } cases[] = {
        {false, 200, true, NULL}, {true, 200, true, NULL},
        {false, 401, false, NULL}, {true, 401, false, NULL},
        {false, 403, false, "unexpected status code: 403"}, {true, 403, false, NULL},
        {false, 500, false, "unexpected status code: 500"}, {true, 500, false, "unexpected status code: 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "no such host"}};
        verify_case(detector, key, cases[i].table, &http, cases[i].verified, cases[i].error);
    }
    test_http http = {.send_rc = -1, .send_error = "No such host", .response = {.status = 200}};
    verify_case(detector, key, false, &http, false, "No such host");
    http.send_error = NULL;
    verify_case(detector, key, true, &http, false, "HTTP transport failed");
    char cause[512];
    snprintf(cause, sizeof(cause), "key=%s host=%s repeated=%s", key, doc_host, key);
    http.send_error = cause;
    verify_case(detector, key, false, &http, false, cause); /* Source intentionally does not redact key. */
    http = (test_http){.response = {.status = 200}};
    verify_case(detector, padded_key, false, &http, true, NULL); /* Nonzero unused pad bits decode to the SAME zero bytes. */
    char input[256];
    snprintf(input, sizeof(input), "%s %s", key, table_host);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_result(&results.items[0], key, table_host, true);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void unique_pairs(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "%s %s %s %s %s %s", key, other_key, key, doc_host, table_host, doc_host);
    requests expected = {.hosts = {doc_host, table_host}, .authorization = {
        {golden_auth[0][0], golden_auth[0][1]}, {golden_auth[1][0], golden_auth[1][1]}}, .nhosts = 2, .nkeys = 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "cosmos-test"};
    expected.original = &ctx;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && !http.calls && !http.releases);
    bool seen[2][2] = {{false}};
    for (size_t r = 0; r < results.len; ++r) {
        const char *secret = !memcmp(results.items[r].raw.data, key, 88) ? key : other_key;
        br_json *host = NULL;
        CHECK(json_object_object_get_ex(results.items[r].secret_parts, "account_url", &host));
        const char *account = json_object_get_string(host);
        CHECK(!strcmp(account, doc_host) || !strcmp(account, table_host));
        size_t k = secret == key ? 0 : 1, h = !strcmp(account, doc_host) ? 0 : 1;
        CHECK(!seen[k][h]);
        seen[k][h] = true;
        check_result(&results.items[r], secret, account, false);
        CHECK(!results.items[r].verified && !results.items[r].verification_error);
    }
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t h = 0; h < 2; ++h)
        for (size_t k = 0; k < 2; ++k) CHECK(expected.seen[h][k] == 1);
    for (size_t r = 0; r < results.len; ++r) CHECK(results.items[r].verified && !results.items[r].verification_error);
    br_results_clear(&results);
}

static void cache_expiry(const br_detector *detector)
{
    const char *hosts[] = {"cache-doc.documents.azure.com", "cache-table.table.cosmos.azure.com"};
    test_http http = {.send_rc = -1, .send_error = "wrapped lookup: no such hostname"};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[512];
    int64_t start = test_now_ns;
    for (size_t h = 0; h < 2; ++h) {
        http.calls = http.releases = 0;
        snprintf(input, sizeof(input), "%s %s %s", key, other_key, hosts[h]);
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(!results.len && http.calls == 1 && http.releases == 1); /* Suppress CURRENT candidate, then skip next key. */
        br_results_clear(&results);
        if (!h) test_now_ns += 5;
    }
    snprintf(input, sizeof(input), "%s %s %s %s", key, other_key, hosts[0], hosts[1]);
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    test_now_ns = start + ttl_ns;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len && http.calls == 1);
    br_results_clear(&results);
    ++test_now_ns;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 1);
    for (size_t i = 0; i < results.len; ++i)
        check_result(&results.items[i], !memcmp(results.items[i].raw.data, key, 88) ? key : other_key, hosts[0], false);
    br_results_clear(&results);
    test_now_ns = start + ttl_ns + 5;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 1);
    br_results_clear(&results);
    ++test_now_ns;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
}

static void expire_after_cache_add(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx; (void)request;
    if (http->calls == 1) {
        http->send_rc = -1;
        http->send_error = "no such host";
        /* The next wall-clock read is cache.Set. Return its timestamp, then
         * expire it BEFORE the next key's Exists check. */
        advance_after_next_clock = true;
    } else {
        http->send_rc = 0;
        http->send_error = NULL;
        http->response.status = 200;
    }
}

static void advance_on_second_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx; (void)request;
    if (http->calls == 2) test_now_ns += ttl_ns + 1;
}

static void local_host_removal(const br_detector *detector)
{
    char input[512];
    const char retry_host[] = "retry.documents.azure.com";
    test_http http = {.inspect = expire_after_cache_add};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s %s %s", key, other_key, retry_host);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results); /* A DNS failure alone must NOT remove the local host. */

    const char bad[] = "removed.documents.azure.com", good[] = "remaining.documents.azure.com";
    http = (test_http){.send_rc = -1, .send_error = "no such host"};
    snprintf(input, sizeof(input), "%s %s", key, bad);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http = (test_http){.response = {.status = 200}, .inspect = advance_on_second_request};
    snprintf(input, sizeof(input), "%s %s %s %s %s", key, other_key, padded_key, bad, good);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        br_json *host = NULL;
        CHECK(json_object_object_get_ex(results.items[i].secret_parts, "account_url", &host));
        CHECK(!strcmp(json_object_get_string(host), good));
    }
    br_results_clear(&results); /* Once Exists was true, removal persists for THIS scan. */
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 6 && http.calls == 3 && http.releases == 3);
    br_results_clear(&results);
}

int main(void)
{
    memset(key, 'A', 86);
    memcpy(key + 86, "==", 3);
    memcpy(padded_key, key, sizeof(key));
    padded_key[85] = 'B';
    unsigned char raw[64];
    memset(raw, 1, sizeof(raw));
    CHECK(EVP_EncodeBlock((unsigned char *)other_key, raw, sizeof(raw)) == 88);
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    unique_pairs(detector);
    cache_expiry(detector);
    local_host_removal(detector);
    return test_finish("AzureCosmosDBKeyIdentifiable");
}
