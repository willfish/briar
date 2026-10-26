/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static const char full64[] = "ACVKb5S53gMoTXKXvOEGK1B1mr/kCS5TeJ3C5wwxVnugxeoPNFl+o8jtEjdcgabL8BU6X4SpzvMYPWKHrNH2Gw==";
static const char full66[] = "ADVqn9QJPnOo3RJHfLHmG1CFuu8kWY7D+C1il8wBNmug1Qo/dKneE0h9succUYa78CVaj8T5LmOYzQI3bKHWC0B1";
static const char emulator_key[] = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
static char prefix3[89], empty_key[89], all_a[89];
static const char date[] = "Tue, 02 Jan 2024 03:04:05 GMT";
static const char syntax_cause[] = "unsupported: Azure Storage XML syntax/whole-document or namespace semantics";

time_t time(time_t *out)
{
    time_t value = (time_t)1704164645;
    if (out) *out = value;
    return value;
}

typedef struct {
    const char *name, *key;
    bool verified;
    const char *error, *containers;
} expected_result;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azure_storage_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 931 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AzureStorage") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Azure Storage is a Microsoft-managed cloud service that provides storage "
        "that is highly available, secure, durable, scalable, and redundant. "
        "Azure Storage Account keys can be used to access and manage data within storage accounts."));
    const char *const keywords[] = {
        "DefaultEndpointsProtocol=http", "EndpointSuffix", "core.windows.net",
        "AccountName", "Account_Name", "Account.Name", "Account-Name",
        "StorageAccount", "Storage_Account", "Storage.Account", "Storage-Account",
        "AccountKey", "Account_Key", "Account.Key", "Account-Key",
    };
    CHECK(detector->nkeywords == sizeof(keywords) / sizeof(keywords[0]));
    for (size_t i = 0; i < detector->nkeywords; ++i) CHECK(!strcmp(detector->keywords[i], keywords[i]));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *patterns = detector->state;
    CHECK(br_azure_storage_init(&again, &error) == 0 && !error && again == detector && again->state == patterns);
    CHECK(br_azure_storage_init(&again, NULL) == 0 && again == detector);
    CHECK(br_azure_storage_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_azure_storage_init(NULL, NULL) != 0);
    return detector;
}

static void check_text(br_json *object, const char *field, const char *text)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, field, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(text));
    CHECK(!strcmp(json_object_get_string(value), text));
}

static void check_result(const br_result *result, const expected_result *expected)
{
    CHECK(result->detector_type == 931 && !result->detector_name);
    CHECK(result->raw.len == strlen(expected->key) && !memcmp(result->raw.data, expected->key, result->raw.len));
    char raw_v2[192];
    int n = snprintf(raw_v2, sizeof(raw_v2), "{\"accountName\":\"%s\",\"accountKey\":\"%s\"}", expected->name, expected->key);
    CHECK(n > 0 && (size_t)n < sizeof(raw_v2));
    CHECK(result->raw_v2.len == (size_t)n && !memcmp(result->raw_v2.data, raw_v2, (size_t)n));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_text(result->secret_parts, "account_name", expected->name);
    check_text(result->secret_parts, "account_key", expected->key);
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == (expected->containers ? 2 : 1));
    check_text(result->extra_data, "Account_name", expected->name);
    if (expected->containers) check_text(result->extra_data, "container_names", expected->containers);
    CHECK(result->verified == expected->verified);
    if (expected->error) {
        CHECK(result->verification_error && !strcmp(result->verification_error, expected->error));
        CHECK(!strstr(result->verification_error, expected->key));
    } else CHECK(!result->verification_error);
    CHECK(!result->redacted && !result->structured_data && !result->verification_from_cache);
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

static void scan_config(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         const char *name, const char *key, const expected_result *expected, size_t count)
{
    char input[256];
    int n = snprintf(input, sizeof(input), "AccountName=%s\nAccountKey=%s", name, key);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expect_results(detector, ctx, verify, input, (size_t)n, expected, count);
}

static void test_extraction(const br_detector *detector)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expected_result one = {.name = "acctone", .key = full64};
    scan_config(detector, &ctx, false, one.name, full64, &one, 1);
    expect_results(detector, &ctx, false, NULL, 0, NULL, 0);
    char input[2048], changed[91];
    const char *name_prefixes[] = {"Account.Name", "STORAGE_NAME", "Storage-Account"};
    const char *key_prefixes[] = {"Storage.Key", "Access_Key", "ACCOUNT-KEY"};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(input, sizeof(input), "%s=acctone\n%s=%s", name_prefixes[i], key_prefixes[i], full64);
        expect_results(detector, &ctx, false, input, strlen(input), &one, 1);
    }
    snprintf(input, sizeof(input), "ZZZacctone.BLOB.CORE.WINDOWS.NET\nAccessKey=%s", full64);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1); /* Alternate has no leading boundary. */
    snprintf(input, sizeof(input), "AccountKey=%s", full64);
    expect_results(detector, &ctx, true, input, strlen(input), NULL, 0);
    expect_results(detector, &ctx, true, "AccountName=acctone", strlen("AccountName=acctone"), NULL, 0);
    const char *excluded_names[] = {"devstoreaccount1", "storagesample"};
    for (size_t i = 0; i < 2; ++i) scan_config(detector, &ctx, true, excluded_names[i], full64, NULL, 0);
    scan_config(detector, &ctx, true, "acctone", emulator_key, NULL, 0);
    memcpy(changed, emulator_key, sizeof(emulator_key));
    changed[0] = 'A';
    one.key = changed;
    scan_config(detector, &ctx, false, one.name, changed, &one, 1); /* Only the exact public emulator key is excluded. */
    one.key = full64;

    size_t at = (size_t)snprintf(input, sizeof(input), "AccountName=UPPERCASE");
    memset(input + at, '\n', 50);
    snprintf(input + at + 50, sizeof(input) - at - 50, "AccountKey=%s", full64);
    expect_results(detector, &ctx, false, input, strlen(input), NULL, 0);
    char longest_name[25];
    memset(longest_name, 'a', 24);
    longest_name[24] = '\0';
    one.name = longest_name;
    snprintf(input, sizeof(input), "a%s.blob.core.windows.net\nAccountKey=%s", longest_name, full64);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1); /* Suffix alternate captures the last 24. */
    one.name = "acctone";
    for (size_t gap = 20; gap <= 21; ++gap) {
        at = (size_t)snprintf(input, sizeof(input), "AccountName");
        memset(input + at, '.', gap);
        at += gap;
        memcpy(input + at, "acctone", 7);
        at += 7;
        memset(input + at, '\n', 50);
        at += 50;
        snprintf(input + at, sizeof(input) - at, "AccountKey=%s", full64);
        expect_results(detector, &ctx, false, input, strlen(input), &one, gap == 20 ? 1 : 0);
    }
    for (size_t gap = 25; gap <= 26; ++gap) {
        at = (size_t)snprintf(input, sizeof(input), "AccountName=acctone\nAccountKey");
        memset(input + at, '.', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", full64);
        expect_results(detector, &ctx, false, input, strlen(input), &one, gap == 25 ? 1 : 0);
    }
    at = (size_t)snprintf(input, sizeof(input), "AccountName");
    memset(input + at, '\r', 20);
    at += 20;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "acctone\nAccountKey");
    memset(input + at, '\r', 25);
    snprintf(input + at + 25, sizeof(input) - at - 25, "%s", full64);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1);

    memset(changed, 'A', 85);
    changed[85] = '\0';
    scan_config(detector, &ctx, false, one.name, changed, NULL, 0);
    changed[85] = 'A';
    changed[86] = '\0';
    one.key = changed;
    scan_config(detector, &ctx, false, one.name, changed, &one, 1);
    memset(changed, 'A', 88);
    memcpy(changed + 88, "==", 3);
    scan_config(detector, &ctx, false, one.name, changed, &one, 1); /* 88 base chars plus two padding chars. */
    memset(changed, 'A', 89);
    changed[89] = '\0';
    one.key = all_a;
    scan_config(detector, &ctx, false, one.name, changed, &one, 1);
    memcpy(changed, full64, sizeof(full64));
    changed[20] = '_';
    scan_config(detector, &ctx, false, one.name, changed, NULL, 0);
    one.key = prefix3;
    scan_config(detector, &ctx, false, one.name, prefix3, &one, 1);
    one.key = full64;
    at = (size_t)snprintf(input, sizeof(input), "AccountName=acctone");
    memset(input + at, '\n', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "AccountKey=%s", full64);
    expect_results(detector, &ctx, false, input, strlen(input), &one, 1);
    CHECK(!http.calls && !http.releases);
}

typedef struct { const char *name, *authorization; int status; } expected_request;
typedef struct { const expected_request *items; size_t count; uint32_t timeout_limit; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls);
    const expected_request *entry = &expected->items[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    char url[128];
    snprintf(url, sizeof(url), "https://%s.blob.core.windows.net/?comp=list", entry->name);
    CHECK(!strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->detector_type == 931);
    if (expected->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    else CHECK(request->timeout_ms == 10000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4);
    size_t dated = 0, version = 0, auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "x-ms-date")) {
            ++dated;
            CHECK(!strcmp(header->value, date));
        } else if (!strcmp(header->name, "x-ms-version")) {
            ++version;
            CHECK(!strcmp(header->value, "2019-12-12"));
        } else if (!strcmp(header->name, "Authorization")) {
            ++auth;
            CHECK(!strcmp(header->value, entry->authorization));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog azure-storage-test" : "TruffleHog"));
        } else CHECK(!"unexpected Azure Storage request header");
    }
    CHECK(dated == 1 && version == 1 && auth == 1 && agent == 1);
    if (entry->status) http->response.status = entry->status;
}

static void test_signing_goldens(const br_detector *detector)
{
    /* Independent Python stdlib HMAC vectors, with opaque 64/66-byte decoded
     * keys, a NONZERO decoded prefix before '-', and an empty decoded prefix. */
    const struct { const char *key, *authorization; } cases[] = {
        {full64, "SharedKey acctone:Vw0njoMRxLpCu4MIZKRVq15jNL6yn+h/N8KBbgRipxE="},
        {full66, "SharedKey acctone:xNWKZUYW1qIi6EvAgGbrHZCb48tvV4W3IZ6oPEur7Lc="},
        {prefix3, "SharedKey acctone:GV99rxEJDLkxUZtJUzJhFuclqZsAA1MWIwF6gVMfbLs="},
        {empty_key, "SharedKey acctone:MWPnRImujO0P2bJemC6n6s+cO4PVlkYdvaG3Lbiplk0="},
    };
    static const unsigned char body[] = "<anything/>";
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_request request = {"acctone", cases[i].authorization, 0};
        expected_requests requests = {.items = &request, .count = 1};
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}},
                          .inspect = inspect_request, .user = &requests};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "azure-storage-test"};
        expected_result expected = {.name = "acctone", .key = cases[i].key, .verified = true};
        scan_config(detector, &ctx, true, expected.name, cases[i].key, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static void test_unique_product_and_break(const br_detector *detector)
{
    char input[768];
    snprintf(input, sizeof(input), "AccountName=acctone\nAccountName=accttwo\nacctone.blob.core.windows.net\n"
             "AccountKey=%s\nAccessKey=%s\nStorageKey=%s\nAccountKey=%s", full64, prefix3, full66, full64);
    const char *names[] = {"acctone", "accttwo"};
    const char *keys[] = {full64, prefix3, full66};
    expected_result all[6];
    for (size_t a = 0; a < 2; ++a)
        for (size_t k = 0; k < 3; ++k) all[a * 3 + k] = (expected_result){.name = names[a], .key = keys[k]};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_results(detector, &ctx, false, input, strlen(input), all, 6);
    CHECK(!http.calls && !http.releases);
    const expected_request request_list[] = {
        {"acctone", "SharedKey acctone:Vw0njoMRxLpCu4MIZKRVq15jNL6yn+h/N8KBbgRipxE=", 403},
        {"acctone", "SharedKey acctone:GV99rxEJDLkxUZtJUzJhFuclqZsAA1MWIwF6gVMfbLs=", 200},
        {"accttwo", "SharedKey accttwo:T3um9j2JzjJTJLeHbPQyFmOimAJY1bFjskvqofmI1DA=", 403},
        {"accttwo", "SharedKey accttwo:YkOgQ8FIOHkucN3m79CXetyR+ArXVzTSMpK8oWChlP8=", 200},
    };
    static const unsigned char body[] = "<r/>";
    expected_requests requests = {.items = request_list, .count = 4};
    http = (test_http){.response = {.body = {body, sizeof(body) - 1}}, .inspect = inspect_request, .user = &requests};
    expected_result stopped[4];
    for (size_t a = 0; a < 2; ++a) {
        stopped[a * 2] = (expected_result){.name = names[a], .key = full64};
        stopped[a * 2 + 1] = (expected_result){.name = names[a], .key = prefix3, .verified = true};
    }
    expect_results(detector, &ctx, true, input, strlen(input), stopped, 4);
    CHECK(http.calls == 4 && http.releases == 4);
}

static void test_xml(const br_detector *detector)
{
    char sensitive[128], redacted[128];
    snprintf(sensitive, sizeof(sensitive), "synthetic read for %s failed", full64);
    snprintf(redacted, sizeof(redacted), "synthetic read for [REDACTED] failed");
    const struct {
        const char *body, *read_error;
        bool verified;
        const char *error, *containers;
    } cases[] = {
        {"<arbitrary/>", NULL, true, NULL, NULL},
        {"<Arbitrary><Containers><Container><Name> A<![CDATA[B]]><!--ignored--><Skip>NOT</Skip>C&amp;D </Name></Container></Containers></Arbitrary>",
         NULL, true, NULL, " ABC&D "},
        {"<r><Containers><Container><Name><![CDATA[]]><![CDATA[a]]><![CDATA[b]]>c</Name></Container></Containers></r>",
         NULL, true, NULL, "abc"},
        {"<r><Containers><Container><Name>old</Name><Name>last</Name></Container></Containers><Containers><Container/><Container><Name>lost</Name><Name/></Container></Containers></r>",
         NULL, true, NULL, "last, , "},
        {"<r xmlns:p='urn:a' xmlns:q='urn:b'><p:Containers><q:Container><p:Name>mixed</p:Name></q:Container><q:Container><p:name>ignored</p:name></q:Container><q:container><p:Name>ignored</p:Name></q:container></p:Containers><containers><Container><Name>ignored</Name></Container></containers></r>",
         NULL, true, NULL, "mixed, "},
        {"<r><ignored><Containers><Container><Name>hidden</Name></Container></Containers></ignored><Containers><ignored><Container><Name>hidden</Name></Container></ignored></Containers></r>",
         NULL, true, NULL, NULL},
        {"<Containers><Container><Name>hidden</Name></Container></Containers>", NULL, true, NULL, NULL},
        {"<r><Containers><Container/></Containers></r>", NULL, true, NULL, ""},
        {"<r><Containers><Container><Name>x</Name></Container></Containers></r>", sensitive, true, NULL, "x"},
        {"<r><Containers><Container><Name>x</Name></Container></Containers></r", sensitive, false, redacted, NULL},
        {"", NULL, false, "EOF", NULL},
        {"", sensitive, false, redacted, NULL},
        {"not XML", NULL, false, syntax_cause, NULL},
        /* Explicit bounded-parser gaps: Go Decode stops after its first root. */
        {"<r/><second/>", NULL, false, syntax_cause, NULL},
        {"<r/>junk<broken", NULL, false, syntax_cause, NULL},
        /* Check the original declaration, not forced UTF-8 doc->encoding. */
        {"<?xml version='1.0' encoding='ISO-8859-1'?><r/>", NULL, false, "unsupported: Azure Storage XML encoding", NULL},
        {"<?xml version='1.0' encoding='utf8'?><r/>", NULL, false, "unsupported: Azure Storage XML encoding", NULL},
        {"<?xml version='1.0' encoding='uTf-8'?><r/>", NULL, true, NULL, NULL},
        {"<?xml version='1.1'?><r/>", NULL, false, "unsupported: Azure Storage XML version", NULL},
        {"<!DOCTYPE r [<!ENTITY a 'synthetic'>]><r/>", NULL, false, "unsupported: Azure Storage XML DTD", NULL},
        {"<!DOCTYPE r SYSTEM 'https://must-not-resolve.invalid/never.dtd'><r/>", NULL, false, "unsupported: Azure Storage XML DTD", NULL},
        {"<r><p:Containers/></r>", NULL, false, syntax_cause, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_request request = {"acctone", "SharedKey acctone:Vw0njoMRxLpCu4MIZKRVq15jNL6yn+h/N8KBbgRipxE=", 0};
        expected_requests requests = {.items = &request, .count = 1};
        test_http http = {.response = {.status = 200,
            .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}, .body_error = cases[i].read_error},
            .inspect = inspect_request, .user = &requests};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expected_result expected = {.name = "acctone", .key = full64, .verified = cases[i].verified,
                                   .error = cases[i].error, .containers = cases[i].containers};
        scan_config(detector, &ctx, true, expected.name, full64, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static void test_status_and_errors(const br_detector *detector)
{
    char sensitive[128];
    snprintf(sensitive, sizeof(sensitive), "synthetic key %s rejected", full64);
    const struct { int status, send_rc; const char *send_error, *error; } cases[] = {
        {403, 0, NULL, NULL},
        {401, 0, NULL, "unexpected HTTP response status 401"},
        {201, 0, NULL, "unexpected HTTP response status 201"},
        {500, 0, NULL, "unexpected HTTP response status 500"},
        {200, 1, "lookup synthetic: no such host", NULL},
        {200, 1, "lookup synthetic: No such host", "lookup synthetic: No such host"},
        {200, 1, sensitive, "synthetic key [REDACTED] rejected"},
        {200, 1, "context canceled", "context canceled"},
        {200, 1, "context deadline exceeded", "context deadline exceeded"},
        {200, 1, NULL, "HTTP transport failed"},
        {200, 1, "unsupported: synthetic PUBLIC transport", "unsupported: synthetic PUBLIC transport"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_request request = {"acctone", "SharedKey acctone:Vw0njoMRxLpCu4MIZKRVq15jNL6yn+h/N8KBbgRipxE=", 0};
        expected_requests requests = {.items = &request, .count = 1};
        static const unsigned char body[] = "not XML";
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body) - 1}, .body_error = sensitive},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &requests};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expected_result expected = {.name = "acctone", .key = full64, .error = cases[i].error};
        scan_config(detector, &ctx, true, expected.name, full64, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1);
        expected.error = NULL;
        scan_config(detector, &ctx, false, expected.name, full64, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context(const br_detector *detector)
{
    expected_request request = {"acctone", "SharedKey acctone:Vw0njoMRxLpCu4MIZKRVq15jNL6yn+h/N8KBbgRipxE=", 0};
    expected_requests requests = {.items = &request, .count = 1, .timeout_limit = 3000};
    static const unsigned char body[] = "<r/>";
    test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}}, .inspect = inspect_request, .user = &requests};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + requests.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expected_result expected = {.name = "acctone", .key = full64, .verified = true};
    scan_config(detector, &ctx, true, expected.name, full64, &expected, 1);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    ctx.deadline_monotonic_ms = 1;
    http.calls = http.releases = 0;
    expected.verified = false;
    expected.error = "context deadline exceeded";
    scan_config(detector, &ctx, true, expected.name, full64, &expected, 1);
    CHECK(!http.calls && http.releases == 1);
    ctx.deadline_monotonic_ms = 0;
    ctx.cancelled = cancelled;
    http.calls = http.releases = 0;
    expected.error = "context canceled";
    scan_config(detector, &ctx, true, expected.name, full64, &expected, 1);
    CHECK(!http.calls && http.releases == 1);
}

int main(void)
{
    CHECK(strlen(full64) == 88 && strlen(full66) == 88 && strlen(emulator_key) == 88);
    memcpy(prefix3, "AQID-", 5);
    memset(prefix3 + 5, 'A', 83);
    prefix3[88] = '\0';
    empty_key[0] = '-';
    memset(empty_key + 1, 'A', 87);
    empty_key[88] = '\0';
    memset(all_a, 'A', 88);
    all_a[88] = '\0';
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_signing_goldens(detector);
    test_unique_product_and_break(detector);
    test_xml(detector);
    test_status_and_errors(detector);
    test_context(detector);
    return test_finish("AzureStorage");
}
