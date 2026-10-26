/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define ENDPOINT "https://abcde.search.windows.net/indexes/index1"
#define BYTES(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static char key[53], other_key[53];
static const char unsupported[] = "unsupported: Azure Search query URL outside canonical ASCII subset";
static bool fail_503_dup;

/* One known positive core allocation failure must NOT become a creation skip. */
char *strdup(const char *value)
{
    if (fail_503_dup && !strcmp(value, "unexpected HTTP response status 503")) {
        fail_503_dup = false;
        return NULL;
    }
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azuresearchquerykey_init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(!br_azuresearchquerykey_init(&detector, &error) && detector && !error);
    CHECK(!br_azuresearchquerykey_init(&again, NULL) && again == detector);
    CHECK(detector->type == 977 && detector->version == 0 && !strcmp(detector->name, "AzureSearchQueryKey"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Azure Search Query Keys are used to authenticate search requests to Azure Search service. They should be kept confidential to prevent unauthorized access to search indexes and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "azure"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_part(br_json *parts, const char *name, br_slice bytes)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(parts, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == bytes.len);
    CHECK(!memcmp(json_object_get_string(value), bytes.data, bytes.len));
}

static void check_result(const br_result *result, const char *secret, br_slice endpoint, bool verified, const char *error)
{
    CHECK(result->detector_type == 977 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 52 && !memcmp(result->raw.data, secret, 52));
    CHECK(result->raw_v2.data && result->raw_v2.len == 52 + endpoint.len);
    CHECK(!memcmp(result->raw_v2.data, secret, 52));
    CHECK(!memcmp(result->raw_v2.data + 52, endpoint.data, endpoint.len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_part(result->secret_parts, "key", (br_slice){(const unsigned char *)secret, 52});
    check_part(result->secret_parts, "url", endpoint);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static br_bytes make_input(const char *secret, br_slice record)
{
    size_t n = strlen(secret);
    br_bytes input = {malloc(7 + n + record.len), 7 + n + record.len}; CHECK(input.data);
    memcpy(input.data, "azure ", 6); memcpy(input.data + 6, secret, n); input.data[6 + n] = '\n';
    memcpy(input.data + 7 + n, record.data, record.len);
    return input;
}

static br_results scan_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            const char *secret, br_slice record)
{
    br_bytes input = make_input(secret, record);
    br_results results = test_scan(detector, ctx, verify, input.data, input.len);
    free(input.data);
    return results;
}

static void extraction_case(const br_detector *detector, const char *secret, br_slice record,
                              br_slice endpoint, bool found)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = scan_one(detector, &ctx, false, secret, record);
    CHECK(results.len == (found ? 1 : 0) && !http.calls && !http.releases);
    if (found) check_result(&results.items[0], secret, endpoint, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    extraction_case(detector, key, BYTES("AZURE " ENDPOINT), BYTES(ENDPOINT), true);
    extraction_case(detector, key, BYTES(ENDPOINT), (br_slice){0}, false); /* URL also needs its prefix. */
    char changed[56], record[192];
    memset(changed, 'A', 52); changed[52] = '\0';
    extraction_case(detector, changed, BYTES("azure " ENDPOINT), BYTES(ENDPOINT), true); /* No entropy rule. */
    memcpy(changed, key, 53); changed[51] = '\0';
    extraction_case(detector, changed, BYTES("azure " ENDPOINT), (br_slice){0}, false);
    memcpy(changed, key, 52); changed[52] = 'x'; changed[53] = '\0';
    extraction_case(detector, changed, BYTES("azure " ENDPOINT), (br_slice){0}, false);
    memcpy(changed + 52, "==", 3);
    extraction_case(detector, changed, BYTES("azure " ENDPOINT), BYTES(ENDPOINT), true); /* Padding is outside capture. */
    changed[52] = '_'; changed[53] = '\0';
    extraction_case(detector, changed, BYTES("azure " ENDPOINT), (br_slice){0}, false);
    changed[52] = '-';
    extraction_case(detector, changed, BYTES("azure " ENDPOINT), BYTES(ENDPOINT), true);
    const char *invalid[] = {
        "https://Abcde.search.windows.net/indexes/index1", "https://ab-cd.search.windows.net/indexes/index1",
        "https://abcd.search.windows.net/indexes/index1", "https://abcde.Search.windows.net/indexes/index1",
        "HTTPS://abcde.search.windows.net/indexes/index1", "https://abcde.search.windows.net/indexes/Index1",
        "https://abcde.search.windows.net/indexes/abcd", "https://abcde.search.windows.net/indexes/in-dex",
        "https://abcde.search.windows.net/indexes/index1_more",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        snprintf(record, sizeof(record), "azure %s", invalid[i]);
        extraction_case(detector, key, text(record), (br_slice){0}, false);
    }
    extraction_case(detector, key, BYTES("azure " ENDPOINT "-tail"), BYTES(ENDPOINT), true); /* Source's own final word boundary. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(record, "azure", 5); memset(record + 5, ' ', gap);
        memcpy(record + 5 + gap, ENDPOINT, sizeof(ENDPOINT));
        extraction_case(detector, key, text(record), BYTES(ENDPOINT), gap == 40);
    }
    char longest[128], name[42];
    memset(name, 'a', 40); name[40] = '\0';
    snprintf(longest, sizeof(longest), "https://%s.search.windows.net/indexes/%s", name, name);
    snprintf(record, sizeof(record), "azure %s", longest);
    extraction_case(detector, key, text(record), text(longest), true);
    name[40] = 'a'; name[41] = '\0';
    snprintf(record, sizeof(record), "azure https://%s.search.windows.net/indexes/index1", name);
    extraction_case(detector, key, text(record), (br_slice){0}, false);
}

typedef struct { const char *key; br_slice endpoint; } expected_request;
typedef struct { const expected_request *items; size_t len; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    const expected_request *item = &expected->items[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000 && request->detector_type == 977);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "api-key"));
    CHECK(!strcmp(request->headers[0].value, item->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog search-query-test"));
    const char suffix[] = "/docs/$count?api-version=2023-10-01-Preview";
    CHECK(strlen(request->url) == item->endpoint.len + sizeof(suffix) - 1);
    CHECK(!memcmp(request->url, item->endpoint.data, item->endpoint.len));
    CHECK(!strcmp(request->url + item->endpoint.len, suffix));
}

static void occurrences(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "azure %s\nazure %s\nazure %s\nazure " ENDPOINT "\nAZURE https://other1.search.windows.net/indexes/index2\nazure " ENDPOINT,
             key, other_key, key);
    const br_slice urls[] = {BYTES(ENDPOINT), BYTES("https://other1.search.windows.net/indexes/index2"), BYTES(ENDPOINT)};
    const char *keys[] = {key, other_key, key};
    expected_request items[9];
    for (size_t k = 0; k < 3; ++k) for (size_t u = 0; u < 3; ++u) items[k * 3 + u] = (expected_request){keys[k], urls[u]};
    expected_requests expected = {items, 9};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "search-query-test"};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 9 && http.calls == (verify ? 9 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) check_result(&results.items[i], items[i].key, items[i].endpoint, verify, NULL);
        br_results_clear(&results);
    }
}

typedef enum { SUPPORTED, SKIP_CREATION, UNSUPPORTED } url_policy;

static void byte_policy(const br_detector *detector)
{
    const struct { br_slice record, transformed; url_policy policy; } cases[] = {
        {BYTES("azure " ENDPOINT), BYTES(ENDPOINT), SUPPORTED},
        {BYTES("azure x " ENDPOINT), BYTES(ENDPOINT), SUPPORTED},
        {BYTES("azure\0 " ENDPOINT), BYTES(ENDPOINT), SUPPORTED}, /* Discarded NUL is harmless. */
        {BYTES("azure:" ENDPOINT), BYTES("azure:" ENDPOINT), UNSUPPORTED},
        {BYTES("azure\0" ENDPOINT), BYTES("azure\0" ENDPOINT), SKIP_CREATION},
        {BYTES("azure\t" ENDPOINT), BYTES("azure\t" ENDPOINT), SKIP_CREATION},
        {BYTES("azure foo\t" ENDPOINT), BYTES("foo\t" ENDPOINT), SKIP_CREATION},
        {BYTES("azure\177" ENDPOINT), BYTES("azure\177" ENDPOINT), SKIP_CREATION},
        {BYTES("azure\0#" ENDPOINT), BYTES("azure\0#" ENDPOINT), SKIP_CREATION},
        {BYTES("azure#\0" ENDPOINT), BYTES("azure#\0" ENDPOINT), UNSUPPORTED}, /* Fragment-only control is NOT a known creation error. */
        {BYTES("azure%20" ENDPOINT), BYTES("azure%20" ENDPOINT), UNSUPPORTED},
        {BYTES("azureπ" ENDPOINT), BYTES("azureπ" ENDPOINT), UNSUPPORTED},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        extraction_case(detector, key, cases[i].record, cases[i].transformed, true);
        expected_request item = {key, cases[i].transformed}; expected_requests expected = {&item, 1};
        test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "search-query-test"};
        br_results results = scan_one(detector, &ctx, true, key, cases[i].record);
        bool skipped = cases[i].policy == SKIP_CREATION, sent = cases[i].policy == SUPPORTED;
        CHECK(results.len == (skipped ? 0 : 1) && http.calls == (sent ? 1 : 0) && http.releases == http.calls);
        if (!skipped) check_result(&results.items[0], key, cases[i].transformed, sent, sent ? NULL : unsupported);
        br_results_clear(&results);
    }
    static const unsigned char records[] = "azure\0" ENDPOINT "\nazure#\0" ENDPOINT "\nazure " ENDPOINT "\nazure " ENDPOINT;
    expected_request items[] = {{key, BYTES(ENDPOINT)}, {key, BYTES(ENDPOINT)}};
    expected_requests expected = {items, 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "search-query-test"};
    br_results results = scan_one(detector, &ctx, true, key, (br_slice){records, sizeof(records) - 1});
    CHECK(results.len == 3 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key, BYTES("azure#\0" ENDPOINT), false, unsupported);
    for (size_t i = 1; i < 3; ++i) check_result(&results.items[i], key, BYTES(ENDPOINT), true, NULL);
    br_results_clear(&results); /* Candidate guards and creation skips never stop later pairs. */
    results = scan_one(detector, NULL, true, key, BYTES("azure " ENDPOINT));
    CHECK(results.len == 0 && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    expected_request item = {key, BYTES(ENDPOINT)}; expected_requests expected = {&item, 1};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "search-query-test"};
    br_results results = scan_one(detector, &ctx, true, key, BYTES("azure " ENDPOINT));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_result(&results.items[0], key, BYTES(ENDPOINT), verified, error);
    br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }

static void verification(const br_detector *detector)
{
    const int statuses[] = {200, 201, 204, 299, 401, 403, 302, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80]; snprintf(error, sizeof(error), "unexpected HTTP response status %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = BYTES("not JSON\0lastUpdateTime"), .body_error = "ignored read error"}};
        verify_case(detector, &http, statuses[i] >= 200 && statuses[i] < 300, i < 6 ? NULL : error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = "unsupported: PUBLIC redirect/address policy"};
    verify_case(detector, &http, false, http.send_error); /* One PUBLIC call, NO SANE fallback. */
    http.send_error = "lookup: no such host";
    verify_case(detector, &http, false, http.send_error);
    verify_case(detector, &http, false, http.send_error); /* No DNS cache/suppression. */
    http.send_error = NULL;
    verify_case(detector, &http, false, "HTTP transport failed");
    char cause[256], redacted[192];
    snprintf(cause, sizeof(cause), "url=" ENDPOINT " key=%s again=%s", key, key);
    snprintf(redacted, sizeof(redacted), "url=" ENDPOINT " key=[REDACTED] again=[REDACTED]");
    http.send_error = cause;
    verify_case(detector, &http, false, redacted);
    br_scan_ctx missing = {0};
    br_results results = scan_one(detector, &missing, true, key, BYTES("azure " ENDPOINT));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, BYTES(ENDPOINT), false, "HTTP transport not installed");
    br_results_clear(&results);
    http = (test_http){.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled};
    results = scan_one(detector, &ctx, true, key, BYTES("azure " ENDPOINT));
    CHECK(results.len == 1 && !http.calls && http.releases == 1);
    check_result(&results.items[0], key, BYTES(ENDPOINT), false, "context canceled");
    br_results_clear(&results);
}

static void setter_resource_failure(const br_detector *detector)
{
    expected_request item = {key, BYTES(ENDPOINT)}; expected_requests expected = {&item, 1};
    test_http http = {.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "search-query-test"};
    br_bytes input = make_input(key, BYTES("azure " ENDPOINT));
    br_result prior = {0}; br_results results = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data;
    fail_503_dup = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){input.data, input.len}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory recording Azure Search query verification error"));
    CHECK(!fail_503_dup && results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    CHECK(http.calls == 1 && http.releases == 1);
    free(error); free(input.data); br_results_clear(&results);
    http = (test_http){.response = {.status = 503}};
    verify_case(detector, &http, false, "unexpected HTTP response status 503");
}

int main(void)
{
    test_secret(key, 52, 0); key[0] = 'A'; key[15] = 'Z';
    test_secret(other_key, 52, 13); other_key[0] = 'Q'; other_key[31] = 'B';
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences(detector);
    byte_policy(detector);
    verification(detector);
    setter_resource_failure(detector);
    return test_finish("AzureSearchQueryKey");
}
