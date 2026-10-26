/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *key, *service; } expected_pair;
typedef struct { const expected_pair *pairs; size_t len; bool reject_first; } expected_requests;
static char lower_key[53], upper_key[53], mixed_key[53];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azuresearchadminkey_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_azuresearchadminkey_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 976 && detector->version == 0 && !strcmp(detector->name, "AzureSearchAdminKey"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Azure Search is a search-as-a-service solution that allows developers to incorporate search capabilities "
        "into their applications. Azure Search Admin Keys can be used to manage and query search services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "azure"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_azuresearchadminkey_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void check_pair(const br_result *result, const expected_pair *pair)
{
    size_t service_len = strlen(pair->service);
    CHECK(result->detector_type == 976 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 52 && !memcmp(result->raw.data, pair->key, 52));
    CHECK(result->raw_v2.data && result->raw_v2.len == 52 + service_len);
    CHECK(!memcmp(result->raw_v2.data, pair->key, 52));
    CHECK(!memcmp(result->raw_v2.data + 52, pair->service, service_len));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *key = NULL, *service = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &key));
    CHECK(json_object_object_get_ex(result->secret_parts, "service", &service));
    CHECK(json_object_is_type(key, json_type_string) && !strcmp(json_object_get_string(key), pair->key));
    CHECK(json_object_is_type(service, json_type_string) && !strcmp(json_object_get_string(service), pair->service));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    const expected_pair *pair = &expected->pairs[http->calls - 1];
    char url[160];
    snprintf(url, sizeof(url), "https://%s.search.windows.net/servicestats?api-version=2023-10-01-Preview", pair->service);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 976);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "api-key"));
    CHECK(!strcmp(request->headers[0].value, pair->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog search-admin-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1);
    if (expected->reject_first) http->response.status = http->calls == 1 ? 403 : 201;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const expected_pair *pair, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && http.calls == 0 && http.releases == 0);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pair);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    expected_pair pair = {lower_key, "CaseSrv7"};
    const struct { const char *format; size_t count; } cases[] = {
        {"azure '%s'\nazure '%s'", 1},
        {"AZURE %s\nAzUrE %s", 1},
        {"prefixazuresuffix %s\nazure %s", 1},
        {"azure\r\n%s\nazure\r\n%s", 1},
        {"%s\n%s", 0},
        {"azure _%s\nazure %s", 0},
        {"azure %s_\nazure %s", 0},
        {"azure %sx\nazure %s", 0},
        {"azure %.51s\nazure %s", 0},
        {"azure %s\nazure _%s", 0},
        {"azure %s\nazure %s_", 0},
        {"azure %s\nazure '-%s-'", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, pair.key, pair.service);
        expect_extraction(detector, input, strlen(input), &pair, cases[i].count);
    }
    const char *case_keys[] = {upper_key, mixed_key};
    for (size_t i = 0; i < sizeof(case_keys) / sizeof(case_keys[0]); ++i) {
        pair.key = case_keys[i];
        snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.service);
        expect_extraction(detector, input, strlen(input), &pair, 1);
    }
    pair.key = lower_key;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "azure", 5); memset(input + 5, '-', gap);
        snprintf(input + 5 + gap, sizeof(input) - 5 - gap, "%s\nazure %s", pair.key, pair.service);
        expect_extraction(detector, input, strlen(input), &pair, gap == 40 ? 1 : 0);
        size_t at = (size_t)snprintf(input, sizeof(input), "azure %s\nazure", pair.key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", pair.service);
        expect_extraction(detector, input, strlen(input), &pair, gap == 40 ? 1 : 0);
    }
    char service40[41], service41[42]; memset(service40, 'B', 40); service40[40] = 0;
    memset(service41, 'C', 41); service41[41] = 0;
    const struct { const char *service; size_t count; } services[] = {
        {"Abcd123", 1}, {service40, 1}, {"Abcd12", 0}, {service41, 0}, {"Abc-Def", 0}, {"Abc_Def", 0},
    };
    for (size_t i = 0; i < sizeof(services) / sizeof(services[0]); ++i) {
        pair.service = services[i].service;
        snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.service);
        expect_extraction(detector, input, strlen(input), &pair, services[i].count);
    }
    char broken[53]; memcpy(broken, lower_key, sizeof(broken)); broken[26] = '-';
    snprintf(input, sizeof(input), "azure %s\nazure CaseSrv7", broken);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    expect_extraction(detector, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "azure %s", lower_key);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    expect_extraction(detector, "azure CaseSrv7", sizeof("azure CaseSrv7") - 1, NULL, 0);
}

static void occurrences(const br_detector *detector)
{
    char input[320];
    snprintf(input, sizeof(input), "azure OtherSrv8\nazure %s\nazure %s\nazure CaseSrv7\nazure %s\nazure OtherSrv8",
             lower_key, upper_key, lower_key);
    const expected_pair pairs[] = {
        {lower_key, "OtherSrv8"}, {lower_key, "CaseSrv7"}, {lower_key, "OtherSrv8"},
        {upper_key, "OtherSrv8"}, {upper_key, "CaseSrv7"}, {upper_key, "OtherSrv8"},
        {lower_key, "OtherSrv8"}, {lower_key, "CaseSrv7"}, {lower_key, "OtherSrv8"},
    };
    expected_requests expected = {pairs, sizeof(pairs) / sizeof(pairs[0]), true};
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {.response = {.status = 201}, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == expected.len);
        CHECK(http.calls == (verify ? expected.len : 0) && http.releases == http.calls);
        for (size_t i = 0; i < results.len; ++i) {
            check_pair(&results.items[i], &pairs[i]);
            /* Rejecting the first pair must not cache/consume its service;
             * succeeding later must not break either loop. Duplicates retry. */
            CHECK(results.items[i].verified == ((bool)verify && i != 0) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void verification_statuses(const br_detector *detector)
{
    const struct { int status; bool verified, error; } cases[] = {
        {200, true, false}, {201, true, false}, {204, true, false}, {299, true, false},
        {401, false, false}, {403, false, false},
        {199, false, true}, {300, false, true}, {500, false, true},
    };
    expected_pair pair = {mixed_key, "OriginalCase7"}; expected_requests expected = {&pair, 1, false};
    char input[128], error[80];
    snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.service);
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)},
                                      .body_error = "ignored synthetic body-read error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "search-admin-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0]; check_pair(result, &pair);
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            snprintf(error, sizeof(error), "unexpected HTTP response status %d", cases[i].status);
            CHECK(result->verification_error && !strcmp(result->verification_error, error));
        } else CHECK(!result->verification_error);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { return *(bool *)user; }

static void creation_transport_and_context(const br_detector *detector)
{
    expected_pair pair = {upper_key, "CaseSrv7"}; expected_requests expected = {&pair, 1, false};
    char input[128], sensitive[256], redacted[160];
    snprintf(input, sizeof(input), "azure %s\nazure %s", pair.key, pair.service);
    snprintf(sensitive, sizeof(sensitive), "service=%s key=%s again=%s", pair.service, pair.key, pair.key);
    snprintf(redacted, sizeof(redacted), "service=%s key=[REDACTED] again=[REDACTED]", pair.service);
    const struct { int rc; const char *cause, *expected; } failures[] = {
        {1, sensitive, redacted}, {-1, "context deadline exceeded", "context deadline exceeded"},
        {1, NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        test_http http = {.response = {.status = 200, .body_error = "ignored partial response"},
                          .send_rc = failures[i].rc, .send_error = failures[i].cause,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_pair(&results.items[0], &pair);
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, failures[i].expected));
        CHECK(!strstr(results.items[0].verification_error, pair.key));
        if (i == 0) CHECK(strstr(results.items[0].verification_error, pair.service));
        br_results_clear(&results);
    }
    /* Nil context is request-creation failure: skip, not a transport error. */
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    check_pair(&results.items[0], &pair); br_results_clear(&results);
    bool stop = true;
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .cancel_user = &stop, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        check_pair(&results.items[0], &pair);
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(lower_key, 52, 0);
    for (size_t i = 0; i < sizeof(upper_key); ++i) {
        char upper = lower_key[i] >= 'a' && lower_key[i] <= 'z' ? lower_key[i] - 'a' + 'A' : lower_key[i];
        upper_key[i] = upper; mixed_key[i] = i % 4 ? lower_key[i] : upper;
    }
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification_statuses(detector); creation_transport_and_context(detector);
    return test_finish("AzureSearchAdminKey");
}
