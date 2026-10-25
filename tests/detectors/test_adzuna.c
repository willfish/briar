/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *key, *id; } expected_pair;
typedef struct { const expected_pair *pairs; size_t len; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_adzuna_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 431 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Adzuna"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Adzuna is a job search engine used to find job listings. "
        "Adzuna API keys can be used to access job listing data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "adzuna"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_adzuna_init(&again, &error) == 0 && !error && again == detector);
    CHECK(br_adzuna_init(&again, NULL) == 0 && again == detector);
    CHECK(br_adzuna_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_adzuna_init(NULL, NULL) != 0);
    return detector;
}

static void check_pair(const br_result *result, const expected_pair *pair)
{
    CHECK(result->detector_type == 431 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 32 && !memcmp(result->raw.data, pair->key, 32));
    CHECK(result->raw_v2.data && result->raw_v2.len == 40 && !memcmp(result->raw_v2.data, pair->key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, pair->id, 8));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *key = NULL, *id = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &key));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &id));
    CHECK(json_object_is_type(key, json_type_string) && json_object_is_type(id, json_type_string));
    CHECK(json_object_get_string_len(key) == 32 && !strcmp(json_object_get_string(key), pair->key));
    CHECK(json_object_get_string_len(id) == 8 && !strcmp(json_object_get_string(id), pair->id));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                              const void *input, size_t len, const expected_pair *pair,
                              size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pair);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[33], id[9], input[2304];
    test_secret(key, 32, 0);
    test_secret(id, 8, 9);
    expected_pair pair = {key, id};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"adzuna '%s'\nadzuna '%s'", 1},
        {"ADZUNA %s\nADZUNA %s", 1},
        {"prefixadzunasuffix %s\nadzuna %s", 1},
        {"%s\n%s", 0},
        {"adzuna %s", 0},
        {"adzuna %s\nad zuna %s", 0},
        {"adzuna _%s\nadzuna %s", 0},
        {"adzuna %s_\nadzuna %s", 0},
        {"adzuna %sx\nadzuna %s", 0},
        {"adzuna %.31s\nadzuna %s", 0},
        {"adzuna Z%.31s\nadzuna %s", 0},
        {"adzuna %s\nadzuna _%s", 0},
        {"adzuna %s\nadzuna %s_", 0},
        {"adzuna %s\nadzuna %sx", 0},
        {"adzuna %s\nadzuna %.7s", 0},
        {"adzuna %s\nadzuna Z%.7s", 0},
        {"adzuna\r\n%s\nadzuna\r\n%s", 1},
        {"adzuna %s %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, id);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)len, &pair, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "adzuna %s", id);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    char invalid_key[33];
    memcpy(invalid_key, key, sizeof(invalid_key));
    invalid_key[16] = '-';
    snprintf(input, sizeof(input), "adzuna %s\nadzuna %s", invalid_key, id);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "adzuna", 6);
        memset(input + 6, '-', gap);
        snprintf(input + 6 + gap, sizeof(input) - 6 - gap, "%s\nadzuna %s", key, id);
        expect_extraction(detector, &ctx, input, strlen(input), &pair, gap == 40 ? 1 : 0);
        size_t at = (size_t)snprintf(input, sizeof(input), "adzuna %s\nadzuna", key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", id);
        expect_extraction(detector, &ctx, input, strlen(input), &pair, gap == 40 ? 1 : 0);
    }
    memcpy(input, "adzuna\0", 7);
    int len = snprintf(input + 7, sizeof(input) - 7, "%s\nadzuna %s", key, id);
    CHECK(len > 0);
    expect_extraction(detector, &ctx, input, 7 + (size_t)len, &pair, 1);

    /* The multipart span is engine metadata, not a detector-local pairing limit. */
    size_t at = (size_t)snprintf(input, sizeof(input), "adzuna %s\n", key);
    memset(input + at, '-', 2048);
    snprintf(input + at + 2048, sizeof(input) - at - 2048, "\nadzuna %s", id);
    expect_extraction(detector, &ctx, input, strlen(input), &pair, 1);

    memset(key, 'a', 32);
    memset(id, '0', 8);
    snprintf(input, sizeof(input), "adzuna %s\nadzuna %s", key, id);
    expect_extraction(detector, &ctx, input, strlen(input), &pair, 1);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    const expected_pair *pair = &expected->pairs[http->calls - 1];
    char url[160];
    snprintf(url, sizeof(url),
             "https://api.adzuna.com/v1/api/jobs/us/search/1?app_id=%s&app_key=%s",
             pair->id, pair->key);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 431);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ?
                  "TruffleHog adzuna-test" : "TruffleHog"));
}

static void test_pairing(const br_detector *detector)
{
    char first[33], second[33], first_id[9], second_id[9], input[256];
    test_secret(first, 32, 0);
    test_secret(second, 32, 11);
    test_secret(first_id, 8, 3);
    test_secret(second_id, 8, 19);
    snprintf(input, sizeof(input),
             "adzuna %s\nadzuna %s\nadzuna %s\nadzuna %s\nadzuna %s\nadzuna %s",
             second_id, first, second, first_id, first, second_id);
    /* Capture occurrences are ordered, not unique: three keys times three IDs. */
    const expected_pair pairs[] = {
        {first, second_id}, {first, first_id}, {first, second_id},
        {second, second_id}, {second, first_id}, {second, second_id},
        {first, second_id}, {first, first_id}, {first, second_id},
    };
    expected_requests expected = {pairs, sizeof(pairs) / sizeof(pairs[0])};
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {
            .response = {.status = 200}, .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == expected.len);
        CHECK(http.calls == (verify ? expected.len : 0) && http.releases == http.calls);
        for (size_t i = 0; i < results.len; ++i) {
            check_pair(&results.items[i], &pairs[i]);
            CHECK(results.items[i].verified == (bool)verify && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_verification(const br_detector *detector)
{
    char key[33], id[9], input[128], sensitive_error[128], redacted[96];
    test_secret(key, 32, 0);
    test_secret(id, 8, 9);
    snprintf(input, sizeof(input), "adzuna %s\nadzuna %s", key, id);
    snprintf(sensitive_error, sizeof(sensitive_error), "id=%s key=%s again=%s", id, key, key);
    snprintf(redacted, sizeof(redacted), "id=%s key=[REDACTED] again=[REDACTED]", id);
    const expected_pair pair = {key, id};
    expected_requests expected = {&pair, 1};
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected HTTP response status 201"},
        {403, 0, NULL, false, "unexpected HTTP response status 403"},
        {429, 0, NULL, false, "unexpected HTTP response status 429"},
        {500, 0, NULL, false, "unexpected HTTP response status 500"},
        {200, 1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, 1, "context canceled", false, "context canceled"},
        {200, 1, sensitive_error, false, redacted},
        {200, 1, NULL, false, "HTTP transport failed"},
    };
    /* Neither malformed JSON nor a body read error participates in verification. */
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status,
                         .body = {body, sizeof(body)}, .body_error = sensitive_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "adzuna-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        check_pair(result, &pair);
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error);
            CHECK(!strcmp(result->verification_error, cases[i].error));
            CHECK(!strstr(result->verification_error, key));
        } else {
            CHECK(!result->verification_error);
        }
        br_results_clear(&results);
    }

    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "adzuna %s", key);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_pairing(detector);
    test_verification(detector);
    return test_finish("Adzuna");
}
