/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *key, *id; } expected_pair;
typedef struct {
    const expected_pair *pairs;
    size_t len;
    bool seen[4];
} expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_airbrakeprojectkey_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 125 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AirbrakeProjectKey"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Airbrake is an error and performance monitoring service for web applications. "
        "Airbrake project keys can be used to report and track errors in applications."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "airbrake"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_airbrakeprojectkey_init(&again, &error) == 0 && !error && again == detector);
    CHECK(br_airbrakeprojectkey_init(&again, NULL) == 0 && again == detector);
    CHECK(br_airbrakeprojectkey_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_airbrakeprojectkey_init(NULL, NULL) != 0);
    return detector;
}

static void check_pair(const br_result *result, const expected_pair *pair)
{
    CHECK(result->detector_type == 125 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == 32 && !memcmp(result->raw.data, pair->key, 32));
    CHECK(result->raw_v2.data && result->raw_v2.len == 38);
    CHECK(!memcmp(result->raw_v2.data, pair->key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, pair->id, 6));
    CHECK(!result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *key = NULL, *id = NULL, *guide = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &key));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &id));
    CHECK(json_object_is_type(key, json_type_string) && json_object_is_type(id, json_type_string));
    CHECK(json_object_get_string_len(key) == 32 && !strcmp(json_object_get_string(key), pair->key));
    CHECK(json_object_get_string_len(id) == 6 && !strcmp(json_object_get_string(id), pair->id));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &guide));
    CHECK(json_object_is_type(guide, json_type_string));
    CHECK(!strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/airbrake/"));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void check_pairs(const br_results *results, const expected_pair *pairs,
                        size_t count, bool verified)
{
    bool seen[4] = {0};
    CHECK(count <= sizeof(seen) / sizeof(seen[0]) && results->len == count);
    /* Upstream iterates maps: assert the complete set, not a fixed map order. */
    for (size_t i = 0; i < results->len; ++i) {
        const br_result *result = &results->items[i];
        CHECK(result->raw_v2.data && result->raw_v2.len == 38);
        size_t j = 0;
        for (; j < count; ++j) {
            if (!memcmp(result->raw_v2.data, pairs[j].key, 32) &&
                !memcmp(result->raw_v2.data + 32, pairs[j].id, 6)) break;
        }
        CHECK(j < count && !seen[j]);
        seen[j] = true;
        check_pair(result, &pairs[j]);
        CHECK(result->verified == verified && !result->verification_error);
    }
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                              const void *input, size_t len,
                              const expected_pair *pairs, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    check_pairs(&results, pairs, count, false);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[33], changed[33], input[2304];
    test_secret(key, 32, 0);
    key[0] = 'B';
    key[10] = '-';
    const char *id = "004207";
    const expected_pair pair = {key, id};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"airbrake '%s'\nairbrake '%s'", 1},
        {"AIRBRAKE %s\nAIRBRAKE %s", 1},
        {"prefixairbrakesuffix %s\nairbrake %s", 1},
        {"%s\n%s", 0},
        {"airbrake %s", 0},
        {"airbrake%s\nairbrake %s", 0},
        {"airbrake _%s\nairbrake %s", 0},
        {"airbrake %s_\nairbrake %s", 0},
        {"airbrake %sx\nairbrake %s", 0},
        {"airbrake %.31s\nairbrake %s", 0},
        {"airbrake %s\nairbrake _%s", 0},
        {"airbrake %s\nairbrake %s_", 0},
        {"airbrake %s\nairbrake %s0", 0},
        {"airbrake %s\nairbrake %.5s", 0},
        {"airbrake %s\nairbrake x%.5s", 0},
        {"airbrake\r\n%s\nairbrake\r\n%s", 1},
        {"airbrake %s %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, id);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)len, &pair, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "airbrake %s", id);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[16] = '$';
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s", changed, id);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "airbrake", 8);
        memset(input + 8, '-', gap);
        snprintf(input + 8 + gap, sizeof(input) - 8 - gap, "%s\nairbrake %s", key, id);
        expect_extraction(detector, &ctx, input, strlen(input), &pair, gap == 40 ? 1 : 0);
        size_t at = (size_t)snprintf(input, sizeof(input), "airbrake %s\nairbrake", key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", id);
        expect_extraction(detector, &ctx, input, strlen(input), &pair, gap == 40 ? 1 : 0);
    }
    memcpy(input, "airbrake\0", 9);
    int len = snprintf(input + 9, sizeof(input) - 9, "%s\nairbrake %s", key, id);
    CHECK(len > 0);
    expect_extraction(detector, &ctx, input, 9 + (size_t)len, &pair, 1);

    /* Hyphen is in the key alphabet, but word boundaries still apply. */
    memcpy(changed, key, sizeof(changed));
    changed[0] = '-';
    expected_pair hyphen = {changed, id};
    snprintf(input, sizeof(input), "airbrake%s\nairbrake %s", changed, id);
    expect_extraction(detector, &ctx, input, strlen(input), &hyphen, 1);
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s", changed, id);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[31] = '-';
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s", changed, id);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "airbrake %sQ\nairbrake %s", changed, id);
    expect_extraction(detector, &ctx, input, strlen(input), &hyphen, 1);

    memcpy(changed, key, sizeof(changed));
    memcpy(changed + 2, "-123456-", 8);
    const expected_pair embedded_id[] = {{changed, "123456"}, {changed, id}};
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s", changed, id);
    expect_extraction(detector, &ctx, input, strlen(input), embedded_id, 2);

    size_t at = (size_t)snprintf(input, sizeof(input), "airbrake %s\n", key);
    memset(input + at, '.', 2048);
    snprintf(input + at + 2048, sizeof(input) - at - 2048, "\nairbrake %s", id);
    expect_extraction(detector, &ctx, input, strlen(input), &pair, 1);

    memset(key, 'a', 32);
    const expected_pair low_entropy = {key, "000000"};
    snprintf(input, sizeof(input), "airbrake %s\nairbrake 000000", key);
    expect_extraction(detector, &ctx, input, strlen(input), &low_entropy, 1);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(expected->len <= sizeof(expected->seen) / sizeof(expected->seen[0]));
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    size_t i = 0;
    for (; i < expected->len; ++i) {
        char url[160];
        snprintf(url, sizeof(url),
                 "https://api.airbrake.io/api/v4/projects/%s/deploys?key=%s",
                 expected->pairs[i].id, expected->pairs[i].key);
        if (!strcmp(request->url, url)) break;
    }
    CHECK(i < expected->len && !expected->seen[i]);
    expected->seen[i] = true;
    static const char payload[] =
        "{\"environment\":\"production\",\"username\":\"john\",\"email\":\"john@smith.com\","
        "\"repository\":\"https://github.com/airbrake/airbrake\","
        "\"revision\":\"38748467ea579e7ae64f7815452307c9d05e05c5\",\"version\":\"v2.0\"}";
    CHECK(request->body.data && request->body.len == sizeof(payload) - 1);
    CHECK(!memcmp(request->body.data, payload, sizeof(payload) - 1));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 125);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    /* No Content-Type, authorization header, or other detector-added header. */
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ?
                  "TruffleHog airbrake-project-test" : "TruffleHog"));
}

static void test_unique_pairing(const br_detector *detector)
{
    char first[33], second[33], input[320];
    test_secret(first, 32, 0);
    test_secret(second, 32, 11);
    /* Repeated components are independently deduplicated, not merely zipped. */
    snprintf(input, sizeof(input),
             "airbrake 008209\nairbrake %s\nairbrake %s\nairbrake 004207\n"
             "airbrake %s\nairbrake 008209\nairbrake %s\nairbrake 004207",
             first, second, first, second);
    const expected_pair pairs[] = {
        {first, "008209"}, {first, "004207"},
        {second, "008209"}, {second, "004207"},
    };
    for (int verify = 0; verify <= 1; ++verify) {
        expected_requests expected = {.pairs = pairs, .len = 4};
        test_http http = {
            .response = {.status = 200}, .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        check_pairs(&results, pairs, 4, verify);
        CHECK(http.calls == (verify ? 4u : 0u) && http.releases == http.calls);
        br_results_clear(&results);
    }
}

static void test_verification(const br_detector *detector)
{
    char key[33], input[128], sensitive_error[160];
    test_secret(key, 32, 0);
    const expected_pair pair = {key, "004207"};
    snprintf(input, sizeof(input), "airbrake %s\nairbrake %s", key, pair.id);
    snprintf(sensitive_error, sizeof(sensitive_error),
             "POST deploys?key=%s project=%s again=%s failed", key, pair.id, key);
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {204, 0, NULL, false, "unexpected status code: 204"},
        {404, 0, NULL, false, "unexpected status code: 404"},
        {429, 0, NULL, false, "unexpected status code: 429"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, 1, "context canceled", false, "context canceled"},
        {200, 1, sensitive_error, false, sensitive_error},
        {200, 1, NULL, false, "HTTP transport failed"},
    };
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.pairs = &pair, .len = 1};
        test_http http = {
            .response = {.status = cases[i].status,
                         .body = {body, sizeof(body)}, .body_error = sensitive_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "airbrake-project-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        check_pair(result, &pair);
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error);
            /* Source supplies no secrets to the error setter; compare, never log. */
            CHECK(!strcmp(result->verification_error, cases[i].error));
        } else {
            CHECK(!result->verification_error);
        }
        br_results_clear(&results);
    }

    /* A missing transport must fail closed: this verifier has remote side effects. */
    br_scan_ctx closed = {0};
    br_results results = test_scan(detector, &closed, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_pair(&results.items[0], &pair);
    CHECK(results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);

    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "airbrake %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_unique_pairing(detector);
    test_verification(detector);
    return test_finish("AirbrakeProjectKey");
}
