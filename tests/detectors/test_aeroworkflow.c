/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char key[] = "BcDfGhJkLmNpQrStVwXy";
static const char other_key[] = "YxWvTsRqPnMlKjHgFdCb";
static const char account[] = "00042";
typedef struct { const char *key, *id; } expected_pair;

static void check_pair(const br_result *result, expected_pair pair)
{
    size_t key_len = strlen(pair.key), id_len = strlen(pair.id);
    CHECK(result->detector_type == 693 && !result->detector_name);
    CHECK(result->raw.len == key_len && !memcmp(result->raw.data, pair.key, key_len));
    CHECK(result->raw_v2.len == key_len + id_len);
    CHECK(!memcmp(result->raw_v2.data, pair.key, key_len));
    CHECK(!memcmp(result->raw_v2.data + key_len, pair.id, id_len));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.id));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aeroworkflow_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_aeroworkflow_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 693 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Aeroworkflow") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Aeroworkflow is a service for managing workflows. Aeroworkflow API keys and Account IDs can be used to access and manage workflows."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "aeroworkflow"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const expected_pair *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed[21];
    expected_pair one[] = {{key, account}};
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", key, account);
    expect_extraction(detector, input, strlen(input), one, 1);
    expect_extraction(detector, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "%s\n%s", key, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "aeroworkflow %s", key);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "aeroworkflow %s", account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "aeroworkflow %s %s", key, account);
    expect_extraction(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", account, key);
    expect_extraction(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "preAEROWORKFLOWsuffix=%s\naeroworkflow %s", key, account);
    expect_extraction(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "AEROWORKFLOW\r\n%s\naeroworkflow\r\n%s", key, account);
    expect_extraction(detector, input, strlen(input), one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "aeroworkflow");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\naeroworkflow %s", key, account);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        at = (size_t)snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow", key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", account);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    const struct { const char *before, *after; bool matches; } key_edges[] = {
        {"_", "", false}, {"", "_", true}, {"", "longer", true},
    };
    for (size_t i = 0; i < sizeof(key_edges) / sizeof(key_edges[0]); ++i) {
        snprintf(input, sizeof(input), "aeroworkflow %s%s%s\naeroworkflow %s",
                 key_edges[i].before, key, key_edges[i].after, account);
        expect_extraction(detector, input, strlen(input), one, key_edges[i].matches ? 1 : 0);
    }
    snprintf(input, sizeof(input), "aeroworkflow %.19s\naeroworkflow %s", key, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[10] = '$';
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", changed, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);

    memcpy(changed + 3, "^!?#:*;", 7);
    changed[10] = '7';
    changed[19] = ';';
    expected_pair symbols[] = {{changed, account}};
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", changed, account);
    expect_extraction(detector, input, strlen(input), symbols, 1);
    changed[0] = '^';
    snprintf(input, sizeof(input), "aeroworkflow%s\naeroworkflow %s", changed, account);
    expect_extraction(detector, input, strlen(input), symbols, 1);
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", changed, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);

    const char *invalid_ids[] = {"a00042", "00042b", "_00042", "00042_"};
    for (size_t i = 0; i < sizeof(invalid_ids) / sizeof(invalid_ids[0]); ++i) {
        snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", key, invalid_ids[i]);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow -%s", key, account);
    expect_extraction(detector, input, strlen(input), one, 1);
    expected_pair single_digit[] = {{key, "0"}};
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow 0", key);
    expect_extraction(detector, input, strlen(input), single_digit, 1);

    memset(changed, 'a', 20);
    changed[20] = '\0';
    expected_pair low_entropy[] = {{changed, account}};
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", changed, account);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", changed, account);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);

    size_t at = (size_t)snprintf(input, sizeof(input), "aeroworkflow %s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\naeroworkflow %s", account);
    expect_extraction(detector, input, strlen(input), one, 1); /* Span limits belong to the engine. */
    at = (size_t)snprintf(input, sizeof(input), "aeroworkflow");
    input[at++] = '\0';
    at += (size_t)snprintf(input + at, sizeof(input) - at, "%s\naeroworkflow %s", key, account);
    expect_extraction(detector, input, at, one, 1);

    memset(changed, '0', 20);
    changed[19] = '7';
    snprintf(input, sizeof(input), "aeroworkflow %s", changed);
    expected_pair self[] = {{changed, changed}};
    expect_extraction(detector, input, strlen(input), self, 1);
}

typedef struct { const expected_pair *pairs; size_t count; const char *agent; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    expected_pair pair = expected->pairs[http->calls - 1];
    char url[2048];
    snprintf(url, sizeof(url), "https://api.aeroworkflow.com/api/%s/me", pair.id);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 693);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "apikey") && !strcmp(request->headers[1].value, pair.key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
}

static void ordered_pairs(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "aeroworkflow 7\naeroworkflow %s\naeroworkflow %s\n"
             "aeroworkflow %s\naeroworkflow 7\naeroworkflow %s", other_key, account, key, other_key);
    const expected_pair pairs[] = {
        {other_key, "7"}, {other_key, account}, {other_key, "7"},
        {key, "7"}, {key, account}, {key, "7"},
        {other_key, "7"}, {other_key, account}, {other_key, "7"},
    };
    expect_extraction(detector, input, strlen(input), pairs, 9);
    expected_requests expected = {pairs, 9, "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 9 && http.calls == 9 && http.releases == 9);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    char long_id[257], numeric_key[21];
    memset(long_id, '7', sizeof(long_id) - 1);
    memcpy(long_id, "000", 3);
    long_id[256] = '\0';
    memcpy(numeric_key, long_id, 20);
    numeric_key[20] = '\0';
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", key, long_id);
    /* Numeric IDs are unbounded strings and can also be captured as API keys. */
    const expected_pair numeric[] = {{key, long_id}, {numeric_key, long_id}};
    expect_extraction(detector, input, strlen(input), numeric, 2);
    expected = (expected_requests){numeric, 2, "TruffleHog"};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], numeric[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", key, account);
    const expected_pair pairs[] = {{key, account}, {key, account}, {key, account}, {key, account}};
    expected_requests expected = {pairs, 1, "TruffleHog detector-test"};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected HTTP response status 201"},
        {500, 0, NULL, false, "unexpected HTTP response status 500"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, NULL, false, "HTTP transport failed"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = "ignored body-read failure"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "detector-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_pair(&results.items[0], pairs[0]);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s\naeroworkflow %s\naeroworkflow %s",
             key, account, key, account);
    char transport_error[128];
    snprintf(transport_error, sizeof(transport_error), "key=%s account=%s repeated=%s", key, account, key);
    expected = (expected_requests){pairs, 4, "TruffleHog"};
    test_http http = {.send_rc = -1, .send_error = transport_error, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, "key=[REDACTED] account=00042 repeated=[REDACTED]"));
    }
    br_results_clear(&results);

    http = (test_http){0};
    snprintf(input, sizeof(input), "aeroworkflow %s", account);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "aeroworkflow %s\naeroworkflow %s", key, account);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_pair(&results.items[0], pairs[0]);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    extraction(detector);
    ordered_pairs(detector);
    verification(detector);
    return test_finish("Aeroworkflow");
}
