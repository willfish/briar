/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[33], other_key[33], id[21], other_id[21];
typedef struct { const char *key, *id; } expected_pair;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_artsy_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_artsy_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_artsy_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 278 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Artsy") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Artsy is an online platform for discovering, buying, and selling art. "
        "Artsy API keys can be used to access Artsy's services and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "artsy"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 278 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, pair.key, 32));
    CHECK(result->raw_v2.len == 52 && !memcmp(result->raw_v2.data, pair.key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, pair.id, 20));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.id));
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const expected_pair *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed_key[33], changed_id[21];
    const expected_pair one[] = {{key, id}};
    snprintf(input, sizeof(input), "artsy %s\nartsy %s", key, id);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, NULL, NULL, 0);
    snprintf(input, sizeof(input), "%s %s", key, id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "artsy %s", key);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "artsy %s", id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "artsy %s %s", key, id);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "artsy %s\nartsy %s", id, key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "preARTSYsuffix:%s\nartsy\r\n%s", key, id);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "artsy \xc3\xa9%s\xc3\xa9\nartsy \xc3\xa9%s\xc3\xa9", key, id);
    expect_extraction(detector, input, one, 1); /* Word boundaries remain ASCII. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "artsy");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\nartsy %s", key, id);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
        at = (size_t)snprintf(input, sizeof(input), "artsy %s\nartsy", key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", id);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const struct { const char *before, *after; } edges[] = {{"_", ""}, {"", "_"}, {"", "Q"}};
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "artsy %s%s%s\nartsy %s", edges[i].before, key, edges[i].after, id);
        expect_extraction(detector, input, NULL, 0);
        snprintf(input, sizeof(input), "artsy %s\nartsy %s%s%s", key, edges[i].before, id, edges[i].after);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "artsy %.31s\nartsy %s", key, id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "artsy %s\nartsy %.19s", key, id);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[7] = '-';
    snprintf(input, sizeof(input), "artsy %s\nartsy %s", changed_key, id);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed_id, id, sizeof(changed_id));
    changed_id[7] = '%';
    snprintf(input, sizeof(input), "artsy %s\nartsy %s", key, changed_id);
    expect_extraction(detector, input, NULL, 0);
    memset(changed_key, 'a', 32);
    changed_key[32] = '\0';
    memset(changed_id, 'b', 20);
    changed_id[20] = '\0';
    const expected_pair low[] = {{changed_key, changed_id}};
    snprintf(input, sizeof(input), "artsy %s\nartsy %s", changed_key, changed_id);
    expect_extraction(detector, input, low, 1);
    size_t at = (size_t)snprintf(input, sizeof(input), "artsy %s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\nartsy %s", id);
    expect_extraction(detector, input, one, 1); /* No scanner-local credential span restriction. */
}

typedef struct { const expected_pair *pairs; size_t count; } requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    expected_pair pair = expected->pairs[http->calls - 1];
    char url[160];
    snprintf(url, sizeof(url), "https://api.artsy.net/api/tokens/xapp_token?client_id=%s&client_secret=%s", pair.id, pair.key);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 278);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* No invented Content-Type, despite POST. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog artsy-test"));
}

static void verification(const br_detector *detector)
{
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {201, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {200, 0, NULL, false, "unexpected status code 200"},
        {403, 0, NULL, false, "unexpected status code 403"},
        {500, 0, NULL, false, "unexpected status code 500"},
        {201, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {201, -1, "context canceled", false, "context canceled"},
        {201, -1, NULL, false, "HTTP transport failed"},
    };
    char input[128];
    snprintf(input, sizeof(input), "artsy %s\nartsy %s", key, id);
    const expected_pair pair = {key, id};
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        requests expected = {&pair, 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "ignored body-read/drain error"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "artsy-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_pair(&results.items[0], pair);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_pair(&results.items[0], pair);
    br_results_clear(&results);
}

static void occurrence_product(const br_detector *detector)
{
    char input[512], cause[256], for_key[256], for_other[256];
    snprintf(input, sizeof(input), "artsy %s\nartsy %s\nartsy %s\nartsy %s\nartsy %s\nartsy %s",
             id, other_key, other_id, key, id, other_key);
    const expected_pair pairs[] = {
        {other_key, id}, {other_key, other_id}, {other_key, id},
        {key, id}, {key, other_id}, {key, id},
        {other_key, id}, {other_key, other_id}, {other_key, id},
    };
    expect_extraction(detector, input, pairs, 9);
    snprintf(cause, sizeof(cause), "request id=%s key=%s repeated=%s other=%s", id, key, key, other_key);
    snprintf(for_key, sizeof(for_key), "request id=%s key=[REDACTED] repeated=[REDACTED] other=%s", id, other_key);
    snprintf(for_other, sizeof(for_other), "request id=%s key=%s repeated=%s other=[REDACTED]", id, key, key);
    static const unsigned char body[] = "ignored";
    for (int mode = 0; mode < 2; ++mode) {
        requests expected = {pairs, 9};
        test_http http = {
            .response = {.status = 201, .body = {body, sizeof(body) - 1}, .body_error = cause},
            .send_rc = mode ? -1 : 0, .send_error = mode ? cause : NULL,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "artsy-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 9 && http.calls == 9 && http.releases == 9);
        for (size_t r = 0; r < results.len; ++r) {
            check_pair(&results.items[r], pairs[r]);
            CHECK(results.items[r].verified == (mode == 0));
            if (mode) {
                CHECK(results.items[r].verification_error);
                CHECK(!strcmp(results.items[r].verification_error, r >= 3 && r < 6 ? for_key : for_other));
                CHECK(!strstr(results.items[r].verification_error, pairs[r].key));
                CHECK(strstr(results.items[r].verification_error, id)); /* The omitted ID redaction stays omitted. */
            } else CHECK(!results.items[r].verification_error);
        }
        br_results_clear(&results);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "artsy %s", id);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other_key, 32, 9);
    test_secret(id, 20, 3);
    test_secret(other_id, 20, 17);
    key[0] = 'B';
    other_key[0] = 'M';
    id[0] = 'U';
    other_id[0] = 'V';
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    occurrence_product(detector);
    return test_finish("Artsy");
}
