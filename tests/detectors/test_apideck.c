/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[102] = "sk_live_", other_key[102] = "sk_live_", id[41], other_id[41];
typedef struct { const char *key, *id; } expected_pair;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apideck_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_apideck_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_apideck_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 212 && detector->version == 0);
    CHECK(!strcmp(detector->name, "ApiDeck") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "ApiDeck is a platform that provides a unified API to connect multiple services. "
        "ApiDeck keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apideck"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 212 && !result->detector_name);
    CHECK(result->raw.len == 101 && !memcmp(result->raw.data, pair.key, 101));
    CHECK(result->raw_v2.len == 141 && !memcmp(result->raw_v2.data, pair.key, 101));
    CHECK(!memcmp(result->raw_v2.data + 101, pair.id, 40));
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
        CHECK(results.items[i].raw.len == 101 && results.items[i].raw_v2.len == 141);
        size_t p = 0;
        for (; p < count; ++p)
            if (!memcmp(results.items[i].raw.data, pairs[p].key, 101) &&
                !memcmp(results.items[i].raw_v2.data + 101, pairs[p].id, 40)) break;
        CHECK(p < count);
        check_pair(&results.items[i], pairs[p]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        for (size_t j = 0; j < i; ++j) CHECK(memcmp(results.items[i].raw_v2.data, results.items[j].raw_v2.data, 141) != 0);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed_key[102], changed_id[41];
    const expected_pair one[] = {{key, id}};
    snprintf(input, sizeof(input), "%s\napideck %s", key, id);
    expect_extraction(detector, input, one, 1); /* No provider prefix belongs before the key. */
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s %s", key, id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "apideck %s", id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "apideck %s\n%s", id, key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "%s\npreAPIDECKsuffix:%s", key, id);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "%s\napideck\r\n%s", key, id);
    expect_extraction(detector, input, one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "%s\napideck", key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", id);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const struct { const char *before, *after; } edges[] = {{"_", ""}, {"x", ""}, {"", "_"}, {"", "Q"}};
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "%s%s%s\napideck %s", edges[i].before, key, edges[i].after, id);
        expect_extraction(detector, input, NULL, 0);
        snprintf(input, sizeof(input), "%s\napideck %s%s%s", key, edges[i].before, id, edges[i].after);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "%s-\napideck %s", key, id);
    expect_extraction(detector, input, one, 1); /* A longer allowed run can end a capture at a boundary. */
    snprintf(input, sizeof(input), "%.100s\napideck %s", key, id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "%s\napideck %.39s", key, id);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[0] = 'S';
    snprintf(input, sizeof(input), "%s\napideck %s", changed_key, id);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[30] = '_';
    snprintf(input, sizeof(input), "%s\napideck %s", changed_key, id);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed_id, id, sizeof(changed_id));
    changed_id[20] = '-';
    snprintf(input, sizeof(input), "%s\napideck %s", key, changed_id);
    expect_extraction(detector, input, NULL, 0);

    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[8] = '-';
    const expected_pair hyphen[] = {{changed_key, id}};
    snprintf(input, sizeof(input), "%s\napideck %s", changed_key, id);
    expect_extraction(detector, input, hyphen, 1);
    changed_key[100] = '-';
    snprintf(input, sizeof(input), "%s\napideck %s", changed_key, id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "%sQ\napideck %s", changed_key, id);
    expect_extraction(detector, input, hyphen, 1);

    memset(changed_key + 8, 'a', 93);
    memset(changed_id, 'b', 40);
    changed_id[40] = '\0';
    const expected_pair low[] = {{changed_key, changed_id}};
    snprintf(input, sizeof(input), "%s\napideck %s", changed_key, changed_id);
    expect_extraction(detector, input, low, 1);

    memset(changed_key + 8, 'b', 93);
    changed_key[8] = 'a';
    changed_key[9] = '-';
    memcpy(changed_key + 10, id, 40);
    changed_key[50] = '-';
    const expected_pair embedded[] = {{changed_key, id}};
    snprintf(input, sizeof(input), "apideck %s", changed_key);
    expect_extraction(detector, input, embedded, 1); /* ID extraction independently sees a bounded run inside a key. */
    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\napideck %s", id);
    expect_extraction(detector, input, one, 1);
}

typedef struct { const expected_pair *pairs; size_t count; unsigned seen; } requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://unify.apideck.com/vault/consumers"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 212);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "x-apideck-app-id"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog apideck-test"));
    CHECK(expected->count <= 4);
    size_t p = 0;
    for (; p < expected->count; ++p) {
        char auth[109];
        snprintf(auth, sizeof(auth), "Bearer %s", expected->pairs[p].key);
        if (!strcmp(request->headers[0].value, expected->pairs[p].id) && !strcmp(request->headers[1].value, auth)) break;
    }
    CHECK(p < expected->count && !(expected->seen & (1u << p)));
    expected->seen |= 1u << p;
}

static void verification(const br_detector *detector)
{
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, NULL, false, "HTTP transport failed"},
    };
    char input[512];
    snprintf(input, sizeof(input), "%s\napideck %s\n%s\napideck %s", key, id, key, id);
    const expected_pair pair = {key, id};
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        requests expected = {&pair, 1, 0};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "ignored body-read/drain error"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "apideck-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.seen == 1);
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

static void unique_product(const br_detector *detector)
{
    char input[512], cause[512];
    snprintf(input, sizeof(input), "apideck %s\n%s\napideck %s\n%s\n%s\napideck %s", id, other_key, other_id, key, other_key, id);
    const expected_pair pairs[] = {{key, id}, {key, other_id}, {other_key, id}, {other_key, other_id}};
    expect_extraction(detector, input, pairs, 4);
    snprintf(cause, sizeof(cause), "key=%s id=%s repeated=%s", key, id, key);
    static const unsigned char body[] = "not JSON";
    for (int mode = 0; mode < 2; ++mode) {
        requests expected = {pairs, 4, 0};
        test_http http = {
            .response = {.status = 200, .body = {body, sizeof(body) - 1}, .body_error = "ignored"},
            .send_rc = mode ? -1 : 0, .send_error = mode ? cause : NULL,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "apideck-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 4 && http.calls == 4 && http.releases == 4 && expected.seen == 15);
        for (size_t i = 0; i < results.len; ++i) {
            CHECK(results.items[i].verified == (mode == 0));
            if (mode) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, cause));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "apideck %s", id);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key + 8, 93, 0);
    test_secret(other_key + 8, 93, 9);
    key[8] = 'B';
    other_key[8] = 'M';
    key[28] = other_key[28] = '-';
    key[61] = other_key[61] = '-';
    key[84] = other_key[84] = '-';
    key[100] = 'Z';
    other_key[100] = 'N';
    test_secret(id, 40, 3);
    test_secret(other_id, 40, 13);
    id[0] = 'U';
    other_id[0] = 'V';
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    unique_product(detector);
    return test_finish("ApiDeck");
}
