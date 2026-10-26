/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic, deliberately non-UUID values; ID case must survive unchanged. */
static const char key[] = "abcdefghijklmnopqrstuvwxyz0123456789";
static const char id[] = "AbCdEfGhIjKlMnOpQrStUvWxYz012345";
typedef struct { const char *key, *id; } expected_pair;

static void check_result(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 269 && !result->detector_name);
    CHECK(result->raw.len == 36 && !memcmp(result->raw.data, pair.key, 36));
    CHECK(result->raw_v2.len == 68 && !memcmp(result->raw_v2.data, pair.key, 36));
    CHECK(!memcmp(result->raw_v2.data + 36, pair.id, 32));
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
    CHECK(br_apptivo_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_apptivo_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 269 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Apptivo") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Apptivo is a cloud-based suite of business solutions, including CRM, project "
                  "management, and more. Apptivo API keys can be used to access and manage these "
                  "services programmatically."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apptivo"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_apptivo_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Apptivo detector output"));
    free(error);
    CHECK(br_apptivo_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const expected_pair *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_result(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed_key[37], changed_id[33];
    const expected_pair one[] = {{key, id}};
    const struct { const char *format; bool matches; } cases[] = {
        {"apptivo %s\napptivo %s", true},
        {"preAPPTIVOsuffix:%s\nAPPTIVO %s", true},
        {"apptivo\r\n%s\napptivo\r\n%s", true},
        {"apptivo '%s'\napptivo '%s'", true},
        {"apptivo %s\n%s", true}, /* Independent patterns can reuse a prefix. */
        {"%s\n%s", false},
        {"apptivo %s", false},
        {"apptivo %.35s\napptivo %s", false},
        {"apptivo %sx\napptivo %s", false},
        {"apptivo _%s\napptivo %s", false},
        {"apptivo %s_\napptivo %s", false},
        {"apptivo %s\napptivo %.31s", false},
        {"apptivo %s\napptivo %sx", false},
        {"apptivo %s\napptivo _%s", false},
        {"apptivo %s\napptivo %s_", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key, id);
        expect_extraction(detector, input, one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, "", NULL, 0);
    snprintf(input, sizeof(input), "apptivo %s", id);
    expect_extraction(detector, input, NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "apptivo");
        memset(input + at, ':', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\napptivo %s", key, id);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
        at = (size_t)snprintf(input, sizeof(input), "apptivo %s\napptivo", key);
        memset(input + at, ':', gap);
        memcpy(input + at + gap, id, sizeof(id));
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[10] = 'A';
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", changed_key, id);
    expect_extraction(detector, input, NULL, 0); /* Prefix folding must not widen the key alphabet. */
    changed_key[10] = '_';
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", changed_key, id);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed_id, id, sizeof(changed_id));
    changed_id[10] = '_';
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", key, changed_id);
    expect_extraction(detector, input, NULL, 0);
    memset(changed_key, 'a', 36); changed_key[36] = '\0';
    memset(changed_id, 'Z', 32); changed_id[32] = '\0';
    const expected_pair loose[] = {{changed_key, changed_id}};
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", changed_key, changed_id);
    expect_extraction(detector, input, loose, 1); /* No UUID or entropy validation. */
    changed_key[17] = '-'; changed_id[13] = '-';
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", changed_key, changed_id);
    expect_extraction(detector, input, loose, 1);
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[0] = '-';
    const expected_pair key_boundary[] = {{changed_key, id}};
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", changed_key, id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "apptivo%s\napptivo %s", changed_key, id);
    expect_extraction(detector, input, key_boundary, 1);
    memcpy(changed_id, id, sizeof(changed_id));
    changed_id[31] = '-';
    const expected_pair id_boundary[] = {{key, changed_id}};
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", key, changed_id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "apptivo %s\napptivo %sX", key, changed_id);
    expect_extraction(detector, input, id_boundary, 1);

    /* The ID pattern can capture a key suffix across an internal hyphen boundary. */
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[4] = '-';
    const expected_pair overlap[] = {{changed_key, changed_key + 4}, {changed_key, id}};
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", changed_key, id);
    expect_extraction(detector, input, overlap, 2);
}

typedef struct { const expected_pair *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const expected_pair pair = expected->pairs[http->calls - 1];
    char url[192];
    snprintf(url, sizeof(url),
             "https://api.apptivo.com/app/dao/v6/leads?a=getConfigData&apiKey=%s&accessKey=%s", pair.key, pair.id);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 269);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    /* The only effective header is shared User-Agent, not provider auth/JSON headers. */
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog apptivo-test"));
}

static void test_occurrence_pairs(const br_detector *detector)
{
    char other_key[37], other_id[33], input[256];
    test_secret(other_key, 36, 9);
    test_secret(other_id, 32, 3);
    other_id[2] = 'Q';
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s\napptivo %s\napptivo %s", id, key, other_key, other_id);
    const expected_pair pairs[] = {{key, id}, {key, other_id}, {other_key, id}, {other_key, other_id}};
    expect_extraction(detector, input, pairs, 4);
    static const unsigned char body[] = "displayName";
    expected_requests expected = {pairs, 4};
    test_http http = {
        .response = {.status = 200, .body = {body, sizeof(body) - 1}},
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apptivo-test"};
    for (size_t failure = 0; failure < 2; ++failure) {
        http.calls = http.releases = 0;
        http.send_rc = failure ? -1 : 0;
        http.send_error = failure ? "context canceled" : NULL;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
        for (size_t i = 0; i < results.len; ++i) {
            check_result(&results.items[i], pairs[i]);
            CHECK(results.items[i].verified == !failure);
            if (failure) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, "context canceled"));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s\napptivo %s\napptivo %s", key, key, id, id);
    const expected_pair duplicates[] = {{key, id}, {key, id}, {key, id}, {key, id}};
    expect_extraction(detector, input, duplicates, 4);
}

typedef struct {
    int status, send_rc;
    br_slice body;
    const char *body_error, *send_error, *error, *id;
    bool verified;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[96];
    const expected_pair pair[] = {{key, fixture.id ? fixture.id : id}};
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", key, pair[0].id);
    expected_requests expected = {pair, 1};
    test_http http = {
        .response = {.status = fixture.status, .body = fixture.body, .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apptivo-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], pair[0]);
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
        CHECK(!strstr(results.items[0].verification_error, key));
        CHECK(!strstr(results.items[0].verification_error, pair[0].id));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    static const unsigned char marker[] = "displayName";
    static const unsigned char embedded[] = "not JSON: prefixdisplayNamesuffix";
    static const unsigned char binary[] = {'x', 0, 0xff, 'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm', 'e'};
    const verification_case cases[] = {
        {.status = 200},
        {.status = 200, .body = {marker, sizeof(marker) - 1}, .verified = true},
        {.status = 200, .body = {embedded, sizeof(embedded) - 1}, .verified = true},
        {.status = 200, .body = {(const unsigned char *)"DisplayName", 11}},
        {.status = 200, .body = {(const unsigned char *)"displayname", 11}},
        {.status = 200, .body = {(const unsigned char *)"display\\u004eame", 16}},
        {.status = 200, .body = {binary, sizeof(binary)}, .verified = true},
        {.status = 200, .body = {binary, sizeof(binary) - 1}},
        {.status = 200, .body = {marker, sizeof(marker) - 1}, .body_error = "read failed", .error = "read failed"},
        {.status = 200, .body_error = "read failed", .error = "read failed"},
        {.status = 200, .body = {marker, sizeof(marker) - 1}, .send_rc = -1,
         .send_error = "context canceled", .error = "context canceled"},
        {.status = 500, .body_error = "ignored body error", .send_rc = -1,
         .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    const struct { int status; const char *error; } statuses[] = {
        {201, "unexpected status code 201"}, {204, "unexpected status code 204"},
        {301, "unexpected status code 301"}, {400, "unexpected status code 400"},
        {401, "unexpected status code 401"}, {403, "unexpected status code 403"},
        {404, "unexpected status code 404"}, {500, "unexpected status code 500"},
    };
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
        verify_case(detector, (verification_case){.status = statuses[i].status,
            .body = {marker, sizeof(marker) - 1}, .body_error = "ignored deferred drain error", .error = statuses[i].error});

    const char *ids[] = {id, key + 4}; /* Overlap detects redaction in the wrong order. */
    const char *redacted = "key=[REDACTED] id=[REDACTED] key-again=[REDACTED] id-again=[REDACTED]";
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        char cause[256];
        snprintf(cause, sizeof(cause), "key=%s id=%s key-again=%s id-again=%s", key, ids[i], key, ids[i]);
        verify_case(detector, (verification_case){.status = 200, .send_rc = -1,
            .send_error = cause, .error = redacted, .id = ids[i]});
        verify_case(detector, (verification_case){.status = 200, .body = {marker, sizeof(marker) - 1},
            .body_error = cause, .error = redacted, .id = ids[i]});
    }
    char input[96];
    snprintf(input, sizeof(input), "apptivo %s", key);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "apptivo %s\napptivo %s", key, id);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_result(&results.items[0], (expected_pair){key, id});
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *state = detector->state;
    CHECK(strlen(key) == 36 && strlen(id) == 32);
    test_extraction(detector);
    test_occurrence_pairs(detector);
    test_verification(detector);
    const br_detector *again = NULL;
    CHECK(br_apptivo_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("Apptivo");
}
