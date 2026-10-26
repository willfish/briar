/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic, deliberately non-UUID credentials. */
static const char key[] = "abcdefghijklmnopqrstuvwxyz0123456789";
static const char username[] = "userabcdefghijklmnopqrstuvwxyz012345678";
static const char account[] = "00042";
typedef struct { const char *key, *username, *id; } expected_triple;

static void check_result(const br_result *result, expected_triple triple)
{
    CHECK(result->detector_type == 322 && !result->detector_name);
    CHECK(result->raw.len == 36 && !memcmp(result->raw.data, triple.key, 36));
    CHECK(result->raw_v2.len == 75 && !memcmp(result->raw_v2.data, triple.key, 36));
    CHECK(!memcmp(result->raw_v2.data + 36, triple.username, 39));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), triple.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "username", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), triple.username));
    CHECK(!json_object_object_get_ex(result->secret_parts, "id", &part));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_appcues_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_appcues_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 322 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Appcues") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Appcues is a user engagement platform that helps create personalized user "
                  "experiences. The detected credentials can be used to access and manage "
                  "user engagement flows and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "appcues"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_appcues_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_appcues_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const expected_triple *triples, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_result(&results.items[i], triples[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[2048], changed_key[37], changed_user[40];
    const expected_triple one[] = {{key, username, account}};
    const struct { const char *format; bool matches; } cases[] = {
        {"appcues %s\nappcues %s\nappcues %s", true},
        {"preAPPCUESsuffix:%s\nAPPCUES %s\nappcues %s", true},
        {"appcues\r\n%s\nappcues\r\n%s\nappcues\r\n%s", true},
        {"appcues '%s'\nappcues '%s'\nappcues '%s'", true},
        {"appcues \xc3\xa9%s\xc3\xa9\nappcues %s\nappcues %s", true},
        {"%s\n%s\n%s", false},
        {"appcues %s\nappcues %s", false}, /* Account ID is mandatory before verification. */
        {"appcues %s\nappcues %s\nappcues %.4s", false},
        {"appcues _%s\nappcues %s\nappcues %s", false},
        {"appcues %s_\nappcues %s\nappcues %s", false},
        {"appcues %.35s\nappcues %s\nappcues %s", false},
        {"appcues %s\nappcues %.38s\nappcues %s", false},
        {"appcues %s\nappcues _%s\nappcues %s", false},
        {"appcues %s\nappcues %s_\nappcues %s", false},
        {"appcues %s\n%s\nappcues %s", true}, /* Independent patterns can reuse a prefix. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key, username, account);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
    snprintf(input, sizeof(input), "appcues %s\nappcues %s", key, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "appcues %s\nappcues %s", username, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    const char *invalid_ids[] = {"000420", "a00042", "00042a", "_00042", "00042_"};
    for (size_t i = 0; i < sizeof(invalid_ids) / sizeof(invalid_ids[0]); ++i) {
        snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", key, username, invalid_ids[i]);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "appcues");
        memset(input + at, ':', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\nappcues %s\nappcues %s", key, username, account);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        at = (size_t)snprintf(input, sizeof(input), "appcues %s\nappcues", key);
        memset(input + at, ':', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\nappcues %s", username, account);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        at = (size_t)snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues", key, username);
        memset(input + at, ':', gap);
        memcpy(input + at + gap, account, sizeof(account));
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[10] = 'A';
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", changed_key, username, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    changed_key[10] = '_';
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", changed_key, username, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed_user, username, sizeof(changed_user));
    changed_user[20] = 'A';
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", key, changed_user, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    changed_user[20] = '_';
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", key, changed_user, account);
    expect_extraction(detector, input, strlen(input), NULL, 0);

    memset(changed_key, 'a', 36); changed_key[36] = '\0';
    memset(changed_user, 'b', 39); changed_user[39] = '\0';
    const expected_triple loose[] = {{changed_key, changed_user, account}};
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", changed_key, changed_user, account);
    expect_extraction(detector, input, strlen(input), loose, 1); /* No UUID or entropy validation. */
    changed_key[17] = '-'; changed_user[20] = '-';
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", changed_key, changed_user, account);
    expect_extraction(detector, input, strlen(input), loose, 1);

    /* A hyphen creates a valid 36-byte key suffix inside a 39-byte username. */
    memcpy(changed_user, username, sizeof(changed_user));
    changed_user[3] = '-';
    const expected_triple overlap[] = {{key, changed_user, account}, {changed_user + 3, changed_user, account}};
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", key, changed_user, account);
    expect_extraction(detector, input, strlen(input), overlap, 2);

    const expected_triple hidden_ids[] = {{key, username, account}, {key, username, "73109"}};
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s\nappcues 73109", key, username, account);
    expect_extraction(detector, input, strlen(input), hidden_ids, 2); /* Identical RawV2, distinct ID occurrences. */
    size_t at = (size_t)snprintf(input, sizeof(input), "appcues %s\nappcues %s\n", key, username);
    memset(input + at, ':', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\nappcues %s", account);
    expect_extraction(detector, input, strlen(input), one, 1); /* Engine owns the span limit. */
    memcpy(input, "appcues\0", 8);
    at = 8 + (size_t)snprintf(input + 8, sizeof(input) - 8, "%s\nappcues %s\nappcues %s", key, username, account);
    expect_extraction(detector, input, at, one, 1);
}

typedef struct { const expected_triple *triples; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const expected_triple triple = expected->triples[http->calls - 1];
    char url[96];
    snprintf(url, sizeof(url), "https://api.appcues.com/v2/accounts/%s/flows", triple.id);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 322);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    char *auth = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)triple.username, 39},
                             (br_slice){(const unsigned char *)triple.key, 36}, &auth, &error) == 0 && auth && !error);
    CHECK(!strcmp(request->headers[0].value, auth));
    if (!strcmp(triple.key, key) && !strcmp(triple.username, username)) {
        /* Independently generated Python stdlib Base64 golden, including padding. */
        CHECK(!strcmp(auth, "Basic dXNlcmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OQ=="));
    }
    free(auth);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog appcues-test"));
}

static void test_ordered_triples(const br_detector *detector)
{
    char other_key[37], other_user[40], input[512];
    test_secret(other_key, 36, 9);
    test_secret(other_user, 39, 0);
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s\nappcues 73109\nappcues %s\nappcues %s",
             account, username, key, other_key, other_user);
    const expected_triple triples[] = {
        {key, username, account}, {key, username, "73109"},
        {key, other_user, account}, {key, other_user, "73109"},
        {other_key, username, account}, {other_key, username, "73109"},
        {other_key, other_user, account}, {other_key, other_user, "73109"},
    };
    expect_extraction(detector, input, strlen(input), triples, 8);
    expected_requests expected = {triples, 8};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "appcues-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 8 && http.calls == 8 && http.releases == 8);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], triples[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    http.calls = http.releases = 0;
    http.send_rc = -1;
    http.send_error = "context canceled";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 8 && http.calls == 8 && http.releases == 8);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], triples[i]);
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, "context canceled"));
    }
    br_results_clear(&results);

    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s\nappcues %s\nappcues %s\nappcues %s",
             key, key, username, username, account, account);
    const expected_triple duplicates[] = {
        {key, username, account}, {key, username, account}, {key, username, account}, {key, username, account},
        {key, username, account}, {key, username, account}, {key, username, account}, {key, username, account},
    };
    expect_extraction(detector, input, strlen(input), duplicates, 8);
}

typedef struct {
    int status, send_rc;
    const char *send_error, *error, *id;
    bool verified;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[160];
    const char *id_value = fixture.id ? fixture.id : account;
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", key, username, id_value);
    const expected_triple triple[] = {{key, username, id_value}};
    expected_requests expected = {triple, 1};
    static const unsigned char body[] = {0, 0xff, '{'};
    test_http http = {
        .response = {.status = fixture.status, .body = {body, sizeof(body)}, .body_error = "ignored body-read failure"},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "appcues-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], triple[0]);
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
        CHECK(!strstr(results.items[0].verification_error, key));
        CHECK(!strstr(results.items[0].verification_error, username));
        CHECK(!strstr(results.items[0].verification_error, id_value));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    const verification_case cases[] = {
        {.status = 200, .verified = true}, {.status = 400}, {.status = 401}, {.status = 403},
        {.status = 201, .error = "unexpected status code: 201"},
        {.status = 404, .error = "unexpected status code: 404"},
        {.status = 500, .error = "unexpected status code: 500"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    const char *ids[] = {account, "01234"};
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        char cause[320];
        snprintf(cause, sizeof(cause), "user=%s key=%s id=%s user-again=%s key-again=%s id-again=%s",
                 username, key, ids[i], username, key, ids[i]);
        verify_case(detector, (verification_case){.status = 200, .send_rc = -1, .send_error = cause,
            .id = ids[i], .error = "user=[REDACTED] key=[REDACTED] id=[REDACTED] user-again=[REDACTED] key-again=[REDACTED] id-again=[REDACTED]"});
    }
    char input[160];
    snprintf(input, sizeof(input), "appcues %s\nappcues %s", key, username);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues %s", key, username, account);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_result(&results.items[0], (expected_triple){key, username, account});
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *state = detector->state;
    CHECK(strlen(key) == 36 && strlen(username) == 39 && strlen(account) == 5);
    test_extraction(detector);
    test_ordered_triples(detector);
    test_verification(detector);
    const br_detector *again = NULL;
    CHECK(br_appcues_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("Appcues");
}
