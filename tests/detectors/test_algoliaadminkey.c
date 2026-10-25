/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static char key[33], other_key[33];
static const char id[] = "AB12CD34EF", other_id[] = "GH56IJ78KL";
static int64_t test_now_ns = 1700000000000000000LL;

/* Interpose only the provider's wall clock, so cache expiry needs no real wait
 * or production test hook. HTTP deadline handling uses CLOCK_MONOTONIC. */
int timespec_get(struct timespec *time, int base)
{
    if (base != TIME_UTC) return 0;
    time->tv_sec = (time_t)(test_now_ns / 1000000000);
    time->tv_nsec = (long)(test_now_ns % 1000000000);
    return TIME_UTC;
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_algoliaadminkey_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_algoliaadminkey_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 170 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AlgoliaAdminKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Algolia is a search-as-a-service platform. Algolia Admin Keys can be used to manage indices "
        "and API keys, and perform administrative tasks."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "algolia") &&
          !strcmp(detector->keywords[1], "docsearch"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, const char *application, const char *secret)
{
    CHECK(result->detector_type == 170 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, secret, 32));
    CHECK(result->raw_v2.len == 43 && !memcmp(result->raw_v2.data, application, 10));
    CHECK(result->raw_v2.data[10] == ':' && !memcmp(result->raw_v2.data + 11, secret, 32));
    CHECK(!result->redacted && !result->structured_data && !result->verification_from_cache);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), secret));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), application));
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void expect_one(const br_detector *detector, const void *input, size_t len,
                         const char *application, const char *secret)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (application ? 1u : 0u) && !http.calls && !http.releases);
    if (application) {
        check_pair(&results.items[0], application, secret);
        CHECK(!results.items[0].verified && !results.items[0].verification_error && !results.items[0].extra_data);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed[33];
    const char *prefixes[] = {"algolia", "docsearch", "APPID"};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(input, sizeof(input), "%s %s\n%s %s", prefixes[i], id, i == 2 ? "APIKEY" : prefixes[i], key);
        expect_one(detector, input, strlen(input), id, key);
    }
    expect_one(detector, NULL, 0, NULL, NULL);
    snprintf(input, sizeof(input), "%s %s", id, key);
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "apiKey %s", key);
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "appId %s", id);
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "appId\r\n%s\napiKey\r\n%s", id, key);
    expect_one(detector, input, strlen(input), id, key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "appId");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\napiKey %s", id, key);
        expect_one(detector, input, strlen(input), gap == 40 ? id : NULL, key);
        at = (size_t)snprintf(input, sizeof(input), "appId %s\napiKey", id);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", key);
        expect_one(detector, input, strlen(input), gap == 40 ? id : NULL, key);
    }
    snprintf(input, sizeof(input), "appId _%s\napiKey %s", id, key);
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "appId %s_\napiKey %s", id, key);
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "appId a%s\napiKey %s", id + 1, key);
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "appId %s\napiKey %s_", id, key);
    expect_one(detector, input, strlen(input), NULL, NULL);
    memcpy(changed, key, sizeof(changed));
    changed[15] = '-';
    snprintf(input, sizeof(input), "appId %s\napiKey %s", id, changed);
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "appId AAABBBCCDD\napiKey %s", key); /* ID entropy < 2. */
    expect_one(detector, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "appId AABBCCDDEE\napiKey %s", key); /* ID entropy > 2. */
    expect_one(detector, input, strlen(input), "AABBCCDDEE", key);
    memcpy(changed, "ABCDEFGHABCDEFGHABCDEFGHABCDEFGH", 33); /* Exactly 3 bits is rejected. */
    snprintf(input, sizeof(input), "appId %s\napiKey %s", id, changed);
    expect_one(detector, input, strlen(input), NULL, NULL);
    for (size_t i = 0; i < 32; ++i) changed[i] = "ABCDEFGHI"[i % 9];
    snprintf(input, sizeof(input), "appId %s\napiKey %s", id, changed);
    expect_one(detector, input, strlen(input), id, changed);
    size_t at = (size_t)snprintf(input, sizeof(input), "appId %s\n", id);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\napiKey %s", key);
    expect_one(detector, input, strlen(input), id, key); /* Span restriction is engine-owned. */
}

typedef struct {
    const char *id, *other_id, *key, *other_key;
    size_t key_calls, other_calls;
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 170 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "X-Algolia-Application-Id"));
    CHECK(!strcmp(request->headers[1].name, "X-Algolia-API-Key"));
    const char *application = request->headers[0].value, *secret = request->headers[1].value;
    CHECK(!strcmp(application, expected->id) || (expected->other_id && !strcmp(application, expected->other_id)));
    if (!strcmp(secret, expected->key)) ++expected->key_calls;
    else { CHECK(expected->other_key && !strcmp(secret, expected->other_key)); ++expected->other_calls; }
    char url[128];
    snprintf(url, sizeof(url), "https://%s.algolia.net/1/keys/%s", application, secret);
    CHECK(!strcmp(request->url, url));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") &&
          !strcmp(request->headers[2].value, "TruffleHog algolia-test"));
}

typedef struct {
    const char *body, *body_error, *send_error;
    int status, send_rc;
    const char *acl, *description, *error;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[128];
    snprintf(input, sizeof(input), "appId %s\napiKey %s", id, key);
    requests expected = {.id = id, .key = key};
    test_http http = {
        .response = {.status = fixture.status ? fixture.status : 200,
                     .body = {(const unsigned char *)fixture.body, fixture.body ? strlen(fixture.body) : 0},
                     .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "algolia-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.key_calls == 1);
    br_result *result = &results.items[0];
    check_pair(result, id, key);
    CHECK(result->verified == (fixture.acl != NULL));
    if (fixture.error) CHECK(result->verification_error && !strcmp(result->verification_error, fixture.error));
    else CHECK(!result->verification_error);
    if (!fixture.acl) CHECK(!result->extra_data);
    else {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == (fixture.description ? 2 : 1));
        br_json *value = NULL;
        CHECK(json_object_object_get_ex(result->extra_data, "acl", &value));
        CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), fixture.acl));
        if (fixture.description) {
            CHECK(json_object_object_get_ex(result->extra_data, "description", &value));
            CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), fixture.description));
        }
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const verification_case cases[] = {
        {.body = "{\"acl\":[\"search\",\"deleteObject\",\"addObject\",\"deleteObject\"],\"description\":\"Fixture\"}",
         .acl = "addObject,deleteObject,deleteObject,search", .description = "Fixture"},
        {.body = "{\"acl\":[\"listIndexes\",\"search\",\"settings\"]}"},
        {.body = "{\"acl\":[],\"description\":\"ignored\"}"},
        {.body = "{}"}, {.body = "null"}, {.body = "{\"acl\":null}"},
        {.body = "{\"acl\":[null]}", .acl = ""},
        {.body = "{\"ACL\":[\"addObject\"],\"DESCRIPTION\":\"<redacted>\"}", .acl = "addObject"},
        {.body = "{\"acl\":[\"addObject\"],\"description\":\"\"}", .acl = "addObject"},
        {.body = "{\"acl\":[\"search\"],\"acl\":[\"deleteObject\"],\"description\":\"first\",\"description\":null}",
         .acl = "deleteObject", .description = "first"},
        {.body = "{\"acl\":[\"addObject\"],\"acl\":null}"},
        {.body = "{\"acl\":[\"search\"],\"acl\":[null]}"},
        {.body = "{\"acl\":[\"deleteObject\",\"search\"],\"acl\":[null],\"acl\":[null,null]}",
         .acl = "deleteObject,search"},
        {.body = "{\"acl\":3}", .error = "json: cannot unmarshal number into Go struct field keyResponse.acl of type []string"},
        {.body = "{\"acl\":[1]}", .error = "json: cannot unmarshal number into Go struct field keyResponse.acl of type string"},
        {.body = "{\"description\":false,\"acl\":[\"addObject\"]}",
         .error = "json: cannot unmarshal bool into Go struct field keyResponse.description of type string"},
        {.body = "{\"acl\":7,\"acl\":[\"addObject\"]}",
         .error = "json: cannot unmarshal number into Go struct field keyResponse.acl of type []string"},
        {.body = "[]", .error = "json: cannot unmarshal array into Go value of type algoliaadminkey.keyResponse"},
        {.body = "!", .error = "invalid character '!' looking for beginning of value"},
        {.body = "", .error = "EOF"},
        {.body = "{\"acl\":[", .error = "unexpected EOF"},
        {.body = "{\"acl\":[\"addObject\"]}not-json", .acl = "addObject"},
        {.body = "{\"acl\":[\"search\"]}{\"acl\":[\"addObject\"]}"},
        {.body = "{\"acl\":[\"addObject\"]}", .body_error = "ignored after complete document", .acl = "addObject"},
        {.status = 401, .body = "not JSON", .body_error = "ignored"},
        {.status = 403, .body = "not JSON", .body_error = "ignored"},
        {.status = 500, .body_error = "ignored", .error = "unexpected HTTP response status 500"},
        {.send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.send_rc = -1, .error = "HTTP transport failed"},
        {.send_rc = -1, .send_error = "No such host", .error = "No such host"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    char cause[160], redacted[160];
    snprintf(cause, sizeof(cause), "key=%s id=%s repeated=%s", key, id, key);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] id=%s repeated=[REDACTED]", id);
    verify_case(detector, (verification_case){.send_rc = -1, .send_error = cause, .error = redacted});
    verify_case(detector, (verification_case){.body = "{\"acl\":[", .body_error = cause, .error = redacted});

    /* Decoded response strings are not credential captures: retain embedded NUL. */
    const char body[] = "{\"acl\":[\"search\\u0000admin\",\"addObject\"],\"description\":\"n\\u0000d\"}";
    char input[128];
    snprintf(input, sizeof(input), "appId %s\napiKey %s", id, key);
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "acl", &value));
    const char acl[] = "addObject,search\0admin";
    CHECK(json_object_get_string_len(value) == (int)sizeof(acl) - 1 && !memcmp(json_object_get_string(value), acl, sizeof(acl) - 1));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "description", &value));
    CHECK(json_object_get_string_len(value) == 3 && !memcmp(json_object_get_string(value), "n\0d", 3));
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
}

static void pairing_and_cache(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "appId %s\nappId %s\napiKey %s\napiKey %s\nappId %s\napiKey %s",
             id, other_id, key, other_key, id, key);
    requests expected = {.id = id, .other_id = other_id, .key = key, .other_key = other_key};
    const char body[] = "{\"acl\":[\"addObject\"]}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "algolia-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        const char *application = !memcmp(results.items[i].raw_v2.data, id, 10) ? id : other_id;
        const char *secret = !memcmp(results.items[i].raw.data, key, 32) ? key : other_key;
        check_pair(&results.items[i], application, secret);
        CHECK(!results.items[i].verified && !results.items[i].extra_data && !results.items[i].verification_error);
        for (size_t j = 0; j < i; ++j) CHECK(memcmp(results.items[i].raw_v2.data, results.items[j].raw_v2.data, 43) != 0);
    }
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    CHECK(expected.key_calls == 1 && expected.other_calls == 1); /* Stop this key's ID loop on verification. */
    for (size_t i = 0; i < results.len; ++i) CHECK(results.items[i].verified);
    br_results_clear(&results);

    const char bad_id[] = "MN90PQ12RS", bad_other[] = "TU34VW56XY";
    snprintf(input, sizeof(input), "appId %s\nappId %s\napiKey %s\napiKey %s", bad_id, bad_other, key, other_key);
    expected = (requests){.id = bad_id, .other_id = bad_other, .key = key, .other_key = other_key};
    http = (test_http){.send_rc = -1, .send_error = "lookup fixture.algolia.net: no such host",
                       .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    const br_detector *again = NULL;
    char *error = NULL;
    CHECK(br_algoliaadminkey_init(&again, &error) == 0 && !error && again == detector);
    results = test_scan(again, &ctx, false, input, strlen(input));
    CHECK(!results.len && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    test_now_ns += 12LL * 60 * 60 * 1000000000;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len && http.calls == 2);
    br_results_clear(&results);
    ++test_now_ns;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "appId %s\napiKey %s", id, key);
    expect_one(detector, input, strlen(input), id, key); /* Cache is per ID, not per key. */
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other_key, 32, 9);
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    pairing_and_cache(detector);
    return test_finish("AlgoliaAdminKey");
}
