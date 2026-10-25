/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

#include <openssl/rand.h>
#include <time.h>

/* All credentials and signing vectors are synthetic. */
static const char key[] = "abcdefghijklmnopqrstuvwxyz0123";
static const char other_key[] = "zyxwvutsrqponmlkjihgfedcba9876";
static const char id[] = "LTAI0123456789abcdefg";
static const char other_id[] = "LTAIabcdefghijklmnopqrstu";
static size_t clock_calls, random_calls;
static int random_result = 1;

time_t time(time_t *out)
{
    ++clock_calls;
    time_t fixed = 1577934245; /* 2020-01-02T03:04:05Z */
    if (out) *out = fixed;
    return fixed;
}

int RAND_bytes(unsigned char *out, int count)
{
    ++random_calls;
    CHECK(count == 16);
    if (random_result != 1) {
        memset(out, 0x5a, (size_t)count / 2); /* Simulate a partially filled failed request. */
        return random_result;
    }
    for (int i = 0; i < count; ++i) out[i] = (unsigned char)i;
    out[14] = 254;
    out[15] = 255; /* Modulo 36, not rejection sampling: nonce ends in "23". */
    return 1;
}

typedef struct { const char *key, *id; } expected_pair;

static void check_pair(const br_result *result, expected_pair pair)
{
    size_t id_len = strlen(pair.id);
    CHECK(result->detector_type == 0 && !result->detector_name);
    CHECK(result->raw.len == 30 && !memcmp(result->raw.data, pair.key, 30));
    CHECK(result->raw_v2.len == 30 + id_len && !memcmp(result->raw_v2.data, pair.key, 30));
    CHECK(!memcmp(result->raw_v2.data + 30, pair.id, id_len));
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
    CHECK(br_alibaba_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_alibaba_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 0 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Alibaba") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Alibaba Cloud is a cloud computing service that provides a suite of cloud "
                  "computing services including data storage, relational databases, big-data "
                  "processing, and content delivery networks (CDNs). Alibaba Cloud API keys "
                  "can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "LTAI"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_alibaba_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_alibaba_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const expected_pair *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    clock_calls = random_calls = 0;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    CHECK(!clock_calls && !random_calls);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[2048], changed[31], changed_id[32];
    const expected_pair one[] = {{key, id}};
    snprintf(input, sizeof(input), "%s\n%s", key, id); /* No separate provider prefix. */
    expect_extraction(detector, input, strlen(input), one, 1);
    expect_extraction(detector, NULL, 0, NULL, 0);
    expect_extraction(detector, key, strlen(key), NULL, 0);
    expect_extraction(detector, id, strlen(id), NULL, 0);
    const struct { const char *before, *after; bool matches; } edges[] = {
        {"'", "'", true}, {"\xc3\xa9", "\xc3\xa9", true},
        {"_", "", false}, {"", "_", false},
        {"x", "", false}, {"", "x", false},
    };
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "%s%s%s\n%s", edges[i].before, key, edges[i].after, id);
        expect_extraction(detector, input, strlen(input), one, edges[i].matches ? 1 : 0);
    }
    snprintf(input, sizeof(input), "%.29s\n%s", key, id);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[15] = '-';
    snprintf(input, sizeof(input), "%s\n%s", changed, id);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(changed, 'A', 30);
    changed[30] = '\0';
    const expected_pair low_entropy[] = {{changed, id}};
    snprintf(input, sizeof(input), "%s\n%s", changed, id);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "%s\n%s", changed, id);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);

    for (size_t suffix = 17; suffix <= 21; ++suffix) {
        memcpy(changed_id, "LTAI", 4);
        test_secret(changed_id + 4, suffix, 0);
        const expected_pair sized[] = {{key, changed_id}};
        snprintf(input, sizeof(input), "%s\n%s\"';\r\n", key, changed_id);
        expect_extraction(detector, input, strlen(input), sized, 1);
    }
    snprintf(input, sizeof(input), "%s\n%.20s", key, id);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    const char *invalid_ids[] = {"lTAI0123456789abcdefg", "LTAi0123456789abcdefg",
                                 "_LTAI0123456789abcdefg", "xLTAI0123456789abcdefg"};
    for (size_t i = 0; i < sizeof(invalid_ids) / sizeof(invalid_ids[0]); ++i) {
        snprintf(input, sizeof(input), "%s\n%s", key, invalid_ids[i]);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    const expected_pair longest[] = {{key, other_id}};
    snprintf(input, sizeof(input), "%s\n%s_tail", key, other_id);
    expect_extraction(detector, input, strlen(input), longest, 1); /* No right ID boundary. */
    snprintf(changed_id, sizeof(changed_id), "%sABCDE", other_id);
    const expected_pair overlap[] = {{key, other_id}, {changed_id, other_id}};
    snprintf(input, sizeof(input), "%s\n%s", key, changed_id);
    expect_extraction(detector, input, strlen(input), overlap, 2); /* Long IDs can also be keys. */

    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\n%s", id);
    expect_extraction(detector, input, strlen(input), one, 1); /* Engine owns the 1024-byte span. */
    memcpy(input, key, 30);
    input[30] = '\0';
    memcpy(input + 31, id, sizeof(id) - 1);
    expect_extraction(detector, input, 31 + sizeof(id) - 1, one, 1);
}

/* Independent Python stdlib HMAC-SHA1/Base64/form-encoding goldens. */
static const struct {
    const char *key, *id, *encoded_signature, *query_length;
} signing_vectors[] = {
    {key, id, "dPFlD3cQUZGpfiJoe3oRT5xXcgo%3D", "242"},
    {key, other_id, "x%2FtsJ6ciNuZJDX1uflgwvZxUOOQ%3D", "248"},
    {other_key, id, "La8VpIVI%2F0V5AGuzgL7TzOw9IQA%3D", "244"},
    {other_key, other_id, "Wx6tOZbE2Yfnc2kz6JRF5aNmnJQ%3D", "246"},
};
typedef struct { const expected_pair *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const expected_pair pair = expected->pairs[http->calls - 1];
    size_t i;
    for (i = 0; i < sizeof(signing_vectors) / sizeof(signing_vectors[0]); ++i)
        if (!strcmp(pair.key, signing_vectors[i].key) && !strcmp(pair.id, signing_vectors[i].id)) break;
    CHECK(i < sizeof(signing_vectors) / sizeof(signing_vectors[0]));
    char url[512];
    snprintf(url, sizeof(url), "https://ecs.aliyuncs.com?AccessKeyId=%s&Action=DescribeRegions&Format=JSON&Signature=%s"
             "&SignatureMethod=HMAC-SHA1&SignatureNonce=0123456789abcd23&SignatureVersion=1.0"
             "&Timestamp=2020-01-02T03%%3A04%%3A05Z&Version=2014-05-26",
             pair.id, signing_vectors[i].encoded_signature);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 0); /* A real protobuf detector ID, not an unset sentinel. */
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "text/xml;charset=utf-8"));
    CHECK(!strcmp(request->headers[1].name, "Content-Length"));
    CHECK(!strcmp(request->headers[1].value, signing_vectors[i].query_length));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog alibaba-test"));
}

static void test_ordered_pairs(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "%s\n%s\n%s\n%s\n%s\n%s", other_id, other_key, id, key, other_id, other_key);
    const expected_pair pairs[] = {
        {other_key, other_id}, {other_key, id}, {other_key, other_id},
        {key, other_id}, {key, id}, {key, other_id},
        {other_key, other_id}, {other_key, id}, {other_key, other_id},
    };
    expect_extraction(detector, input, strlen(input), pairs, 9);
    expected_requests expected = {pairs, 9};
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{}", 2}},
                       .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "alibaba-test"};
    clock_calls = random_calls = 0;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 9 && http.calls == 9 && http.releases == 9);
    CHECK(clock_calls == 9 && random_calls == 9);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http.calls = http.releases = 0;
    http.send_rc = -1;
    http.send_error = "context canceled";
    clock_calls = random_calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 9 && http.calls == 9 && http.releases == 9);
    CHECK(clock_calls == 9 && random_calls == 9);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, "context canceled"));
    }
    br_results_clear(&results);
}

typedef struct {
    int status;
    const char *body, *body_error, *send_error;
    int send_rc;
    bool verified;
    const char *error;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[96];
    snprintf(input, sizeof(input), "%s\n%s", key, id);
    const expected_pair pair[] = {{key, id}};
    expected_requests expected = {pair, 1};
    test_http http = {
        .response = {.status = fixture.status,
                     .body = {(const unsigned char *)fixture.body, fixture.body ? strlen(fixture.body) : 0},
                     .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "alibaba-test"};
    clock_calls = random_calls = 0;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    CHECK(clock_calls == 1 && random_calls == 1);
    check_pair(&results.items[0], pair[0]);
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
        CHECK(!strstr(results.items[0].verification_error, key));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    const verification_case cases[] = {
        {.status = 200, .body = "{}", .verified = true},
        {.status = 200, .body = "null", .verified = true},
        {.status = 200, .body = "{\"RequestId\":\"r\",\"Message\":\"m\",\"Recommend\":\"r\",\"HostId\":\"h\",\"Code\":\"c\"}", .verified = true},
        {.status = 200, .body = "{\"Message\":null,\"Code\":null,\"unknown\":[1,true,{}]}", .verified = true},
        {.status = 400, .body = "{}"}, {.status = 404, .body = "null"},
        {.status = 401, .body = "{}", .error = "unexpected HTTP response status 401"},
        {.status = 403, .body = "{\"Message\":\"denied\",\"Code\":\"InvalidSignature\"}",
         .error = "unexpected HTTP response status 403: denied, InvalidSignature"},
        {.status = 500, .body = "{\"Message\":\"retry\"}", .error = "unexpected HTTP response status 500: retry, "},
        {.status = 201, .body = "{\"Message\":\"\",\"Code\":\"ignored\"}", .error = "unexpected HTTP response status 201"},
        {.status = 200, .body = "{\"RequestId\":7}", .error = "json: cannot unmarshal number into Go struct field alibabaResp.RequestId of type string"},
        {.status = 400, .body = "{\"Message\":false}", .error = "json: cannot unmarshal bool into Go struct field alibabaResp.Message of type string"},
        {.status = 404, .body = "{\"Recommend\":[]}", .error = "json: cannot unmarshal array into Go struct field alibabaResp.Recommend of type string"},
        {.status = 401, .body = "{\"HostId\":{}}", .error = "json: cannot unmarshal object into Go struct field alibabaResp.HostId of type string"},
        {.status = 403, .body = "{\"Code\":7}", .error = "json: cannot unmarshal number into Go struct field alibabaResp.Code of type string"},
        {.status = 200, .body = "[]", .error = "json: cannot unmarshal array into Go value of type alibaba.alibabaResp"},
        {.status = 200, .body = "\"text\"", .error = "json: cannot unmarshal string into Go value of type alibaba.alibabaResp"},
        {.status = 400, .body = "!", .error = "invalid character '!' looking for beginning of value"},
        {.status = 404, .body = "", .error = "EOF"},
        {.status = 200, .body = " \t\r\n", .error = "EOF"},
        {.status = 200, .body = "{\"Message\":", .error = "unexpected EOF"},
        {.status = 200, .body = "{\"Code\":7,\"Code\":\"later\"}", .error = "json: cannot unmarshal number into Go struct field alibabaResp.Code of type string"},
        {.status = 500, .body = "{\"Message\":\"first\",\"MESSAGE\":\"last\",\"Message\":null,\"Code\":\"C\",\"Code\":null}",
         .error = "unexpected HTTP response status 500: last, C"},
        {.status = 200, .body = "{}not-json", .verified = true},
        {.status = 500, .body = "{\"Message\":\"first\"}{\"Message\":\"second\"}", .error = "unexpected HTTP response status 500: first, "},
        {.status = 200, .body = "{}", .body_error = "ignored after complete document", .verified = true},
        {.status = 400, .body = "null ", .body_error = "ignored after complete document"},
        {.status = 200, .body = "{", .body_error = "body read failed", .error = "body read failed"},
        {.status = 200, .body_error = "body read failed", .error = "body read failed"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    char cause[160], redacted[160], body[200];
    snprintf(cause, sizeof(cause), "key=%s id=%s repeated=%s", key, id, key);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] id=%s repeated=[REDACTED]", id);
    verify_case(detector, (verification_case){.status = 200, .send_rc = -1, .send_error = cause, .error = redacted});
    verify_case(detector, (verification_case){.status = 404, .body = "{", .body_error = cause, .error = redacted});
    snprintf(body, sizeof(body), "{\"Message\":\"key=%s\",\"Code\":\"%s\"}", key, id);
    snprintf(redacted, sizeof(redacted), "unexpected HTTP response status 500: key=[REDACTED], %s", id);
    verify_case(detector, (verification_case){.status = 500, .body = body, .error = redacted});

    br_scan_ctx offline = {0};
    snprintf(body, sizeof(body), "%s\n%s", key, id);
    br_results results = test_scan(detector, &offline, true, body, strlen(body));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_pair(&results.items[0], (expected_pair){key, id});
    br_results_clear(&results);
}

static void test_random_failure(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "%s\n%s\n%s", key, id, other_id);
    const expected_pair pairs[] = {{key, id}, {key, other_id}};
    const int failures[] = {0, -1};
    for (size_t f = 0; f < sizeof(failures) / sizeof(failures[0]); ++f) {
        test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{}", 2}}};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        clock_calls = random_calls = 0;
        random_result = failures[f];
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 2 && !http.calls && !http.releases);
        CHECK(clock_calls == 2 && random_calls == 2);
        for (size_t i = 0; i < results.len; ++i) {
            check_pair(&results.items[i], pairs[i]);
            CHECK(!results.items[i].verified && results.items[i].verification_error);
            CHECK(!strcmp(results.items[i].verification_error, "cannot construct Alibaba signed request"));
        }
        br_results_clear(&results);
    }
    random_result = 1;
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *state = detector->state;
    CHECK(strlen(key) == 30 && strlen(other_key) == 30 && strlen(id) == 21 && strlen(other_id) == 25);
    test_extraction(detector);
    test_ordered_pairs(detector);
    test_random_failure(detector);
    test_verification(detector);
    const br_detector *again = NULL;
    CHECK(br_alibaba_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("Alibaba");
}
