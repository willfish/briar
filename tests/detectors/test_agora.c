/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic values, also used by the independent Basic-auth golden below. */
static const char key[] = "0123456789abcdef0123456789abcdef";
static const char secret[] = "fedcba9876543210fedcba9876543210";
typedef struct { const char *key, *secret; } expected_pair;

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 197 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, pair.key, 32));
    CHECK(result->raw_v2.len == 64 && !memcmp(result->raw_v2.data, pair.key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, pair.secret, 32));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_is_type(result->secret_parts, json_type_object));
    CHECK(json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.secret));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_agora_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_agora_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 197 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Agora") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Agora is a real-time engagement platform providing APIs for voice, video, "
                  "and messaging. Agora API keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "agora"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_detector_is_default(detector, NULL));
    CHECK(br_agora_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_agora_init(NULL, NULL) != 0);
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

static void test_extraction(const br_detector *detector)
{
    char input[2048], changed[33];
    const expected_pair one[] = {{key, secret}};
    /* Direct scans accept key/token + secret without the engine's "agora" keyword. */
    snprintf(input, sizeof(input), "key %s\nsecret %s", key, secret);
    CHECK(!strstr(input, "agora"));
    expect_extraction(detector, input, strlen(input), one, 1);
    expect_extraction(detector, NULL, 0, NULL, 0);
    const struct { const char *format; bool matches; } cases[] = {
        {"token %s\nsecret %s", true},
        {"agora %s\nsecret %s", true},
        {"key %s\nagora %s", true},
        {"monKEY:%s\npreSECRETAsuffix:%s", true},
        {"preToKeNsuffix=%s\nSECRET:%s", true},
        {"key '%s'\nsecret '%s'", true},
        {"key\r\n%s\nsecret\r\n%s", true},
        {"key \xc3\xa9%s\xc3\xa9\nsecret %s", true},
        {"%s\n%s", false},
        {"key %s\n%s", false},
        {"%s\nsecret %s", false},
        {"key%s\nsecret %s", false},
        {"key %s\nsecret%s", false},
        {"key _%s\nsecret %s", false},
        {"key %s_\nsecret %s", false},
        {"key %s\nsecret _%s", false},
        {"key %s\nsecret %s_", false},
        {"key %sx\nsecret %s", false},
        {"key %s\nsecret %sx", false},
        {"key %.31s\nsecret %s", false},
        {"key %s\nsecret %.31s", false},
        {"agora %s %s", false}, /* Each independent pattern consumes its first match. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key, secret);
        expect_extraction(detector, input, strlen(input), one, cases[i].matches ? 1 : 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "key", 3);
        memset(input + 3, '-', gap);
        snprintf(input + 3 + gap, sizeof(input) - 3 - gap, "%s\nsecret %s", key, secret);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + 3, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);

        size_t at = (size_t)snprintf(input, sizeof(input), "key %s\nsecret", key);
        memset(input + at, '-', gap);
        memcpy(input + at + gap, secret, sizeof(secret));
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        memset(input + at, '\r', gap);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);

        memcpy(input, "key", 3);
        at = 3;
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        snprintf(input + at, sizeof(input) - at, "%s\nsecret %s", key, secret);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    const char invalid[] = {'A', '%'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[16] = invalid[i];
        snprintf(input, sizeof(input), "key %s\nsecret %s", changed, secret);
        expect_extraction(detector, input, strlen(input), NULL, 0);
        memcpy(changed, secret, sizeof(changed));
        changed[16] = invalid[i];
        snprintf(input, sizeof(input), "key %s\nsecret %s", key, changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const expected_pair low_entropy[] = {{changed, secret}};
    snprintf(input, sizeof(input), "key %s\nsecret %s", changed, secret);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "key %s\nsecret %s", changed, secret);
    expect_extraction(detector, input, strlen(input), low_entropy, 1);

    size_t at = (size_t)snprintf(input, sizeof(input), "key %s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\nsecret %s", secret);
    expect_extraction(detector, input, strlen(input), one, 1); /* Span limits belong to the engine. */
    memcpy(input, "key\0", 4);
    at = 4 + (size_t)snprintf(input + 4, sizeof(input) - 4, "%s\nsecret %s", key, secret);
    expect_extraction(detector, input, at, one, 1);
}

typedef struct { const expected_pair *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const expected_pair pair = expected->pairs[http->calls - 1];
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.agora.io/dev/v1/projects"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 197);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    char *auth = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)pair.secret, 32},
                             (br_slice){(const unsigned char *)pair.key, 32}, &auth, &error) == 0);
    CHECK(auth && !error && !strcmp(request->headers[0].value, auth));
    if (!strcmp(pair.key, key) && !strcmp(pair.secret, secret)) {
        CHECK(!strcmp(request->headers[0].value,
            "Basic ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA6MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="));
    }
    free(auth);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog agora-test"));
}

static void test_ordered_pairs(const br_detector *detector)
{
    char input[512], other_key[33], other_secret[33];
    test_secret(other_key, 32, 0);
    test_secret(other_secret, 32, 9);
    snprintf(input, sizeof(input), "secret %s\nkey %s\ntoken %s\nsecret %s",
             secret, key, other_key, other_secret);
    const expected_pair product[] = {
        {key, secret}, {key, other_secret}, {other_key, secret}, {other_key, other_secret},
    };
    expect_extraction(detector, input, strlen(input), product, 4);
    expected_requests expected = {product, 4};
    test_http http = {.response = {.status = 201}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "agora-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], product[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    snprintf(input, sizeof(input), "agora %s\nagora %s\nagora %s", key, key, secret);
    const expected_pair repeated[] = {{key, secret}, {key, secret}, {secret, key}, {secret, key}};
    expect_extraction(detector, input, strlen(input), repeated, 4);
    expected = (expected_requests){repeated, 4};
    http = (test_http){.send_rc = -1, .send_error = "context canceled",
                       .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], repeated[i]);
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, "context canceled"));
    }
    br_results_clear(&results);

    http = (test_http){0};
    snprintf(input, sizeof(input), "token %s\nsecret %s", key, key);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "agora %s\nagora %s", key, key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    char input[128], transport_error[160], redacted[160];
    snprintf(input, sizeof(input), "key %s\nsecret %s", key, secret);
    snprintf(transport_error, sizeof(transport_error), "key=%s secret=%s key-again=%s", key, secret, key);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] secret=%s key-again=[REDACTED]", secret);
    const expected_pair pair[] = {{key, secret}};
    expected_requests expected = {pair, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {201, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {204, 0, NULL, false, "unexpected HTTP response status 204"},
        {500, 0, NULL, false, "unexpected HTTP response status 500"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {201, -1, "context canceled", false, "context canceled"},
        {200, -1, NULL, false, "HTTP transport failed"},
        {200, -1, transport_error, false, redacted},
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
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "agora-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_pair(&results.items[0], pair[0]);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(results.items[0].verification_error);
            CHECK(!strcmp(results.items[0].verification_error, cases[i].error));
            CHECK(!strstr(results.items[0].verification_error, key));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_pair(&results.items[0], pair[0]);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const void *state = detector->state;
    test_extraction(detector);
    test_ordered_pairs(detector);
    test_verification(detector);
    const br_detector *again = NULL;
    CHECK(br_agora_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("Agora");
}
