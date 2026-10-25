/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *key, *id; } credential;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_adobeio_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_adobeio_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 136 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AdobeIO") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AdobeIO provides APIs for integrating with Adobe services. These credentials can be used to access Adobe services and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "adobe"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(!br_detector_is_default(detector, NULL));
    return detector;
}

static void check_pair(const br_result *result, credential expected)
{
    size_t key_len = strlen(expected.key), id_len = strlen(expected.id);
    CHECK(result->detector_type == 136 && !result->detector_name);
    CHECK(result->raw.len == key_len && !memcmp(result->raw.data, expected.key, key_len));
    CHECK(result->raw_v2.len == key_len + id_len);
    CHECK(!memcmp(result->raw_v2.data, expected.key, key_len));
    CHECK(!memcmp(result->raw_v2.data + key_len, expected.id, id_len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(!strcmp(json_object_get_string(part), expected.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(!strcmp(json_object_get_string(part), expected.id));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const char *input,
                              const credential *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other,
                        const char *id, const char *other_id)
{
    char input[1536], changed[33];
    const credential one[] = {{key, id}};
    snprintf(input, sizeof(input), "preADOBEsuffix:'%s'\radobe\n%s", key, id);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "adobe %s %s", key, id);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", id, key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, "", NULL, 0);
    snprintf(input, sizeof(input), "%s %s adobe", key, id);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "adobe %s", key);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "adobe %s", id);
    expect_extraction(detector, input, NULL, 0);

    for (int gap = 40; gap <= 41; ++gap) {
        const char *padding = "-----------------------------------------";
        snprintf(input, sizeof(input), "adobe%.*s%s\nadobe %s", gap, padding, key, id);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
        snprintf(input, sizeof(input), "adobe %s\nadobe%.*s%s", key, gap, padding, id);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "adobe %s\n%1100s\nadobe %s", key, "", id);
    expect_extraction(detector, input, one, 1); /* Engine span is not a scanner filter. */

    const char *invalid_keys[] = {"_%s", "%s_", "%sq", "%.31s"};
    for (size_t i = 0; i < sizeof(invalid_keys) / sizeof(invalid_keys[0]); ++i) {
        char token[35];
        snprintf(token, sizeof(token), invalid_keys[i], key);
        snprintf(input, sizeof(input), "adobe %s\nadobe %s", token, id);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[0] = 'B';
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", changed, id);
    expect_extraction(detector, input, NULL, 0);

    const struct { const char *token, *captured; } ids[] = {
        {"ABCD0123wxy", NULL}, {"ABCD0123wxyzq", NULL}, {"ABCD_123wxyz", NULL},
        {".ABCDEFGHIJK", NULL}, {"q.ABCDEFGHIJK", ".ABCDEFGHIJK"},
        {"ABCDEFGHIJK.", NULL}, {"ABCDEFGHIJK.X", "ABCDEFGHIJK."},
    };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); ++i) {
        const credential dotted[] = {{key, ids[i].captured}};
        snprintf(input, sizeof(input), "adobe %s\nadobe %s", key, ids[i].token);
        expect_extraction(detector, input, dotted, ids[i].captured ? 1 : 0);
    }
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const credential low_entropy[] = {{changed, "BBBBBBBBBBBB"}};
    snprintf(input, sizeof(input), "adobe %s\nadobe BBBBBBBBBBBB", changed);
    expect_extraction(detector, input, low_entropy, 1);

    /* Each collection keeps its first occurrence; pairing is not positional. */
    snprintf(input, sizeof(input), "adobe %s\nadobe %s\nadobe %s\nadobe %s\nadobe %s\nadobe %s",
             other_id, other, id, key, other_id, other);
    const credential product[] = {{other, other_id}, {other, id}, {key, other_id}, {key, id}};
    expect_extraction(detector, input, product, 4);
}

typedef struct { const credential *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const credential pair = expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url,
        "https://stock.adobe.io/Rest/Media/1/Search/Files?locale=en_US%2526search_parameters%255Bwords%255D=kittens"));
    CHECK(request->detector_type == 136 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "x-api-key"));
    CHECK(!strcmp(request->headers[0].value, pair.key));
    CHECK(!strcmp(request->headers[1].name, "x-product"));
    CHECK(!strcmp(request->headers[1].value, pair.id));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog adobeio-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                credential pair, bool verified, const char *error)
{
    char input[64];
    snprintf(input, sizeof(input), "adobe %s\nadobe %s", pair.key, pair.id);
    expected_requests expected = {&pair, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "adobeio-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_pair(&results.items[0], pair);
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key, const char *other,
                          const char *id, const char *other_id)
{
    const credential pair = {key, id};
    const struct {
        int status;
        const char *body_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, NULL, true, NULL},
        {200, "ignored drain failure", true, NULL},
        {401, "ignored drain failure", false, NULL},
        {403, "ignored drain failure", false, NULL},
        {201, "ignored drain failure", false, "unexpected status code: 201"},
        {500, "ignored drain failure", false, "unexpected status code: 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = cases[i].body_error}};
        expect_verification(detector, &http, pair, cases[i].verified, cases[i].error);
    }

    test_http http = {.response = {.status = 200}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, pair, false, send_errors[i]);
    }
    /* Synthetic values only: upstream omits BOTH credentials from error redaction. */
    char sensitive_error[128];
    snprintf(sensitive_error, sizeof(sensitive_error), "request %s for %s failed: %s", key, id, key);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, pair, false, sensitive_error);
    http.send_error = NULL;
    expect_verification(detector, &http, pair, false, "HTTP transport failed");

    const credential product[] = {{key, id}, {key, other_id}, {other, id}, {other, other_id}};
    expected_requests expected = {product, 4};
    http = (test_http){.response = {.status = 200, .body_error = "ignored drain failure"},
                       .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "adobeio-test"};
    char input[256];
    snprintf(input, sizeof(input), "adobe %s\nadobe %s\nadobe %s\nadobe %s\nadobe %s\nadobe %s",
             key, id, key, other_id, other, id);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], product[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http.calls = http.releases = 0;
    const char *components[] = {key, id};
    for (size_t i = 0; i < sizeof(components) / sizeof(components[0]); ++i) {
        snprintf(input, sizeof(input), "adobe %s", components[i]);
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(!results.len && !http.calls && !http.releases);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[33], other[33];
    test_secret(key, 32, 0);
    test_secret(other, 32, 9);
    const char *id = "A1b2C3d4.E5F", *other_id = "G6h7J8k9.L0M";
    extraction(detector, key, other, id, other_id);
    verification(detector, key, other, id, other_id);
    return test_finish("AdobeIO");
}
