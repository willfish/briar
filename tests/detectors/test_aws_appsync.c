/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <strings.h>

static char key[31], other_key[31], label[27], other_label[27];
static char base[128], other_base[128], endpoint[144], other_endpoint[144];

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aws_appsync_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_aws_appsync_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 1052 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AWSAppSync") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AWS AppSync is a managed GraphQL service. This detector identifies exposed AppSync API keys."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "da2-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, const char *url)
{
    size_t len = strlen(url);
    CHECK(result->detector_type == 1052 && !result->detector_name);
    CHECK(result->raw.len == 30 && !memcmp(result->raw.data, secret, 30));
    CHECK(result->raw_v2.data && result->raw_v2.len == len + 31);
    CHECK(!memcmp(result->raw_v2.data, url, len) && result->raw_v2.data[len] == ':');
    CHECK(!memcmp(result->raw_v2.data + len + 1, secret, 30));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), secret));
    CHECK(json_object_object_get_ex(result->secret_parts, "endpoint", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), url));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "base_url", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), url));
    CHECK(!result->redacted && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void expect_one(const br_detector *detector, const char *input, const char *secret, const char *url)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (secret ? 1u : 0u) && !http.calls && !http.releases);
    if (secret) {
        check_result(&results.items[0], secret, url);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed[128], url[256], normalized[272];
    snprintf(input, sizeof(input), "%s %s", key, base);
    expect_one(detector, input, key, endpoint); /* Direct pattern, no provider prefix. */
    snprintf(input, sizeof(input), "%s %s", base, key);
    expect_one(detector, input, key, endpoint);
    expect_one(detector, "", NULL, NULL);
    expect_one(detector, key, NULL, NULL);
    expect_one(detector, base, NULL, NULL);
    const char *invalid_keys[] = {"x%s", "_%s", "%s_", "%.29s", "%sa"};
    for (size_t i = 0; i < sizeof(invalid_keys) / sizeof(invalid_keys[0]); ++i) {
        snprintf(changed, sizeof(changed), invalid_keys[i], key);
        snprintf(input, sizeof(input), "%s %s", changed, base);
        expect_one(detector, input, NULL, NULL);
    }
    const char invalid_chars[] = {'A', '_', '-'};
    for (size_t i = 0; i < sizeof(invalid_chars); ++i) {
        memcpy(changed, key, sizeof(key));
        changed[12] = invalid_chars[i];
        snprintf(input, sizeof(input), "%s %s", changed, base);
        expect_one(detector, input, NULL, NULL);
    }
    memcpy(changed, key, sizeof(key));
    changed[0] = 'D';
    snprintf(input, sizeof(input), "%s %s", changed, base);
    expect_one(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "-%s-\r\n%s", key, base);
    expect_one(detector, input, key, endpoint);

    const char *accepted_suffixes[] = {"", "/graphql", "/other/path?x=1", "_suffix", "?query", "#fragment", ";"};
    for (size_t i = 0; i < sizeof(accepted_suffixes) / sizeof(accepted_suffixes[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s%s", key, base, accepted_suffixes[i]);
        expect_one(detector, input, key, endpoint); /* Only group 1, then exactly one /graphql. */
    }
    const char *rejected_suffixes[] = {".evil", "-evil", "a", "0"};
    for (size_t i = 0; i < sizeof(rejected_suffixes) / sizeof(rejected_suffixes[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s%s", key, base, rejected_suffixes[i]);
        expect_one(detector, input, NULL, NULL);
    }
    snprintf(input, sizeof(input), "%s prefix%s", key, base);
    expect_one(detector, input, key, endpoint); /* Endpoint pattern has no leading boundary. */
    const char *bad_urls[] = {
        "http://%s.appsync-api.us-east-1.amazonaws.com",
        "HTTPS://%s.appsync-api.us-east-1.amazonaws.com",
        "https://%s.APPSYNC-api.us-east-1.amazonaws.com",
        "https://%s.appsync-api.US-east-1.amazonaws.com",
        "https://%s.appsync-api.us-east-1.amazonaws.COM",
    };
    for (size_t i = 0; i < sizeof(bad_urls) / sizeof(bad_urls[0]); ++i) {
        snprintf(url, sizeof(url), bad_urls[i], label);
        snprintf(input, sizeof(input), "%s %s", key, url);
        expect_one(detector, input, NULL, NULL);
    }
    snprintf(url, sizeof(url), "https://%.25s.appsync-api.us-east-1.amazonaws.com", label);
    snprintf(input, sizeof(input), "%s %s", key, url);
    expect_one(detector, input, NULL, NULL);
    snprintf(url, sizeof(url), "https://%sa.appsync-api.us-east-1.amazonaws.com", label);
    snprintf(input, sizeof(input), "%s %s", key, url);
    expect_one(detector, input, NULL, NULL);
    snprintf(url, sizeof(url), "%s", base);
    url[8] = 'B';
    snprintf(input, sizeof(input), "%s %s", key, url);
    expect_one(detector, input, NULL, NULL);
    snprintf(url, sizeof(url), "https://%s.appsync-api.zone--9.amazonaws.com", label);
    snprintf(normalized, sizeof(normalized), "%s/graphql", url);
    snprintf(input, sizeof(input), "%s %s", key, url);
    expect_one(detector, input, key, normalized); /* Source has no region catalogue. */

    snprintf(input, sizeof(input), "%s %s%s", key, base, other_base);
    expect_one(detector, input, key, other_endpoint); /* No delimiter: first URL cannot match. */
    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", key);
    memset(input + at, ' ', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "%s", base);
    expect_one(detector, input, key, endpoint); /* Credential span belongs to the engine. */
}

typedef struct {
    const char *keys[2], *endpoints[2];
    size_t nkeys, nendpoints, seen[2][2];
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    static const char query[] = "{\"query\":\"query { __typename }\"}";
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 1052 && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->body.len == sizeof(query) - 1 && !memcmp(request->body.data, query, sizeof(query) - 1));
    CHECK(request->nheaders == 3);
    CHECK(!strcasecmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcasecmp(request->headers[1].name, "x-api-key"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog appsync-test"));
    size_t k = 0, e = 0;
    while (k < expected->nkeys && strcmp(request->headers[1].value, expected->keys[k])) ++k;
    while (e < expected->nendpoints && strcmp(request->url, expected->endpoints[e])) ++e;
    CHECK(k < expected->nkeys && e < expected->nendpoints);
    ++expected->seen[k][e];
}

#define BODY(text) {(const unsigned char *)(text), sizeof(text) - 1}

typedef struct {
    int status, send_rc;
    br_slice body;
    const char *body_error, *send_error, *error;
    bool verified;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[256];
    snprintf(input, sizeof(input), "%s %s", key, base);
    requests expected = {.keys = {key}, .endpoints = {endpoint}, .nkeys = 1, .nendpoints = 1};
    test_http http = {.response = {.status = fixture.status, .body = fixture.body, .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "appsync-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.seen[0][0] == 1);
    check_result(&results.items[0], key, endpoint);
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const verification_case cases[] = {
        {.status = 200, .verified = true},
        {.status = 200, .body = BODY("{\"errors\":[\"invalid key\"]}"), .body_error = "ignored", .verified = true},
        {.status = 502, .body = BODY("No schema definition exists"), .verified = true},
        {.status = 502, .body = BODY("\0No schema definition exists\xff"), .verified = true},
        {.status = 502, .body = BODY("prefix No schema definition exists suffix"), .verified = true},
        {.status = 502, .body = BODY("no schema definition exists"), .error = "502 Bad Gateway: unexpected response"},
        {.status = 502, .error = "502 Bad Gateway: unexpected response"},
        {.status = 502, .body = BODY("No schema definition exists"), .body_error = "read failed", .error = "read failed"},
        {.status = 401, .body = BODY("No schema definition exists"), .body_error = "ignored"},
        {.status = 403, .body = BODY("No schema definition exists"), .body_error = "ignored"},
        {.status = 201, .body_error = "ignored", .error = "unexpected HTTP response status 201"},
        {.status = 302, .error = "unexpected HTTP response status 302"},
        {.status = 404, .body_error = "ignored", .error = "unexpected HTTP response status 404"},
        {.status = 500, .error = "unexpected HTTP response status 500"},
        {.send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.send_rc = -1, .send_error = "lookup synthetic: no such host", .error = "lookup synthetic: no such host"},
        {.send_rc = -1, .send_error = "unsupported: redirects for native HTTP POST", .error = "unsupported: redirects for native HTTP POST"},
        {.send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    char cause[384], redacted[384];
    snprintf(cause, sizeof(cause), "key=%s endpoint=%s repeat=%s other=%s", key, endpoint, key, other_key);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] endpoint=%s repeat=[REDACTED] other=%s", endpoint, other_key);
    verify_case(detector, (verification_case){.send_rc = -1, .send_error = cause, .error = redacted});
    verify_case(detector, (verification_case){.status = 502, .body = BODY("No schema definition exists"), .body_error = cause, .error = redacted});
    char input[256];
    snprintf(input, sizeof(input), "%s %s", key, base);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_result(&results.items[0], key, endpoint);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void unique_pairs(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "%s %s %s\n%s\n%s/graphql\n%s/other", key, other_key, key, base, base, other_base);
    requests expected = {.keys = {key, other_key}, .endpoints = {endpoint, other_endpoint}, .nkeys = 2, .nendpoints = 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "appsync-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && !http.calls && !http.releases);
    bool seen[2][2] = {{false}};
    for (size_t r = 0; r < results.len; ++r) {
        size_t k = !memcmp(results.items[r].raw.data, key, 30) ? 0 : 1;
        br_json *value = NULL;
        CHECK(json_object_object_get_ex(results.items[r].secret_parts, "endpoint", &value));
        const char *url = json_object_get_string(value);
        CHECK(!strcmp(url, endpoint) || !strcmp(url, other_endpoint));
        size_t e = !strcmp(url, endpoint) ? 0 : 1;
        CHECK(!seen[k][e]);
        seen[k][e] = true;
        check_result(&results.items[r], expected.keys[k], expected.endpoints[e]);
        CHECK(!results.items[r].verified && !results.items[r].verification_error);
    }
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t k = 0; k < 2; ++k)
        for (size_t e = 0; e < 2; ++e) CHECK(expected.seen[k][e] == 1);
    for (size_t r = 0; r < results.len; ++r) CHECK(results.items[r].verified && !results.items[r].verification_error);
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(!results.len && !http.calls && !http.releases); /* Never invent an endpoint or verify a key alone. */
    br_results_clear(&results);
}

int main(void)
{
    memcpy(key, "da2-", 4);
    memcpy(other_key, "da2-", 4);
    test_secret(key + 4, 26, 0);
    test_secret(other_key + 4, 26, 9);
    test_secret(label, 26, 17);
    test_secret(other_label, 26, 25);
    snprintf(base, sizeof(base), "https://%s.appsync-api.us-east-1.amazonaws.com", label);
    snprintf(other_base, sizeof(other_base), "https://%s.appsync-api.eu-west-1.amazonaws.com", other_label);
    snprintf(endpoint, sizeof(endpoint), "%s/graphql", base);
    snprintf(other_endpoint, sizeof(other_endpoint), "%s/graphql", other_base);
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    unique_pairs(detector);
    return test_finish("AWSAppSync");
}
