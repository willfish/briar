/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[33], other_key[33], secret[17], other_secret[17];
typedef struct { const char *key, *secret; } expected_pair;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_amadeus_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_amadeus_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_amadeus_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 453 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Amadeus") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Amadeus provides travel technology solutions. "
        "Amadeus API keys can be used to access and modify travel-related data and services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "amadeus"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 453 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, pair.key, 32));
    CHECK(result->raw_v2.len == 48 && !memcmp(result->raw_v2.data, pair.key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, pair.secret, 16));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.secret));
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const char *input, bool found,
                               expected_pair pair)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == (found ? 1u : 0u) && !http.calls && !http.releases);
    if (found) {
        check_pair(&results.items[0], pair);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed_key[33], changed_secret[17];
    expected_pair one = {key, secret};
    snprintf(input, sizeof(input), "amadeus %s\namadeus %s", key, secret);
    expect_extraction(detector, input, true, one);
    expect_extraction(detector, NULL, false, one);
    snprintf(input, sizeof(input), "%s %s", key, secret);
    expect_extraction(detector, input, false, one);
    snprintf(input, sizeof(input), "amadeus %s", key);
    expect_extraction(detector, input, false, one);
    snprintf(input, sizeof(input), "amadeus %s", secret);
    expect_extraction(detector, input, false, one);
    snprintf(input, sizeof(input), "amadeus %s %s", key, secret);
    expect_extraction(detector, input, true, one);
    snprintf(input, sizeof(input), "amadeus %s\namadeus %s", secret, key);
    expect_extraction(detector, input, true, one);
    snprintf(input, sizeof(input), "preAMADEUSsuffix:%s\namadeus\r\n%s", key, secret);
    expect_extraction(detector, input, true, one);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "amadeus");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s\namadeus %s", key, secret);
        expect_extraction(detector, input, gap == 40, one);
        at = (size_t)snprintf(input, sizeof(input), "amadeus %s\namadeus", key);
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", secret);
        expect_extraction(detector, input, gap == 40, one);
    }
    const struct { const char *before, *after; } edges[] = {{"_", ""}, {"", "_"}, {"", "Q"}};
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "amadeus %s%s%s\namadeus %s", edges[i].before, key, edges[i].after, secret);
        expect_extraction(detector, input, false, one);
        snprintf(input, sizeof(input), "amadeus %s\namadeus %s%s%s", key, edges[i].before, secret, edges[i].after);
        expect_extraction(detector, input, false, one);
    }
    snprintf(input, sizeof(input), "amadeus %.31s\namadeus %s", key, secret);
    expect_extraction(detector, input, false, one);
    snprintf(input, sizeof(input), "amadeus %s\namadeus %.15s", key, secret);
    expect_extraction(detector, input, false, one);
    memcpy(changed_key, key, sizeof(changed_key));
    changed_key[7] = '-';
    snprintf(input, sizeof(input), "amadeus %s\namadeus %s", changed_key, secret);
    expect_extraction(detector, input, false, one);
    memcpy(changed_secret, secret, sizeof(changed_secret));
    changed_secret[7] = '%';
    snprintf(input, sizeof(input), "amadeus %s\namadeus %s", key, changed_secret);
    expect_extraction(detector, input, false, one);
    memset(changed_key, 'a', 32);
    changed_key[32] = '\0';
    memset(changed_secret, 'a', 16);
    changed_secret[16] = '\0';
    snprintf(input, sizeof(input), "amadeus %s\namadeus %s", changed_key, changed_secret);
    expect_extraction(detector, input, true, (expected_pair){changed_key, changed_secret});
    size_t at = (size_t)snprintf(input, sizeof(input), "amadeus %s\n", key);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\namadeus %s", secret);
    expect_extraction(detector, input, true, one); /* No detector-local span restriction. */
}

typedef struct { const expected_pair *pairs; size_t count; unsigned seen; } requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://test.api.amadeus.com/v1/security/oauth2/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 453);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") &&
          !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog amadeus-test"));
    CHECK(expected->count <= 4 && request->body.data);
    size_t match = 0;
    for (; match < expected->count; ++match) {
        char form[128];
        snprintf(form, sizeof(form), "grant_type=client_credentials&client_id=%s&client_secret=%s",
                 expected->pairs[match].key, expected->pairs[match].secret);
        if (request->body.len == strlen(form) && !memcmp(request->body.data, form, strlen(form))) break;
    }
    CHECK(match < expected->count && !(expected->seen & (1u << match)));
    expected->seen |= 1u << match;
}

static void verification(const br_detector *detector)
{
    static const unsigned char json[] = "{\"access_token\":\"synthetic\"}";
    static const unsigned char non_json[] = "not JSON: access_token suffix";
    static const unsigned char binary[] = "before\0after access_token";
    static const unsigned char wrong_case[] = "ACCESS_TOKEN";
    static const unsigned char incomplete[] = "access_toke";
    const struct {
        int status, send_rc;
        br_slice body;
        const char *body_error, *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {.status = 200, .body = {json, sizeof(json) - 1}, .verified = true},
        {.status = 200, .body = {non_json, sizeof(non_json) - 1}, .verified = true},
        {.status = 200, .body = {binary, sizeof(binary) - 1}, .verified = true},
        {.status = 200, .body = {wrong_case, sizeof(wrong_case) - 1}},
        {.status = 200, .body = {incomplete, sizeof(incomplete) - 1}},
        {.status = 200},
        {.status = 200, .body = {binary, sizeof(binary) - 1}, .body_error = "body read failed", .error = "body read failed"},
        {.status = 401, .body = {json, sizeof(json) - 1}, .body_error = "ignored"},
        {.status = 403, .body_error = "ignored"},
        {.status = 201, .body_error = "ignored", .error = "unexpected status code: 201"},
        {.status = 500, .body_error = "ignored", .error = "unexpected status code: 500"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
    };
    char input[256];
    snprintf(input, sizeof(input), "amadeus %s\namadeus %s\namadeus %s\namadeus %s", key, secret, key, secret);
    const expected_pair pair = {key, secret};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        requests expected = {&pair, 1, 0};
        test_http http = {
            .response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "amadeus-test"};
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

static void unique_pairing(const br_detector *detector)
{
    char input[512], cause[256];
    snprintf(input, sizeof(input), "amadeus %s\namadeus %s\namadeus %s\namadeus %s\namadeus %s\namadeus %s",
             secret, other_key, other_secret, key, secret, other_key);
    const expected_pair pairs[] = {{key, secret}, {key, other_secret}, {other_key, secret}, {other_key, other_secret}};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "amadeus-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        CHECK(results.items[i].raw.len == 32 && results.items[i].raw_v2.len == 48);
        const char *first = !memcmp(results.items[i].raw.data, key, 32) ? key : other_key;
        const char *second = !memcmp(results.items[i].raw_v2.data + 32, secret, 16) ? secret : other_secret;
        check_pair(&results.items[i], (expected_pair){first, second});
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        for (size_t j = 0; j < i; ++j) CHECK(memcmp(results.items[i].raw_v2.data, results.items[j].raw_v2.data, 48) != 0);
    }
    br_results_clear(&results);
    snprintf(cause, sizeof(cause), "key=%s secret=%s key-again=%s secret-again=%s", key, secret, key, secret);
    static const unsigned char body[] = "\0access_token";
    for (int mode = 0; mode < 3; ++mode) {
        requests expected = {pairs, 4, 0};
        http = (test_http){
            .response = {.status = 200, .body = {body, sizeof(body) - 1}, .body_error = mode == 2 ? cause : NULL},
            .send_rc = mode == 1 ? -1 : 0, .send_error = mode == 1 ? cause : NULL,
            .inspect = inspect_request, .user = &expected,
        };
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 4 && http.calls == 4 && http.releases == 4 && expected.seen == 15);
        for (size_t i = 0; i < results.len; ++i) {
            CHECK(results.items[i].verified == (mode == 0));
            if (mode) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, cause));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "amadeus", 7);
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other_key, 32, 9);
    test_secret(secret, 16, 3);
    test_secret(other_secret, 16, 17);
    key[0] = 'B';
    other_key[0] = 'M';
    secret[0] = 'Z';
    other_secret[0] = 'Q';
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    unique_pairing(detector);
    return test_finish("Amadeus");
}
