/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char domain[] = "unit-test00.zz.auth0.com";
static const char other_domain[] = "SYNTHETIC123.A_.auth0.com";
typedef struct { const char *token, *domain; } expected_pair;

/* Opaque synthetic text, not a JWT: one dot, no encoded header or claims. */
static char *make_token(size_t len, size_t shift)
{
    CHECK(len > 54);
    char *token = malloc(len + 1);
    CHECK(token);
    memcpy(token, "ey", 2);
    test_secret(token + 2, len - 2, shift);
    memcpy(token + 50, "._-Q", 4);
    return token;
}

static char *make_input(const char *token, const char *domain_text)
{
    size_t size = strlen(token) + strlen(domain_text) + 2;
    char *input = malloc(size);
    CHECK(input);
    snprintf(input, size, "%s\n%s", token, domain_text);
    return input;
}

static void check_result(const br_result *result, expected_pair pair)
{
    size_t token_len = strlen(pair.token), domain_len = strlen(pair.domain);
    CHECK(result->detector_type == 110 && !result->detector_name);
    CHECK(result->raw.len == token_len && !memcmp(result->raw.data, pair.token, token_len));
    CHECK(result->raw_v2.len == token_len + domain_len && !memcmp(result->raw_v2.data, pair.token, token_len));
    CHECK(!memcmp(result->raw_v2.data + token_len, pair.domain, domain_len));
    CHECK(result->redacted && !strcmp(result->redacted, pair.domain));
    CHECK(!result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.token));
    CHECK(json_object_object_get_ex(result->secret_parts, "domain", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.domain));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_auth0managementapitoken_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_auth0managementapitoken_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 110 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Auth0ManagementApiToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Auth0 provides authentication and authorization as a service. Auth0 Management "
                  "API tokens can be used to manage users, roles, permissions, and other aspects "
                  "of the Auth0 service."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "auth0"));
    CHECK(detector->max_secret_size == 5000 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_auth0managementapitoken_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Auth0 Management API token detector output"));
    free(error);
    CHECK(br_auth0managementapitoken_init(NULL, NULL) != 0);
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

static void test_extraction(const br_detector *detector, const char *token)
{
    const size_t lengths[] = {1999, 2000, 5000, 5001};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        char *candidate = make_token(lengths[i], i);
        char *input = make_input(candidate, domain);
        const expected_pair pair[] = {{candidate, domain}};
        expect_extraction(detector, input, pair, lengths[i] >= 2000 && lengths[i] <= 5000 ? 1 : 0);
        free(input);
        free(candidate);
    }
    const expected_pair one[] = {{token, domain}};
    char *input = make_input(token, domain);
    expect_extraction(detector, input, one, 1); /* No keyword prefix or JWT parsing. */
    size_t size = strlen(input) + 3;
    char *changed = malloc(size);
    CHECK(changed);
    snprintf(changed, size, "_%s", input);
    expect_extraction(detector, changed, NULL, 0);
    snprintf(changed, size, "!%s", input);
    expect_extraction(detector, changed, one, 1);
    memcpy(changed, input, strlen(input) + 1);
    changed[0] = 'E';
    expect_extraction(detector, changed, NULL, 0);
    snprintf(changed, size, "%s-\n%s", token, domain);
    expect_extraction(detector, changed, one, 1); /* Greedy token capture backs up to a word boundary. */
    expect_extraction(detector, token, NULL, 0);
    expect_extraction(detector, domain, NULL, 0);
    expect_extraction(detector, "", NULL, 0);
    free(changed);
    free(input);

    const struct { const char *text, *capture; } domains[] = {
        {"https://unit-test00.zz.auth0.com/path", domain},
        {"Fake-Tenant.A_.auth0.com", "Fake-Tenant.A_.auth0.com"},
        {"prefixABCDEFGHIJKLMNOP.A_1.auth0.comtail", "ABCDEFGHIJKLMNOP.A_1.auth0.com"},
        {"aa.12.auth0.com", "aa.12.auth0.com"},
        {"x.zz.auth0.com", NULL},
        {"unit-test00.z.auth0.com", NULL},
        {"unit-test00.zzzz.auth0.com", NULL},
        {"unit-test00.zz.AUTH0.com", NULL},
    };
    for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); ++i) {
        input = make_input(token, domains[i].text);
        const expected_pair pair[] = {{token, domains[i].capture}};
        expect_extraction(detector, input, pair, domains[i].capture ? 1 : 0);
        free(input);
    }
}

typedef struct { const expected_pair *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const expected_pair pair = expected->pairs[http->calls - 1];
    char url[96];
    snprintf(url, sizeof(url), "https://%s/api/v2/users", pair.domain);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_LOCAL && request->timeout_ms == 10000);
    CHECK(request->detector_type == 110);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == strlen(pair.token) + 7);
    CHECK(!memcmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, pair.token));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog auth0-test"));
}

static void test_occurrence_product(const br_detector *detector, const char *token)
{
    char *other = make_token(2003, 9);
    size_t size = 2 * strlen(token) + strlen(other) + 2 * strlen(domain) + strlen(other_domain) + 6;
    char *input = malloc(size);
    CHECK(input);
    snprintf(input, size, "%s\n%s\n%s\n%s\n%s\n%s", domain, token, other_domain, other, domain, token);
    const expected_pair pairs[] = {
        {token, domain}, {token, other_domain}, {token, domain},
        {other, domain}, {other, other_domain}, {other, domain},
        {token, domain}, {token, other_domain}, {token, domain},
    };
    expect_extraction(detector, input, pairs, 9);
    expected_requests expected = {pairs, 9};
    test_http http = {.response = {.status = 403, .body_error = "ignored body/drain failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "auth0-test"};
    for (size_t failure = 0; failure < 2; ++failure) {
        http.calls = http.releases = 0;
        http.send_rc = failure ? -1 : 0;
        http.send_error = failure ? "context canceled" : NULL;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 9 && http.calls == 9 && http.releases == 9);
        for (size_t i = 0; i < results.len; ++i) {
            check_result(&results.items[i], pairs[i]);
            CHECK(results.items[i].verified == !failure);
            if (failure) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, "context canceled"));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    free(input);
    free(other);
}

typedef struct {
    int status, send_rc;
    const char *send_error, *error, *domain;
    bool verified;
} verification_case;

static void verify_case(const br_detector *detector, const char *token, verification_case fixture)
{
    const expected_pair pair[] = {{token, fixture.domain ? fixture.domain : domain}};
    char *input = make_input(token, pair[0].domain);
    expected_requests expected = {pair, 1};
    static const unsigned char body[] = {0, 0xff, '{'};
    test_http http = {
        .response = {.status = fixture.status, .body = {body, sizeof(body)}, .body_error = "ignored body/drain failure"},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "auth0-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], pair[0]);
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
        CHECK(!strstr(results.items[0].verification_error, token));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    free(input);
}

static void test_verification(const br_detector *detector, const char *token)
{
    const verification_case cases[] = {
        {.status = 200, .verified = true}, {.status = 403, .verified = true}, {.status = 401},
        {.status = 201, .error = "unexpected status code 201"},
        {.status = 400, .error = "unexpected status code 400"},
        {.status = 500, .error = "unexpected status code 500"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 403, .send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, token, cases[i]);
    size_t size = 2 * strlen(token) + strlen(domain) + 96;
    char *cause = malloc(size);
    CHECK(cause);
    snprintf(cause, size, "token=%s domain=%s token-again=%s", token, domain, token);
    char redacted[128];
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] domain=%s token-again=[REDACTED]", domain);
    verify_case(detector, token, (verification_case){.status = 200, .send_rc = -1, .send_error = cause, .error = redacted});
    free(cause); /* The domain stays visible in the error despite being Redacted metadata. */

    char *max_token = make_token(5000, 3);
    verify_case(detector, max_token, (verification_case){.status = 200, .verified = true,
                                                       .domain = "ABCDEFGHIJKLMNOP.A_1.auth0.com"});
    free(max_token);
    char *input = make_input(token, domain);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_result(&results.items[0], (expected_pair){token, domain});
    br_results_clear(&results);
    free(input);
}

int main(void)
{
    const br_detector *detector = detector_init(), *again = NULL;
    const void *state = detector->state;
    char *token = make_token(2000, 0);
    test_extraction(detector, token);
    test_occurrence_product(detector, token);
    test_verification(detector, token);
    free(token);
    CHECK(br_auth0managementapitoken_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("Auth0 Management API token");
}
