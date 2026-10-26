/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/endpoints.h"
#include "../support/detector_test.h"
#include <time.h>

static char token[74], other_token[74], third_token[74];
static const char fixture_host[] = "briar-fixture.jfrog.io";
static const int64_t ttl_ns = 12LL * 60 * 60 * 1000000000;
static int64_t test_now_ns = 1700000000000000000LL;

/* Exercise the production cache's expiry without sleeps or a production hook. */
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
    CHECK(br_artifactory_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_artifactory_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 181 && detector->version == 0);
    CHECK(!strcmp(detector->name, "ArtifactoryAccessToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Artifactory is a repository manager that supports all major package formats. "
        "Artifactory access tokens can be used to authenticate and perform operations on repositories."));
    CHECK(detector->nkeywords == 3 && !strcmp(detector->keywords[0], "artifactory") &&
          !strcmp(detector->keywords[1], "jfrog.io") && !strcmp(detector->keywords[2], "AKCp"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && detector->validate_endpoints == br_endpoints_validate_configured);
    CHECK(detector->cloud_endpoint && !strcmp(detector->cloud_endpoint, ""));
    return detector;
}

static void check_pair(const br_result *result, const char *secret, const char *domain)
{
    size_t token_len = strlen(secret), domain_len = strlen(domain);
    CHECK(result->detector_type == 181 && !result->detector_name);
    CHECK(result->raw.len == token_len && !memcmp(result->raw.data, secret, token_len));
    CHECK(result->raw_v2.len == token_len + domain_len && result->raw_v2.data);
    CHECK(!memcmp(result->raw_v2.data, secret, token_len));
    CHECK(!memcmp(result->raw_v2.data + token_len, domain, domain_len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), secret));
    CHECK(json_object_object_get_ex(result->secret_parts, "domain", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), domain));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void expect_one(const br_detector *detector, const void *input, size_t len,
                        const br_endpoints *settings, const char *secret, const char *domain)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = settings};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (domain ? 1u : 0u) && !http.calls && !http.releases);
    if (domain) {
        check_pair(&results.items[0], secret, domain);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[2048], changed[75], label[65];
    snprintf(input, sizeof(input), "%s %s", token, fixture_host);
    expect_one(detector, input, strlen(input), NULL, token, fixture_host); /* No provider prefix required. */
    expect_one(detector, NULL, 0, NULL, NULL, NULL);
    expect_one(detector, token, strlen(token), NULL, NULL, NULL); /* Empty CloudEndpoint adds no host. */
    expect_one(detector, fixture_host, strlen(fixture_host), NULL, NULL, NULL);
    memcpy(changed, token, sizeof(token));
    changed[10] = 'Z';
    snprintf(input, sizeof(input), "%s %s", changed, fixture_host);
    expect_one(detector, input, strlen(input), NULL, changed, fixture_host);
    const char *bad_prefixes[] = {"aKCp", "AKCP", "AKcp"};
    for (size_t i = 0; i < 3; ++i) {
        memcpy(changed, token, sizeof(token));
        memcpy(changed, bad_prefixes[i], 4);
        snprintf(input, sizeof(input), "%s %s", changed, fixture_host);
        expect_one(detector, input, strlen(input), NULL, NULL, NULL);
    }
    memcpy(changed, token, sizeof(token));
    changed[72] = '\0'; /* Only 68 payload bytes. */
    snprintf(input, sizeof(input), "%s %s", changed, fixture_host);
    expect_one(detector, input, strlen(input), NULL, NULL, NULL);
    memcpy(changed, token, sizeof(token));
    changed[73] = 'x';
    changed[74] = '\0';
    snprintf(input, sizeof(input), "%s %s", changed, fixture_host);
    expect_one(detector, input, strlen(input), NULL, NULL, NULL);
    memcpy(changed, token, sizeof(token));
    changed[25] = '-';
    snprintf(input, sizeof(input), "%s %s", changed, fixture_host);
    expect_one(detector, input, strlen(input), NULL, NULL, NULL);
    const char *blocked_before[] = {"x", "_"}, *blocked_after[] = {"x", "_"};
    for (size_t i = 0; i < 2; ++i) {
        snprintf(input, sizeof(input), "%s%s %s", blocked_before[i], token, fixture_host);
        expect_one(detector, input, strlen(input), NULL, NULL, NULL);
        snprintf(input, sizeof(input), "%s%s %s", token, blocked_after[i], fixture_host);
        expect_one(detector, input, strlen(input), NULL, NULL, NULL);
    }
    snprintf(input, sizeof(input), "-%s-\r\nhttps://%s/path", token, fixture_host);
    expect_one(detector, input, strlen(input), NULL, token, fixture_host);
    const struct { const char *input, *domain; } urls[] = {
        {"a.jfrog.io", NULL}, {"ab.jfrog.io", "ab.jfrog.io"},
        {"1-2.jfrog.io", "1-2.jfrog.io"}, {"AbC.jfrog.io", "AbC.jfrog.io"},
        {"ab.JFROG.IO", NULL}, {"abXjfrogYio", NULL},
        {"_ab.jfrog.io", NULL}, {"a-.jfrog.io", NULL},
        {"-ab.jfrog.io", "ab.jfrog.io"},
        {"ab.jfrog.ioEVIL", "ab.jfrog.io"}, /* No trailing URL boundary in source. */
    };
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s", token, urls[i].input);
        expect_one(detector, input, strlen(input), NULL, token, urls[i].domain);
    }
    for (size_t n = 63; n <= 64; ++n) {
        memset(label, 'a', n);
        label[n] = '\0';
        char domain[80];
        snprintf(domain, sizeof(domain), "%s.jfrog.io", label);
        snprintf(input, sizeof(input), "%s %s", token, domain);
        expect_one(detector, input, strlen(input), NULL, token, n == 63 ? domain : NULL);
    }
    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", token);
    memset(input + at, '-', 1100);
    snprintf(input + at + 1100, sizeof(input) - at - 1100, "\n%s", fixture_host);
    expect_one(detector, input, strlen(input), NULL, token, fixture_host); /* Span is engine-owned. */
    memcpy(input, token, 73);
    input[73] = '\0';
    memcpy(input + 74, fixture_host, sizeof(fixture_host));
    expect_one(detector, input, 74 + strlen(fixture_host), NULL, token, fixture_host);
}

typedef struct {
    const char *tokens[3], *hosts[2];
    size_t ntokens, nhosts, token_calls[3], advance_on_call;
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 181 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-JFrog-Art-Api"));
    size_t k = 0;
    while (k < expected->ntokens && strcmp(request->headers[0].value, expected->tokens[k])) ++k;
    CHECK(k < expected->ntokens);
    ++expected->token_calls[k];
    bool matched = false;
    for (size_t h = 0; h < expected->nhosts; ++h) {
        char url[256];
        snprintf(url, sizeof(url), "https://%s/artifactory/api/system/ping", expected->hosts[h]);
        if (!strcmp(request->url, url)) matched = true;
    }
    CHECK(matched);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") &&
          !strcmp(request->headers[1].value, "TruffleHog artifactory-test"));
    if (http->calls == expected->advance_on_call) test_now_ns += ttl_ns + 1;
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
    char input[160];
    snprintf(input, sizeof(input), "%s %s", token, fixture_host);
    requests expected = {.tokens = {token}, .hosts = {fixture_host}, .ntokens = 1, .nhosts = 1};
    const br_header headers[] = {{"Content-Type", "text/html"}}; /* Access tokens inspect only the body. */
    test_http http = {
        .response = {.status = fixture.status ? fixture.status : 200,
                     .headers = headers, .nheaders = 1, .body = fixture.body, .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "artifactory-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.token_calls[0] == 1);
    check_pair(&results.items[0], token, fixture_host);
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const verification_case cases[] = {
        {.body = BODY("OK"), .verified = true},
        {.body = BODY("not JSON: xOKy"), .verified = true},
        {.body = BODY("\0OK\xff"), .verified = true},
        {.body = BODY("O\0K")}, {.body = BODY("ok")}, {.body = BODY("Ok")}, {0},
        {.body = BODY("OK"), .body_error = "read failed", .error = "read failed"},
        {.body = BODY("OK"), .body_error = "no such host", .error = "no such host"},
        {.status = 401, .body = BODY("OK"), .body_error = "no such host"},
        {.status = 403, .body = BODY("OK"), .body_error = "ignored"},
        {.status = 302, .body = BODY("OK"), .body_error = "ignored"},
        {.status = 301, .body_error = "ignored", .error = "unexpected HTTP response status 301"},
        {.status = 404, .body_error = "ignored", .error = "unexpected HTTP response status 404"},
        {.status = 429, .error = "unexpected HTTP response status 429"},
        {.status = 500, .body = BODY("OK"), .body_error = "ignored", .error = "unexpected HTTP response status 500"},
        {.send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.send_rc = -1, .send_error = "No such host", .error = "No such host"},
        {.send_rc = -1, .send_error = "nosuchhost", .error = "nosuchhost"},
        {.send_rc = -1, .body = BODY("OK"), .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    char cause[384], redacted[384];
    snprintf(cause, sizeof(cause), "token=%s domain=%s repeated=%s other=%s", token, fixture_host, token, other_token);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] domain=%s repeated=[REDACTED] other=%s", fixture_host, other_token);
    verify_case(detector, (verification_case){.send_rc = -1, .send_error = cause, .error = redacted});
    verify_case(detector, (verification_case){.body = BODY("OK"), .body_error = cause, .error = redacted});
    char input[160];
    snprintf(input, sizeof(input), "%s %s", token, fixture_host);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_pair(&results.items[0], token, fixture_host);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void endpoint_settings(const br_detector *detector)
{
    char input[160], *error = NULL;
    snprintf(input, sizeof(input), "%s %s", token, fixture_host);
    const char *configured[] = {"https://custom.invalid:8443/base/", "custom.invalid:8443/base/", "https://custom.invalid:8443/base/"};
    br_endpoints settings = {.configured = configured, .nconfigured = 3};
    CHECK(detector->validate_endpoints(&settings, &error) == 0 && !error);
    expect_one(detector, input, strlen(input), &settings, token, "custom.invalid:8443/base/");
    requests expected = {.tokens = {token}, .hosts = {"custom.invalid:8443/base/"}, .ntokens = 1, .nhosts = 1};
    test_http http = {.response = {.status = 200, .body = BODY("OK")}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "artifactory-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    check_pair(&results.items[0], token, "custom.invalid:8443/base/");
    br_results_clear(&results);

    const char *empty[] = {"", "https://", ""};
    settings = (br_endpoints){.configured = empty, .nconfigured = 1};
    CHECK(detector->validate_endpoints(&settings, &error) == 0 && !error); /* One empty argument is accepted. */
    settings.nconfigured = 3;
    expect_one(detector, token, strlen(token), &settings, token, "");
    settings = (br_endpoints){0};
    CHECK(detector->validate_endpoints(&settings, &error) != 0 && error && !strcmp(error, "at least one endpoint required"));
    free(error);
    error = NULL;
    expect_one(detector, input, strlen(input), &settings, NULL, NULL); /* Valid flags-only state, not a setter call. */
    settings = (br_endpoints){.cloud = "https://cloud.invalid", .use_cloud = true};
    expect_one(detector, input, strlen(input), &settings, token, "cloud.invalid");
    settings.cloud = "";
    expect_one(detector, input, strlen(input), &settings, NULL, NULL);

    const char *overlap[] = {"https://briar-fixture.jfrog.io", "briar-fixture.jfrog.io"};
    settings = (br_endpoints){.configured = overlap, .nconfigured = 2,
                             .cloud = overlap[0], .use_cloud = true, .use_found = true};
    expect_one(detector, input, strlen(input), &settings, token, fixture_host);
    const char *prefixes[] = {"https://https://custom.invalid", "HTTPS://custom.invalid", "http://custom.invalid"};
    const char *domains[] = {"https://custom.invalid", "HTTPS://custom.invalid", "http://custom.invalid"};
    for (size_t i = 0; i < 3; ++i) {
        settings = (br_endpoints){.configured = &prefixes[i], .nconfigured = 1};
        expect_one(detector, token, strlen(token), &settings, token, domains[i]);
    }
}

static void unique_pairs(const br_detector *detector)
{
    const char *hosts[] = {"pair-fixture.jfrog.io", "PAIR-fixture.jfrog.io"};
    char input[512];
    snprintf(input, sizeof(input), "%s %s %s %s %s https://%s %s", token, hosts[0], other_token, hosts[1], token, hosts[0], other_token);
    requests expected = {.tokens = {token, other_token}, .hosts = {hosts[0], hosts[1]}, .ntokens = 2, .nhosts = 2};
    test_http http = {.response = {.status = 200, .body = BODY("OK")}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "artifactory-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && !http.calls && !http.releases);
    bool seen[2][2] = {{false}};
    for (size_t i = 0; i < results.len; ++i) {
        const char *secret = !memcmp(results.items[i].raw.data, token, 73) ? token : other_token;
        br_json *domain = NULL;
        CHECK(json_object_object_get_ex(results.items[i].secret_parts, "domain", &domain));
        const char *host = json_object_get_string(domain);
        CHECK(!strcmp(host, hosts[0]) || !strcmp(host, hosts[1]));
        size_t k = secret == token ? 0 : 1, h = !strcmp(host, hosts[0]) ? 0 : 1;
        CHECK(!seen[k][h]);
        seen[k][h] = true;
        check_pair(&results.items[i], secret, host);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    CHECK(expected.token_calls[0] == 2 && expected.token_calls[1] == 2); /* No first-success break. */
    for (size_t i = 0; i < results.len; ++i) CHECK(results.items[i].verified && !results.items[i].verification_error);
    br_results_clear(&results);
}

static void cache_expiry(const br_detector *detector)
{
    const char *hosts[] = {"cache-a.jfrog.io", "cache-b.jfrog.io"};
    char input[256];
    int64_t start = test_now_ns;
    requests expected = {.tokens = {token, other_token}, .hosts = {hosts[0]}, .ntokens = 2, .nhosts = 1};
    test_http http = {.send_rc = -1, .send_error = "wrapped lookup: no such host (synthetic)",
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "artifactory-test"};
    for (size_t h = 0; h < 2; ++h) {
        expected.hosts[0] = hosts[h];
        http.calls = http.releases = 0;
        snprintf(input, sizeof(input), "%s %s %s", token, other_token, hosts[h]);
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(!results.len && http.calls == 1 && http.releases == 1);
        br_results_clear(&results);
        if (!h) test_now_ns += 5;
    }
    snprintf(input, sizeof(input), "%s %s %s %s", token, other_token, hosts[0], hosts[1]);
    const br_detector *again = NULL;
    char *error = NULL;
    CHECK(br_artifactory_init(&again, &error) == 0 && !error && again == detector);
    br_results results = test_scan(again, &ctx, false, input, strlen(input));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    test_now_ns = start + ttl_ns;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len && http.calls == 1); /* Exact expiry instant is still cached. */
    br_results_clear(&results);
    ++test_now_ns;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 1);
    for (size_t i = 0; i < results.len; ++i)
        check_pair(&results.items[i], !memcmp(results.items[i].raw.data, token, 73) ? token : other_token, hosts[0]);
    br_results_clear(&results);
    test_now_ns = start + ttl_ns + 5;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 1); /* The second host has its own deadline. */
    br_results_clear(&results);
    ++test_now_ns;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
}

static void local_host_removal(const br_detector *detector)
{
    const char *hosts[] = {"removed.invalid", "remaining.invalid"};
    br_endpoints settings = {.configured = hosts, .nconfigured = 1};
    requests expected = {.tokens = {token}, .hosts = {hosts[0]}, .ntokens = 1, .nhosts = 1};
    test_http http = {.send_rc = -1, .send_error = "no such host", .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "artifactory-test"};
    br_results results = test_scan(detector, &ctx, true, token, strlen(token));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    settings.nconfigured = 2;
    expected = (requests){.tokens = {token, other_token, third_token}, .hosts = {hosts[1]},
                          .ntokens = 3, .nhosts = 1, .advance_on_call = 2};
    http = (test_http){.response = {.status = 200, .body = BODY("OK")}, .inspect = inspect_request, .user = &expected};
    char input[256];
    snprintf(input, sizeof(input), "%s %s %s", token, other_token, third_token);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) CHECK(expected.token_calls[i] == 1);
    for (size_t i = 0; i < results.len; ++i) CHECK(results.items[i].verified);
    br_results_clear(&results);
    /* Once observed cached, access-token URLs stay removed within that scan
     * even if another request advances the clock past global cache expiry. */
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 6 && http.calls == 3 && http.releases == 3);
    br_results_clear(&results);
}

static void provider_cache_isolation(const br_detector *detector)
{
    const br_detector *algolia = NULL;
    char *error = NULL, algolia_key[33], input[160];
    CHECK(br_algoliaadminkey_init(&algolia, &error) == 0 && !error && algolia);
    test_secret(algolia_key, 32, 0);
    const char *host[] = {"AB12CD34EF"}; /* Configured endpoints are not restricted to jfrog.io. */
    test_http http = {.send_rc = -1, .send_error = "synthetic lookup: no such host"};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "appId %s\napiKey %s", host[0], algolia_key);
    br_results results = test_scan(algolia, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    br_endpoints settings = {.configured = host, .nconfigured = 1};
    ctx.endpoints = &settings;
    results = test_scan(detector, &ctx, false, token, strlen(token));
    CHECK(results.len == 1 && http.calls == 1);
    check_pair(&results.items[0], token, host[0]);
    br_results_clear(&results);
    host[0] = "GH56IJ78KL";
    results = test_scan(detector, &ctx, true, token, strlen(token));
    CHECK(!results.len && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
    ctx.endpoints = NULL;
    snprintf(input, sizeof(input), "appId %s\napiKey %s", host[0], algolia_key);
    results = test_scan(algolia, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 2 && http.releases == 2);
    CHECK(results.items[0].detector_type == 170 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

int main(void)
{
    memcpy(token, "AKCp", 4);
    memcpy(other_token, "AKCp", 4);
    memcpy(third_token, "AKCp", 4);
    test_secret(token + 4, 69, 0);
    test_secret(other_token + 4, 69, 9);
    test_secret(third_token + 4, 69, 17);
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    endpoint_settings(detector);
    unique_pairs(detector);
    cache_expiry(detector);
    local_host_removal(detector);
    provider_cache_isolation(detector);
    return test_finish("ArtifactoryAccessToken");
}
