/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/endpoints.h"
#include "../support/detector_test.h"

/* Synthetic 40-character suffix, deliberately not a structural/base64 PAT. */
static const char secret[] = "BBDC-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd";
static const char base[] = "https://git.example.invalid";
static const char request_url[] = "https://git.example.invalid/rest/api/1.0/projects?limit=1";
typedef struct { const char *secret, *base; } expected_pair;

static void check_result(const br_result *result, expected_pair pair)
{
    size_t len = strlen(pair.secret), url_len = strlen(pair.base);
    CHECK(result->detector_type == 1045 && !result->detector_name);
    CHECK(result->raw.len == len && !memcmp(result->raw.data, pair.secret, len));
    CHECK(result->raw_v2.len == len + 1 + url_len && !memcmp(result->raw_v2.data, pair.secret, len));
    CHECK(result->raw_v2.data[len] == ':' && !memcmp(result->raw_v2.data + len + 1, pair.base, url_len));
    CHECK(!result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.secret));
    CHECK(json_object_object_get_ex(result->secret_parts, "url", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.base));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "URL", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), pair.base));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

/* Upstream iterates maps; assert the product as a set, not a Go traversal order. */
static void check_pairs(const br_results *results, const expected_pair *pairs, size_t count)
{
    CHECK(results->len == count);
    for (size_t p = 0; p < count; ++p) {
        size_t matches = 0, len = strlen(pairs[p].secret);
        for (size_t r = 0; r < results->len; ++r) {
            const br_result *result = &results->items[r];
            if (result->raw.len != len || memcmp(result->raw.data, pairs[p].secret, len)) continue;
            br_json *url = NULL;
            CHECK(result->secret_parts && json_object_object_get_ex(result->secret_parts, "url", &url));
            CHECK(json_object_is_type(url, json_type_string));
            if (strcmp(json_object_get_string(url), pairs[p].base)) continue;
            check_result(result, pairs[p]);
            ++matches;
        }
        CHECK(matches == 1);
    }
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bitbucketdatacenter_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_bitbucketdatacenter_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 1045 && detector->version == 0);
    CHECK(!strcmp(detector->name, "BitbucketDataCenter") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Bitbucket is a Git repository hosting service by Atlassian. Bitbucket PATs "
                  "are used to authenticate bitbucket data center(on prem) rest endpoint requests."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "BBDC-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(detector->validate_endpoints == br_endpoints_validate_configured && !detector->cloud_endpoint);
    CHECK(detector->validate_endpoints(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "at least one endpoint required"));
    free(error); error = NULL;
    const char *empty[] = {""};
    br_endpoints settings = {.configured = empty, .nconfigured = 1};
    CHECK(detector->validate_endpoints(&settings, &error) == 0 && !error);
    CHECK(br_bitbucketdatacenter_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Bitbucket Data Center detector output"));
    free(error);
    CHECK(br_bitbucketdatacenter_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_endpoints *settings,
                               const char *input, const expected_pair *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = settings};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!http.calls && !http.releases);
    check_pairs(&results, pairs, count);
    for (size_t i = 0; i < results.len; ++i)
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    const char *configured[] = {base};
    br_endpoints settings = {.configured = configured, .nconfigured = 1};
    const expected_pair one[] = {{secret, base}};
    char input[256], changed[57];
    const struct { const char *format; bool matches; } cases[] = {
        {"%s", true}, {"unrelated %s\n", true}, {"'%s'", true},
        {"%s=", true}, /* '=' is a consuming delimiter, not a base64 validation failure. */
        {"x%s", false}, {"_%s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, secret);
        expect_extraction(detector, &settings, input, one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, &settings, "", NULL, 0);
    memcpy(changed, secret, sizeof(secret));
    changed[0] = 'b';
    expect_extraction(detector, &settings, changed, NULL, 0);
    memcpy(changed, secret, sizeof(secret));
    changed[20] = '.';
    expect_extraction(detector, &settings, changed, NULL, 0);
    const size_t lengths[] = {39, 40, 50, 51};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        memcpy(changed, "BBDC-", 5);
        test_secret(changed + 5, lengths[i], 3);
        const expected_pair candidate[] = {{changed, base}};
        expect_extraction(detector, &settings, changed, candidate, lengths[i] >= 40 && lengths[i] <= 50 ? 1 : 0);
    }
    memcpy(changed, "BBDC-", 5);
    test_secret(changed + 5, 50, 7);
    memcpy(changed + 10, "+/@_-", 5);
    changed[54] = '/'; /* The source has no trailing word boundary. */
    const expected_pair special[] = {{changed, base}};
    expect_extraction(detector, &settings, changed, special, 1);
    snprintf(input, sizeof(input), "%s\n", changed);
    expect_extraction(detector, &settings, input, special, 1);
    snprintf(input, sizeof(input), "%s:%s", secret, changed);
    const expected_pair adjacent[] = {{secret, base}, {changed, base}};
    expect_extraction(detector, &settings, input, adjacent, 2);
    snprintf(input, sizeof(input), "%s\n%s\n%s", secret, secret, secret);
    expect_extraction(detector, &settings, input, one, 1);
}

static void test_endpoints(const br_detector *detector)
{
    char input[256];
    const expected_pair one[] = {{secret, base}};
    expect_extraction(detector, NULL, secret, NULL, 0); /* No token-only fallback. */
    snprintf(input, sizeof(input), "%s\nhttps://git.example.invalid", secret);
    expect_extraction(detector, NULL, input, NULL, 0); /* Dispatch is not a URL prefix. */
    snprintf(input, sizeof(input), "%s https://git.example.invalid", secret);
    expect_extraction(detector, NULL, input, NULL, 0);
    const char *prefixes[] = {"atlassian", "bitbucket", "BITBUCKET"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        snprintf(input, sizeof(input), "%s %s/scm/proj/repo\n%s", prefixes[i], base, secret);
        expect_extraction(detector, NULL, input, one, 1);
    }
    snprintf(input, sizeof(input), "bitbucket %s\n%s", base, secret);
    br_endpoints disabled = {0};
    expect_extraction(detector, &disabled, input, NULL, 0);
    const char *configured[] = {"https://git.example.invalid/", "https://git.example.invalid///", base};
    br_endpoints settings = {.configured = configured, .nconfigured = 3, .use_found = true};
    expect_extraction(detector, &settings, input, one, 1);
    const char *with_path[] = {"https://git.example.invalid/old?old=1#section"};
    settings = (br_endpoints){.configured = with_path, .nconfigured = 1};
    const expected_pair path[] = {{secret, with_path[0]}};
    expect_extraction(detector, &settings, secret, path, 1); /* Do not rewrite metadata URLs. */
    const char *empty[] = {"", "/", "///"};
    settings = (br_endpoints){.configured = empty, .nconfigured = 3};
    const expected_pair empty_pair[] = {{secret, ""}};
    expect_extraction(detector, &settings, secret, empty_pair, 1);
    const char *case_distinct[] = {base, "https://GIT.example.invalid"};
    settings = (br_endpoints){.configured = case_distinct, .nconfigured = 2};
    const expected_pair distinct[] = {{secret, base}, {secret, case_distinct[1]}};
    expect_extraction(detector, &settings, secret, distinct, 2);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "bitbucket", 9);
        memset(input + 9, '!', gap);
        snprintf(input + 9 + gap, sizeof(input) - 9 - gap, "%s\n%s", base, secret);
        expect_extraction(detector, NULL, input, one, gap == 40 ? 1 : 0);
    }
}

typedef struct { const char *secret, *url; } expected_request;
typedef struct { const expected_request *requests; size_t count, seen; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_DETECTOR_LOCAL && request->timeout_ms == 10000);
    CHECK(request->detector_type == 1045);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strncmp(request->headers[1].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog bb-dc-test"));
    size_t matches = 0;
    for (size_t i = 0; i < expected->count; ++i) {
        if (strcmp(request->url, expected->requests[i].url) ||
            strcmp(request->headers[1].value + 7, expected->requests[i].secret)) continue;
        CHECK(!(expected->seen & ((size_t)1 << i)));
        expected->seen |= (size_t)1 << i;
        ++matches;
    }
    CHECK(matches == 1);
}

static void test_product(const br_detector *detector)
{
    char second[56], input[320];
    memcpy(second, "BBDC-", 5);
    test_secret(second + 5, 50, 9);
    const char *configured[] = {base, "https://other.example.invalid", "https://git.example.invalid///"};
    br_endpoints settings = {.configured = configured, .nconfigured = 3, .use_found = true};
    snprintf(input, sizeof(input), "%s\n%s\n%s\nbitbucket %s/repos", second, secret, second, base);
    const expected_pair pairs[] = {{secret, base}, {secret, configured[1]}, {second, base}, {second, configured[1]}};
    expect_extraction(detector, &settings, input, pairs, 4);
    const expected_request requests[] = {
        {secret, request_url}, {secret, "https://other.example.invalid/rest/api/1.0/projects?limit=1"},
        {second, request_url}, {second, "https://other.example.invalid/rest/api/1.0/projects?limit=1"},
    };
    expected_requests expected = {requests, 4, 0};
    static const unsigned char body[] = "{\"displayName\":\"ignored\",\"URL\":\"not-the-base-url\"}";
    test_http http = {
        .response = {.status = 200, .body = {body, sizeof(body) - 1}},
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "bb-dc-test"};
    for (size_t failure = 0; failure < 2; ++failure) {
        expected.seen = http.calls = http.releases = 0;
        http.send_rc = failure ? -1 : 0;
        http.send_error = failure ? "no such host" : NULL;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 4 && http.releases == 4 && expected.seen == 15);
        check_pairs(&results, pairs, 4);
        for (size_t i = 0; i < results.len; ++i) {
            CHECK(results.items[i].verified == !failure);
            if (failure) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, "no such host"));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

typedef struct {
    int status, send_rc;
    br_slice body;
    const char *body_error, *send_error, *error, *base, *url;
    bool verified;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    const char *configured[] = {fixture.base ? fixture.base : base};
    br_endpoints settings = {.configured = configured, .nconfigured = 1};
    const expected_request requests[] = {{secret, fixture.url ? fixture.url : request_url}};
    expected_requests expected = {requests, 1, 0};
    test_http http = {
        .response = {.status = fixture.status, .body = fixture.body, .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "bb-dc-test"};
    br_results results = test_scan(detector, &ctx, true, secret, strlen(secret));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && expected.seen == 1);
    check_result(&results.items[0], (expected_pair){secret, configured[0]});
    CHECK(results.items[0].verified == fixture.verified);
    if (fixture.error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
        CHECK(!strstr(results.items[0].verification_error, secret));
        CHECK(!strstr(results.items[0].verification_error, configured[0]));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    static const unsigned char map[] = "{\"values\":[],\"size\":0}";
    static const unsigned char malformed[] = {'x', 0, 0xff};
    const verification_case cases[] = {
        {.status = 200, .verified = true},
        {.status = 200, .body = {map, sizeof(map) - 1}, .verified = true},
        {.status = 200, .body = {malformed, sizeof(malformed)}, .verified = true},
        {.status = 200, .body_error = "read failed", .verified = true},
        {.status = 401, .body_error = "ignored deferred body error"},
        {.status = 201, .error = "unexpected HTTP response status 201"},
        {.status = 403, .body_error = "ignored deferred body error", .error = "unexpected HTTP response status 403"},
        {.status = 500, .error = "unexpected HTTP response status 500"},
        {.status = 200, .send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1, .error = "HTTP transport failed"},
        {.status = 200, .base = "https://reader:synthetic@git.example.invalid:7990/old?old=1#section",
         .url = "https://reader:synthetic@git.example.invalid:7990/rest/api/1.0/projects?limit=1#section", .verified = true},
        {.status = 200, .base = "https://git.example.invalid/old?#section",
         .url = "https://git.example.invalid/rest/api/1.0/projects?limit=1#section", .verified = true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    const char *original = "https://git.example.invalid/old?old=1#section";
    char cause[384];
    snprintf(cause, sizeof(cause), "secret=%s base=%s secret-again=%s base-again=%s other=leave-this-alone",
             secret, original, secret, original);
    verify_case(detector, (verification_case){.status = 200, .send_rc = -1, .send_error = cause,
        .base = original, .url = "https://git.example.invalid/rest/api/1.0/projects?limit=1#section",
        .error = "secret=[REDACTED] base=[REDACTED] secret-again=[REDACTED] base-again=[REDACTED] other=leave-this-alone"});

    const char *unsupported[] = {"", "https://git.example.invalid/escaped%20path"};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
        br_endpoints settings = {.configured = &unsupported[i], .nconfigured = 1};
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings};
        br_results results = test_scan(detector, &ctx, true, secret, strlen(secret));
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(&results.items[0], (expected_pair){secret, unsupported[i]});
        CHECK(!results.items[0].verified && results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, "unsupported: Data Center URL form or normalization"));
        br_results_clear(&results);
    }
    const char *configured[] = {base};
    br_endpoints settings = {.configured = configured, .nconfigured = 1};
    br_scan_ctx offline = {.endpoints = &settings};
    br_results results = test_scan(detector, &offline, true, secret, strlen(secret));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_result(&results.items[0], (expected_pair){secret, base});
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init(), *again = NULL;
    const void *state = detector->state;
    CHECK(strlen(secret) == 45);
    test_extraction(detector);
    test_endpoints(detector);
    test_product(detector);
    test_verification(detector);
    CHECK(br_bitbucketdatacenter_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("Bitbucket Data Center");
}
