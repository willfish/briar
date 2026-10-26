/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/datacenter.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <time.h>

static char token[45], other_token[45];
static const char base_url[] = "http://confluence.invalid:8090/wiki?old=1#section";
static const int64_t ttl_ns = 12LL * 60 * 60 * 1000000000;
static int64_t test_now_ns = 1700000000000000000LL;

/* Interpose only the wall clock used by the production host cache. */
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
    CHECK(br_confluencedatacenter_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_confluencedatacenter_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 1047 && detector->version == 0);
    CHECK(!strcmp(detector->name, "ConfluenceDataCenter") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Confluence Data Center is Atlassian's self-hosted wiki product. Personal Access Tokens (PATs) "
        "authenticate via Bearer auth against the REST API and grant access scoped to the issuing user."));
    CHECK(detector->nkeywords == 3 && !strcmp(detector->keywords[0], "confluence") &&
          !strcmp(detector->keywords[1], "atlassian") && !strcmp(detector->keywords[2], "wiki"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(detector->validate_endpoints == br_endpoints_validate_configured);
    CHECK(detector->cloud_endpoint && !strcmp(detector->cloud_endpoint, ""));
    return detector;
}

static void check_text(br_json *object, const char *field, const char *expected)
{
    br_json *value = NULL;
    CHECK(object && json_object_object_get_ex(object, field, &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), expected));
}

static void check_result(const br_result *result, const char *secret, const char *base)
{
    CHECK(result->detector_type == 1047 && !result->detector_name);
    CHECK(result->raw.len == 44 && !memcmp(result->raw.data, secret, 44));
    CHECK(result->raw_v2.data && result->raw_v2.len == (base ? 45 + strlen(base) : 44));
    CHECK(!memcmp(result->raw_v2.data, secret, 44));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == (base ? 2 : 1));
    check_text(result->secret_parts, "token", secret);
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    if (base) {
        CHECK(result->raw_v2.data[44] == ':' && !memcmp(result->raw_v2.data + 45, base, strlen(base)));
        check_text(result->secret_parts, "url", base);
        check_text(result->extra_data, "base_url", base);
    } else check_text(result->extra_data, "verification_note",
        "no reachable Confluence Data Center URL found in context; token reported unverified");
    CHECK(!result->redacted && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void expect_one(const br_detector *detector, const char *input, const br_endpoints *settings,
                        const char *secret, const char *base, bool verify)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = settings};
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(results.len == (secret ? 1u : 0u) && !http.calls && !http.releases);
    if (secret) {
        check_result(&results.items[0], secret, base);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[46], padding[42];
    const char *prefixes[] = {"confluence", "ATLaSsIaN", "wiki", "preConFLuEnCEsuffix"};
    for (size_t i = 0; i < 4; ++i) {
        snprintf(input, sizeof(input), "%s %s", prefixes[i], token);
        expect_one(detector, input, NULL, token, NULL, false);
    }
    expect_one(detector, "", NULL, NULL, NULL, false);
    expect_one(detector, token, NULL, NULL, NULL, false);
    snprintf(input, sizeof(input), "%s confluence", token);
    expect_one(detector, input, NULL, NULL, NULL, false);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "confluence%.*s%s", gap, padding, token);
        expect_one(detector, input, NULL, gap == 40 ? token : NULL, NULL, false);
    }
    snprintf(input, sizeof(input), "wiki\r\n%s", token);
    expect_one(detector, input, NULL, token, NULL, false);
    const char *invalid[] = {"wiki%s", "wiki _%s", "wiki %.43s", "wiki %s=", "wiki %sA", "wiki %s+", "wiki %s/"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        snprintf(input, sizeof(input), invalid[i], token);
        expect_one(detector, input, NULL, NULL, NULL, false);
    }
    memcpy(changed, token, sizeof(token));
    changed[0] = 'm';
    snprintf(input, sizeof(input), "wiki %s", changed);
    expect_one(detector, input, NULL, NULL, NULL, false);
    memcpy(changed, token, sizeof(token));
    changed[10] = '_';
    snprintf(input, sizeof(input), "wiki %s", changed);
    expect_one(detector, input, NULL, NULL, NULL, false);
    unsigned char raw[33];
    memset(raw, '7', sizeof(raw)); /* Regex-shaped base64, but no decoded colon. */
    CHECK(EVP_EncodeBlock((unsigned char *)changed, raw, sizeof(raw)) == 44);
    snprintf(input, sizeof(input), "wiki %s", changed);
    expect_one(detector, input, NULL, NULL, NULL, false);
    memcpy(raw, "123456789012:synthetic-only-bytes", sizeof(raw));
    memset(raw + 30, 0xff, 3);
    CHECK(EVP_EncodeBlock((unsigned char *)changed, raw, sizeof(raw)) == 44 && changed[43] == '/');
    snprintf(input, sizeof(input), "wiki %s", changed);
    expect_one(detector, input, NULL, changed, NULL, false); /* Trailing '/' does not require a word boundary. */
    snprintf(input, sizeof(input), "wiki %s\nwiki %s", token, token);
    expect_one(detector, input, NULL, token, NULL, false);
    snprintf(input, sizeof(input), "wiki %s", token);
    expect_one(detector, input, NULL, token, NULL, true); /* No URL: no verification request. */
}

typedef struct {
    const char *tokens[2], *bases[2];
    size_t ntokens, nbases, token_calls[2], advance_on_call;
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_LOCAL && request->timeout_ms == 10000);
    CHECK(request->detector_type == 1047 && !request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strncmp(request->headers[1].value, "Bearer ", 7));
    size_t k = 0;
    while (k < expected->ntokens && strcmp(request->headers[1].value + 7, expected->tokens[k])) ++k;
    CHECK(k < expected->ntokens);
    ++expected->token_calls[k];
    bool matched = false;
    for (size_t i = 0; i < expected->nbases; ++i) {
        char url[256];
        snprintf(url, sizeof(url), "%s/rest/api/user/current", expected->bases[i]);
        if (!strcmp(request->url, url)) matched = true;
    }
    CHECK(matched);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog confluence-test"));
    if (http->calls == expected->advance_on_call) test_now_ns += ttl_ns + 1;
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    char input[64];
    snprintf(input, sizeof(input), "wiki %s", token);
    const char *configured[] = {base_url};
    br_endpoints settings = {.configured = configured, .nconfigured = 1};
    requests expected = {.tokens = {token}, .bases = {base_url}, .ntokens = 1, .nbases = 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "confluence-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_result(&results.items[0], token, base_url);
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const struct { int status; const char *body, *body_error; bool verified; const char *error; } cases[] = {
        {200, "{\"displayName\":\"Synthetic user\",\"id\":7}", NULL, true, NULL},
        {200, "", NULL, true, NULL}, {200, "not JSON", NULL, true, NULL},
        {200, "[]", NULL, true, NULL}, {200, "null", NULL, true, NULL},
        {200, "{", "read failed", true, NULL}, {200, "{}", "ignored after object", true, NULL},
        {200, "{", "no such host", true, NULL},
        {401, "not JSON", "ignored", false, NULL},
        {403, "{}", "ignored", false, "unexpected HTTP response status 403"},
        {302, "{}", "ignored", false, "unexpected HTTP response status 302"},
        {500, "{}", "ignored", false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}, .body_error = cases[i].body_error}};
        verify_case(detector, &http, cases[i].verified, cases[i].error);
    }
    static const unsigned char binary[] = {0xff, 0, '{'};
    test_http http = {.response = {.status = 200, .body = {binary, sizeof(binary)}, .body_error = "ignored"}};
    verify_case(detector, &http, true, NULL);
    http = (test_http){.send_rc = -1, .response = {.status = 200}};
    const char *send_errors[] = {"context canceled", "context deadline exceeded", "No such host"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        verify_case(detector, &http, false, send_errors[i]);
    }
    char cause[384], redacted[384];
    snprintf(cause, sizeof(cause), "token=%s url=%s again=%s other=%s", token, base_url, token, other_token);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] url=%s again=[REDACTED] other=%s", base_url, other_token);
    http.send_error = cause;
    verify_case(detector, &http, false, redacted);
    http.send_error = NULL;
    verify_case(detector, &http, false, "HTTP transport failed");
    const char *configured[] = {base_url};
    br_endpoints settings = {.configured = configured, .nconfigured = 1};
    br_scan_ctx offline = {.endpoints = &settings};
    char input[64];
    snprintf(input, sizeof(input), "wiki %s", token);
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    check_result(&results.items[0], token, base_url);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void endpoint_settings(const br_detector *detector)
{
    char input[256], *error = NULL;
    snprintf(input, sizeof(input), "wiki %s\nconfluence https://found.invalid:8443/wiki/path?discard=1", token);
    expect_one(detector, input, NULL, token, "https://found.invalid:8443", false);
    const char *configured[] = {"https://configured.invalid/wiki///", "https://configured.invalid/wiki", "https://configured.invalid/wiki/"};
    br_endpoints settings = {.configured = configured, .nconfigured = 3};
    CHECK(detector->validate_endpoints(&settings, &error) == 0 && !error);
    expect_one(detector, input, &settings, token, "https://configured.invalid/wiki", false);
    const char *empty[] = {"", "///"};
    settings = (br_endpoints){.configured = empty, .nconfigured = 1};
    CHECK(detector->validate_endpoints(&settings, &error) == 0 && !error);
    settings.nconfigured = 2;
    expect_one(detector, input, &settings, token, "", false); /* Empty endpoint is not absent context. */
    settings = (br_endpoints){0};
    CHECK(detector->validate_endpoints(&settings, &error) != 0 && error && !strcmp(error, "at least one endpoint required"));
    free(error);
    expect_one(detector, input, &settings, token, NULL, true); /* Flags-only configuration is valid during scanning. */
    settings = (br_endpoints){.cloud = "https://cloud.invalid/wiki///", .use_cloud = true};
    expect_one(detector, input, &settings, token, "https://cloud.invalid/wiki", false);
}

static void unique_pairs(const br_detector *detector)
{
    const char *bases[] = {"http://pair.invalid:8090", "https://second.invalid/wiki"};
    const char *configured[] = {"http://pair.invalid:8090///", "http://pair.invalid:8090", "https://second.invalid/wiki/"};
    br_endpoints settings = {.configured = configured, .nconfigured = 3, .use_found = true};
    char input[512];
    snprintf(input, sizeof(input), "wiki %s\nwiki %s\nwiki %s\nwiki http://pair.invalid:8090/context", token, other_token, token);
    requests expected = {.tokens = {token, other_token}, .bases = {bases[0], bases[1]}, .ntokens = 2, .nbases = 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "confluence-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && !http.calls && !http.releases);
    bool seen[2][2] = {{false}};
    for (size_t i = 0; i < results.len; ++i) {
        size_t k = !memcmp(results.items[i].raw.data, token, 44) ? 0 : 1;
        br_json *value = NULL;
        CHECK(json_object_object_get_ex(results.items[i].extra_data, "base_url", &value));
        const char *base = json_object_get_string(value);
        CHECK(!strcmp(base, bases[0]) || !strcmp(base, bases[1]));
        size_t u = !strcmp(base, bases[0]) ? 0 : 1;
        CHECK(!seen[k][u]);
        seen[k][u] = true;
        check_result(&results.items[i], expected.tokens[k], bases[u]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    CHECK(expected.token_calls[0] == 2 && expected.token_calls[1] == 2);
    for (size_t i = 0; i < results.len; ++i) CHECK(results.items[i].verified && !results.items[i].verification_error);
    br_results_clear(&results);
}

static void cache_and_fallback(const br_detector *detector)
{
    const char *configured[] = {"https://cache.invalid/wiki///"};
    br_endpoints settings = {.configured = configured, .nconfigured = 1};
    const char *trimmed = "https://cache.invalid/wiki";
    requests expected = {.tokens = {token, other_token}, .bases = {trimmed}, .ntokens = 2, .nbases = 1};
    test_http http = {.send_rc = -1, .send_error = "wrapped synthetic lookup: no such hostname", .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "confluence-test"};
    char input[160];
    snprintf(input, sizeof(input), "wiki %s\nwiki %s", token, other_token);
    int64_t start = test_now_ns;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 1 && http.releases == 1);
    size_t errors = 0, fallbacks = 0;
    for (size_t i = 0; i < results.len; ++i) {
        const char *secret = !memcmp(results.items[i].raw.data, token, 44) ? token : other_token;
        CHECK(!results.items[i].verified);
        if (results.items[i].verification_error) {
            ++errors;
            CHECK(!strcmp(results.items[i].verification_error, "no such host"));
            check_result(&results.items[i], secret, trimmed);
        } else {
            ++fallbacks;
            check_result(&results.items[i], secret, NULL);
        }
    }
    CHECK(errors == 1 && fallbacks == 1); /* Current failure is emitted; next token skips the endpoint. */
    br_results_clear(&results);
    const br_detector *again = NULL;
    char *error = NULL;
    CHECK(br_confluencedatacenter_init(&again, &error) == 0 && !error && again == detector);
    expect_one(again, "wiki", &settings, NULL, NULL, false);
    snprintf(input, sizeof(input), "wiki %s", token);
    expect_one(again, input, &settings, token, NULL, false);
    expect_one(again, input, &settings, token, NULL, true);
    configured[0] = "https://cache.invalid/other";
    expect_one(detector, input, &settings, token, configured[0], false); /* Cache key includes the path. */
    configured[0] = "https://cache.invalid/wiki?x=1";
    expect_one(detector, input, &settings, token, configured[0], false); /* And the query bytes. */
    configured[0] = "https://cache.invalid/wiki";
    test_now_ns = start + ttl_ns;
    expect_one(detector, input, &settings, token, NULL, false);
    ++test_now_ns;
    expect_one(detector, input, &settings, token, configured[0], false);
    CHECK(http.calls == 1 && http.releases == 1);
}

static void upfront_filter_snapshot(const br_detector *detector)
{
    const char *configured[] = {"https://snapshot.invalid/wiki", "https://remaining.invalid/wiki"};
    br_endpoints settings = {.configured = configured, .nconfigured = 1};
    requests expected = {.tokens = {token}, .bases = {configured[0]}, .ntokens = 1, .nbases = 1};
    test_http http = {.send_rc = -1, .send_error = "lookup fixture: no such host", .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &settings, .user_agent = "confluence-test"};
    char input[160];
    snprintf(input, sizeof(input), "wiki %s", token);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && results.items[0].verification_error);
    br_results_clear(&results);
    settings.nconfigured = 2;
    expected = (requests){.tokens = {token, other_token}, .bases = {configured[1]},
                          .ntokens = 2, .nbases = 1, .advance_on_call = 1};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    snprintf(input, sizeof(input), "wiki %s\nwiki %s", token, other_token);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], !memcmp(results.items[i].raw.data, token, 44) ? token : other_token, configured[1]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    /* A URL rejected up front stays absent even after another request advances
     * the clock past its expiry. A new scan may use that URL again. */
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 4 && http.calls == 2 && http.releases == 2);
    br_results_clear(&results);
}

int main(void)
{
    unsigned char raw[33];
    memcpy(raw, "123456789012:synthetic-only-bytes", sizeof(raw));
    CHECK(EVP_EncodeBlock((unsigned char *)token, raw, sizeof(raw)) == 44);
    raw[0] = '9';
    raw[32] = 'Z';
    CHECK(EVP_EncodeBlock((unsigned char *)other_token, raw, sizeof(raw)) == 44);
    CHECK(br_dc_is_structural_pat44((br_slice){(unsigned char *)token, 44}));
    CHECK(br_dc_is_structural_pat44((br_slice){(unsigned char *)other_token, 44}));
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    endpoint_settings(detector);
    unique_pairs(detector);
    cache_and_fallback(detector);
    upfront_filter_snapshot(detector);
    return test_finish("ConfluenceDataCenter");
}
