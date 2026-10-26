/* SPDX-License-Identifier: AGPL-3.0-only */
/* Function GETs can execute user code: every test uses injected HTTP only. */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static const char key0[] = "AbCdEf0123456789_-xY";
static const char key1[] = "ZyXwVu9876543210_-aB";
static const char url0[] = "https://Ab-c.azurewebsites.net/api/Fn-2";
static const char url1[] = "https://xy.azurewebsites.net/api/go";
typedef struct { br_slice key, url; bool verified; const char *error; } expected_result;

static br_slice text(const char *value)
{
    return (br_slice){(const unsigned char *)value, strlen(value)};
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azurefunctionkey_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_azurefunctionkey_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 973 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AzureFunctionKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Azure Functions is a serverless compute service that lets you run event-triggered code "
        "without having to explicitly provision or manage infrastructure. Azure Function Keys "
        "can be used to access and manage these functions."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "azure"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(!br_detector_is_default(detector, NULL)); /* Source constructor is commented out for FPs. */
    const void *patterns = detector->state;
    CHECK(br_azurefunctionkey_init(&again, NULL) == 0 && again == detector && again->state == patterns);
    CHECK(br_azurefunctionkey_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_azurefunctionkey_init(NULL, NULL) != 0);
    return detector;
}

static void check_json_bytes(br_json *object, const char *name, br_slice expected)
{
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(object, name, &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)expected.len);
    CHECK(!memcmp(json_object_get_string(part), expected.data, expected.len));
}

static void check_result(const br_result *result, const expected_result *expected)
{
    CHECK(result->detector_type == 973 && !result->detector_name);
    CHECK(result->raw.len == expected->key.len && !memcmp(result->raw.data, expected->key.data, expected->key.len));
    CHECK(result->raw_v2.len == expected->key.len + expected->url.len);
    CHECK(!memcmp(result->raw_v2.data, expected->key.data, expected->key.len));
    CHECK(!memcmp(result->raw_v2.data + expected->key.len, expected->url.data, expected->url.len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_json_bytes(result->secret_parts, "key", expected->key);
    check_json_bytes(result->secret_parts, "url", expected->url);
    if (memchr(expected->key.data, 0, expected->key.len)) {
        const char *encoded = json_object_to_json_string_ext(result->secret_parts, JSON_C_TO_STRING_PLAIN);
        CHECK(encoded && strstr(encoded, "\\u0000"));
        br_json *decoded = json_tokener_parse(encoded);
        CHECK(decoded);
        check_json_bytes(decoded, "key", expected->key);
        json_object_put(decoded);
    }
    CHECK(result->verified == expected->verified);
    if (expected->error) CHECK(result->verification_error && !strcmp(result->verification_error, expected->error));
    else CHECK(!result->verification_error);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_results(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, const expected_result *expected, size_t count)
{
    br_results results = test_scan(detector, ctx, verify, input.data, input.len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&results.items[i], &expected[i]);
    br_results_clear(&results);
}

static br_slice make_input(unsigned char *out, size_t cap, br_slice line, br_slice url)
{
    CHECK(line.len < cap && url.len < cap - line.len - 1);
    memcpy(out, line.data, line.len);
    out[line.len] = '\n';
    memcpy(out + line.len + 1, url.data, url.len);
    out[line.len + 1 + url.len] = '\0';
    return (br_slice){out, line.len + 1 + url.len};
}

static void test_full_match_extraction(const br_detector *detector)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    unsigned char input[1024];
    char line[256], raw[256];
    const struct { const char *line, *raw; } cases[] = {
        {"aZuRe %s==", "%s=="}, {"preAZUREsuffix:%s", "AZUREsuffix:%s"},
        {"azure=%s", "azure=%s"}, {"azure =%s", "=%s"},
        {"azure key=%s", "key=%s"}, {"azure \t%s", "\t%s"},
        {"azure\t%s", "azure\t%s"}, {"azure\r\n%s", "azure\r\n%s"},
        {"azure %s===", "%s=="}, {"azure %s-", "%s"}, {"azure %s_", "%s_"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(line, sizeof(line), cases[i].line, key0);
        snprintf(raw, sizeof(raw), cases[i].raw, key0);
        br_slice data = make_input(input, sizeof(input), text(line), text(url0));
        expected_result expected = {.key = text(raw), .url = text(url0)};
        expect_results(detector, &ctx, false, data, &expected, 1);
    }
    const unsigned char nul[] = "azure\0AbCdEf0123456789_-xY==";
    const unsigned char nul_after_space[] = "azure \0AbCdEf0123456789_-xY";
    const unsigned char nul_before_space[] = "azure\0 AbCdEf0123456789_-xY";
    const unsigned char del[] = "azure\177AbCdEf0123456789_-xY";
    const br_slice lines[] = {{nul, sizeof(nul) - 1}, {nul_after_space, sizeof(nul_after_space) - 1},
                             {nul_before_space, sizeof(nul_before_space) - 1}, {del, sizeof(del) - 1}};
    const br_slice keys[] = {lines[0], {nul_after_space + 6, sizeof(nul_after_space) - 7}, text(key0), lines[3]};
    for (size_t i = 0; i < 4; ++i) {
        br_slice data = make_input(input, sizeof(input), lines[i], text(url0));
        expected_result expected = {.key = keys[i], .url = text(url0)};
        expect_results(detector, &ctx, false, data, &expected, 1);
    }
    char generated[58];
    memset(generated, 'a', 57);
    generated[57] = '\0';
    const size_t lengths[] = {19, 20, 56, 57};
    for (size_t i = 0; i < 4; ++i) {
        snprintf(line, sizeof(line), "azure %.*s", (int)lengths[i], generated);
        br_slice data = make_input(input, sizeof(input), text(line), text(url0));
        expected_result expected = {.key = {(const unsigned char *)generated, lengths[i]}, .url = text(url0)};
        expect_results(detector, &ctx, false, data, &expected, lengths[i] == 20 || lengths[i] == 56 ? 1 : 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(line, "azure", 5);
        memset(line + 5, '.', gap);
        memcpy(line + 5 + gap, key0, sizeof(key0));
        br_slice data = make_input(input, sizeof(input), text(line), text(url0));
        expected_result expected = {.key = text(line), .url = text(url0)};
        expect_results(detector, &ctx, false, data, &expected, gap == 40 ? 1 : 0);
    }
    br_slice data = make_input(input, sizeof(input), text(key0), text(url0));
    expect_results(detector, &ctx, true, data, NULL, 0);
    expect_results(detector, &ctx, true, text(url0), NULL, 0);
    snprintf(line, sizeof(line), "azure %s", key0);
    expect_results(detector, &ctx, true, text(line), NULL, 0);
    expect_results(detector, &ctx, true, (br_slice){0}, NULL, 0);
    CHECK(!http.calls && !http.releases);
}

static void test_url_extraction(const br_detector *detector)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    unsigned char input[512];
    char line[80], url[192], domain[32];
    snprintf(line, sizeof(line), "azure %s", key0);
    const char *invalid[] = {
        "HTTPS://ab.azurewebsites.net/api/Fn", "https://ab.AZUREWEBSITES.net/api/Fn",
        "https://ab.azurewebsites.net/API/Fn", "xhttps://ab.azurewebsites.net/api/Fn",
        "https://a.azurewebsites.net/api/Fn", "https://ab.azurewebsites.net/api/F",
        "https://ab.azurewebsites.net/api/--",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        br_slice data = make_input(input, sizeof(input), text(line), text(invalid[i]));
        expect_results(detector, &ctx, false, data, NULL, 0);
    }
    const struct { const char *input, *url; } valid[] = {
        {url0, url0}, {"https://-Ab-.azurewebsites.net/api/-Fn", "https://-Ab-.azurewebsites.net/api/-Fn"},
        {"https://ab.azurewebsites.net/api/Fn-", "https://ab.azurewebsites.net/api/Fn"},
        {"https://ab.azurewebsites.net/api/Fn?not-code=ignored", "https://ab.azurewebsites.net/api/Fn"},
        {"https://ab.azurewebsites.net/api/Fn/ignored", "https://ab.azurewebsites.net/api/Fn"},
    };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        br_slice data = make_input(input, sizeof(input), text(line), text(valid[i].input));
        expected_result expected = {.key = text(key0), .url = text(valid[i].url)};
        expect_results(detector, &ctx, false, data, &expected, 1);
    }
    for (size_t len = 30; len <= 31; ++len) {
        memset(domain, 'a', len);
        domain[len] = '\0';
        snprintf(url, sizeof(url), "https://%s.azurewebsites.net/api/Fn", domain);
        br_slice data = make_input(input, sizeof(input), text(line), text(url));
        expected_result expected = {.key = text(key0), .url = text(url)};
        expect_results(detector, &ctx, false, data, &expected, len == 30 ? 1 : 0);
    }
    /* Long function names are ALSO key matches via the 'azurewebsites' prefix.
     * Preserve that source overlap instead of imposing a secret/URL exclusion. */
    for (size_t len = 30; len <= 31; ++len) {
        char function[32], derived[96];
        memset(function, 'F', len);
        function[len] = '\0';
        snprintf(url, sizeof(url), "https://ab.azurewebsites.net/api/%s", function);
        snprintf(derived, sizeof(derived), "azurewebsites.net/api/%s", function);
        br_slice data = make_input(input, sizeof(input), text(line), text(url));
        const expected_result expected[] = {
            {.key = text(key0), .url = text(url)}, {.key = text(derived), .url = text(url)},
        };
        expect_results(detector, &ctx, false, data, expected, len == 30 ? 2 : 0);
    }
    CHECK(!http.calls && !http.releases);
}

typedef struct { const expected_result *items; size_t count; uint32_t timeout_limit; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls); /* Immediate ABI1 release, not upstream deferred closes. */
    const expected_result *pair = &expected->items[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && request->detector_type == 973);
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC); /* Never permit a SANE fallback. */
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 10000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 10000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(strlen(request->url) == pair->url.len + 6 + pair->key.len);
    CHECK(!memcmp(request->url, pair->url.data, pair->url.len));
    CHECK(!memcmp(request->url + pair->url.len, "?code=", 6));
    CHECK(!memcmp(request->url + pair->url.len + 6, pair->key.data, pair->key.len));
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ? "TruffleHog function-test" : "TruffleHog"));
}

static void test_occurrences_and_literal_query(const br_detector *detector)
{
    char input[768], padded[24];
    snprintf(padded, sizeof(padded), "%s==", key0);
    snprintf(input, sizeof(input), "azure %s\nazure %s\nazure %s\n%s\n%s\n%s",
             padded, key1, padded, url0, url1, url0);
    expected_result product[9];
    const char *keys[] = {padded, key1, padded}, *urls[] = {url0, url1, url0};
    for (size_t k = 0; k < 3; ++k)
        for (size_t u = 0; u < 3; ++u) product[k * 3 + u] = (expected_result){.key = text(keys[k]), .url = text(urls[u])};
    expected_requests requests = {product, 9, 0};
    test_http http = {.response = {.status = 204, .body_error = "ignored drain failure"},
                      .inspect = inspect_request, .user = &requests};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_results(detector, &ctx, false, text(input), product, 9);
    CHECK(!http.calls && !http.releases);
    for (size_t i = 0; i < 9; ++i) product[i].verified = true;
    expect_results(detector, &ctx, true, text(input), product, 9);
    CHECK(http.calls == 9 && http.releases == 9); /* No success break, deduplication or key consumption. */
    const char *line_formats[] = {"azure=%s==", "azure?state=1&value=+%s", "azure\0 %s"};
    for (size_t i = 0; i < 3; ++i) {
        char line[96], raw[96];
        unsigned char data[256];
        if (i == 2) {
            memcpy(line, "azure\0 ", 7);
            memcpy(line + 7, key0, sizeof(key0));
            memcpy(raw, key0, sizeof(key0));
        } else {
            snprintf(line, sizeof(line), line_formats[i], key0);
            memcpy(raw, line, strlen(line) + 1);
        }
        br_slice joined = make_input(data, sizeof(data), (br_slice){(unsigned char *)line, i == 2 ? 7 + strlen(key0) : strlen(line)}, text(url0));
        expected_result expected = {.key = text(raw), .url = text(url0), .verified = true};
        requests = (expected_requests){&expected, 1, 0};
        http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &requests};
        expect_results(detector, &ctx, true, joined, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1); /* Raw query literal; discarded prefix NUL is harmless. */
    }
}

static void test_request_creation_and_subset(const br_detector *detector)
{
    unsigned char input[512];
    char line[128], raw[128];
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const unsigned char nul[] = "azure \0AbCdEf0123456789_-xY";
    const unsigned char nul_prefix[] = "azure\0AbCdEf0123456789_-xY";
    const unsigned char del[] = "azure\177AbCdEf0123456789_-xY";
    const br_slice invalid[] = {
        {nul, sizeof(nul) - 1}, {nul_prefix, sizeof(nul_prefix) - 1}, {del, sizeof(del) - 1},
        {(const unsigned char *)"azure\tAbCdEf0123456789_-xY", 26},
        {(const unsigned char *)"azure\nAbCdEf0123456789_-xY", 26},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        br_slice data = make_input(input, sizeof(input), invalid[i], text(url0));
        expect_results(detector, &ctx, true, data, NULL, 0);
    }
    snprintf(line, sizeof(line), "azure %s", key0);
    br_slice data = make_input(input, sizeof(input), text(line), text(url0));
    expect_results(detector, NULL, true, data, NULL, 0);
    expected_result canonical = {.key = text(key0), .url = text(url0)};
    expect_results(detector, NULL, false, data, &canonical, 1);
    CHECK(!http.calls && !http.releases);
    const char *unsupported[] = {"azure:#%s", "azure:%%ZZ%s", "azure\xc2\xa0%s"};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(raw, sizeof(raw), unsupported[i], key0);
        data = make_input(input, sizeof(input), text(raw), text(url0));
        expected_result expected = {.key = text(raw), .url = text(url0)};
        expect_results(detector, &ctx, false, data, &expected, 1);
        expected.error = "unsupported: Azure Function key URL form";
        expect_results(detector, &ctx, true, data, &expected, 1);
        CHECK(!http.calls && !http.releases);
    }
    /* A rejected binary key must not abort the scan or hide later valid keys. */
    memcpy(input, nul, sizeof(nul) - 1);
    int n = snprintf((char *)input + sizeof(nul) - 1, sizeof(input) - sizeof(nul) + 1,
                     "\nazure %s\n%s", key1, url0);
    CHECK(n > 0 && (size_t)n < sizeof(input) - sizeof(nul) + 1);
    data = (br_slice){input, sizeof(nul) - 1 + (size_t)n};
    expected_result later = {.key = text(key1), .url = text(url0), .verified = true};
    expected_requests requests = {&later, 1, 0};
    http.inspect = inspect_request;
    http.user = &requests;
    expect_results(detector, &ctx, true, data, &later, 1);
    CHECK(http.calls == 1 && http.releases == 1);
}

static void test_fragment_boundary(const br_detector *detector)
{
    /* Parse checks controls before the FIRST '#', not inside its fragment.
     * All fragments remain guarded, without claiming their constructors fail. */
    const unsigned char before_fragment[] = "azure\0#AbCdEf0123456789_-xY";
    const unsigned char fragment_nul[] = "azure#\0AbCdEf0123456789_-xY";
    const unsigned char fragment_del[] = "azure#\177AbCdEf0123456789_-xY";
    const unsigned char first_fragment[] = "azure#\0#AbCdEf0123456789_-xY";
    const br_slice lines[] = {
        {before_fragment, sizeof(before_fragment) - 1}, {fragment_nul, sizeof(fragment_nul) - 1},
        {fragment_del, sizeof(fragment_del) - 1}, {first_fragment, sizeof(first_fragment) - 1},
    };
    unsigned char input[512];
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); ++i) {
        br_slice data = make_input(input, sizeof(input), lines[i], text(url0));
        expected_result expected = {.key = lines[i], .url = text(url0)};
        expect_results(detector, &ctx, false, data, &expected, 1);
        expected.error = "unsupported: Azure Function key URL form";
        expect_results(detector, &ctx, true, data, &expected, i ? 1 : 0);
        CHECK(!http.calls && !http.releases);
    }
    memcpy(input, fragment_nul, sizeof(fragment_nul) - 1);
    int n = snprintf((char *)input + sizeof(fragment_nul) - 1, sizeof(input) - sizeof(fragment_nul) + 1,
                     "\nazure %s\n%s", key1, url0);
    CHECK(n > 0 && (size_t)n < sizeof(input) - sizeof(fragment_nul) + 1);
    br_slice data = {input, sizeof(fragment_nul) - 1 + (size_t)n};
    const expected_result results[] = {
        {.key = lines[1], .url = text(url0), .error = "unsupported: Azure Function key URL form"},
        {.key = text(key1), .url = text(url0), .verified = true},
    };
    expected_requests requests = {&results[1], 1, 0};
    http.inspect = inspect_request;
    http.user = &requests;
    expect_results(detector, &ctx, true, data, results, 2);
    CHECK(http.calls == 1 && http.releases == 1); /* Guarded fragment does not hide later pairs. */
}

static void test_status_and_errors(const br_detector *detector)
{
    unsigned char input[256];
    char line[64], sensitive[256], redacted[256];
    snprintf(line, sizeof(line), "azure %s==", key0);
    char padded[24];
    snprintf(padded, sizeof(padded), "%s==", key0);
    br_slice data = make_input(input, sizeof(input), text(line), text(url0));
    snprintf(sensitive, sizeof(sensitive), "GET %s?code=%s: repeated %s denied", url0, padded, padded);
    snprintf(redacted, sizeof(redacted), "GET %s?code=[REDACTED]: repeated [REDACTED] denied", url0);
    const struct { int status, send_rc; const char *cause; bool verified; const char *error; } cases[] = {
        {199, 0, NULL, false, "unexpected HTTP response status 199"},
        {200, 0, NULL, true, NULL}, {201, 0, NULL, true, NULL},
        {204, 0, NULL, true, NULL}, {299, 0, NULL, true, NULL},
        {300, 0, NULL, false, "unexpected HTTP response status 300"},
        {401, 0, NULL, false, NULL}, {403, 0, NULL, false, "unexpected HTTP response status 403"},
        {500, 0, NULL, false, "unexpected HTTP response status 500"},
        {200, 1, sensitive, false, redacted},
        {200, 1, "lookup synthetic: no such host", false, "lookup synthetic: no such host"},
        {200, 1, NULL, false, "HTTP transport failed"},
        {200, 1, "unsupported: native curl HTTP client profile", false, "unsupported: native curl HTTP client profile"},
    };
    static const unsigned char body[] = {0, 0xff, '<', 'n', 'o', 't', '-', 'j', 's', 'o', 'n'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_result expected = {.key = text(padded), .url = text(url0), .verified = cases[i].verified, .error = cases[i].error};
        expected_requests requests = {&expected, 1, 0};
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain error"},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &requests};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "function-test"};
        expect_results(detector, &ctx, true, data, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1);
        expected.verified = false;
        expected.error = NULL;
        expect_results(detector, &ctx, false, data, &expected, 1);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context(const br_detector *detector)
{
    unsigned char input[256];
    char line[64];
    snprintf(line, sizeof(line), "azure %s", key0);
    br_slice data = make_input(input, sizeof(input), text(line), text(url0));
    expected_result expected = {.key = text(key0), .url = text(url0), .verified = true};
    expected_requests requests = {&expected, 1, 2000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &requests};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + requests.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_results(detector, &ctx, true, data, &expected, 1);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 1;
    expected.verified = false;
    expected.error = "context deadline exceeded";
    expect_results(detector, &ctx, true, data, &expected, 1);
    CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 0;
    ctx.cancelled = cancelled;
    expected.error = "context canceled";
    expect_results(detector, &ctx, true, data, &expected, 1);
    CHECK(!http.calls && http.releases == 1);
    expected.error = NULL;
    expect_results(detector, &ctx, false, data, &expected, 1);
    CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL;
    http.calls = http.releases = 0;
    requests.timeout_limit = 0;
    expected.verified = true;
    expect_results(detector, &ctx, true, data, &expected, 1);
    CHECK(http.calls == 1 && http.releases == 1);
}

int main(void)
{
    CHECK(strlen(key0) == 20 && strlen(key1) == 20);
    const br_detector *detector = detector_init();
    test_full_match_extraction(detector);
    test_url_extraction(detector);
    test_occurrences_and_literal_query(detector);
    test_request_creation_and_subset(detector);
    test_fragment_boundary(detector);
    test_status_and_errors(detector);
    test_context(detector);
    return test_finish("AzureFunctionKey");
}
