/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { br_slice token, id; } credential;

static br_slice text(const char *value)
{
    return (br_slice){(const unsigned char *)value, strlen(value)};
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_alegra_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_alegra_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 375 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Alegra") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Alegra is a cloud-based accounting software. Alegra API keys can be used to access and modify accounting data and user information."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "alegra"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, credential expected)
{
    CHECK(result->detector_type == 375 && !result->detector_name);
    CHECK(result->raw.len == expected.token.len);
    CHECK(!memcmp(result->raw.data, expected.token.data, expected.token.len));
    CHECK(result->raw_v2.len == expected.token.len + 1 + expected.id.len);
    CHECK(!memcmp(result->raw_v2.data, expected.token.data, expected.token.len));
    CHECK(result->raw_v2.data[expected.token.len] == ':');
    CHECK(!memcmp(result->raw_v2.data + expected.token.len + 1, expected.id.data, expected.id.len));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)expected.token.len);
    CHECK(!memcmp(json_object_get_string(part), expected.token.data, expected.token.len));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)expected.id.len);
    CHECK(!memcmp(json_object_get_string(part), expected.id.data, expected.id.len));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

/* Separate statements by more than PrefixRegex's 40-character gap so the ID
 * match starts at id_line, not at the earlier token's provider keyword. */
static br_slice make_input(unsigned char *out, size_t cap, const char *token, br_slice id_line)
{
    int n = snprintf((char *)out, cap, "alegra %s\n%48s\n", token, "");
    CHECK(n >= 0 && (size_t)n < cap);
    CHECK(id_line.len <= cap - (size_t)n);
    memcpy(out + n, id_line.data, id_line.len);
    return (br_slice){out, (size_t)n + id_line.len};
}

static void expect_extraction(const br_detector *detector, br_slice input,
                              const credential *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *token, const char *other)
{
    unsigned char input[1024];
    char line[256], changed[21];
    const credential one[] = {{text(token), text("u@example.invalid")}};
    br_slice data = make_input(input, sizeof(input), token, text("preALEGRAsuffix: u@example.invalid"));
    expect_extraction(detector, data, one, 1);
    expect_extraction(detector, (br_slice){0}, NULL, 0);
    expect_extraction(detector, text("alegra u@example.invalid"), NULL, 0);
    snprintf(line, sizeof(line), "alegra %s", token);
    expect_extraction(detector, text(line), NULL, 0);
    snprintf(line, sizeof(line), "%s u@example.invalid", token);
    expect_extraction(detector, text(line), NULL, 0);

    const struct { const char *input, *id; } tails[] = {
        {"alegra = u@example.invalid", "u@example.invalid"},
        {"alegra \tu@example.invalid", "\tu@example.invalid"},
        {"alegra \r\nu@example.invalid", "\r\nu@example.invalid"},
        {"alegra\tu@example.invalid", "alegra\tu@example.invalid"},
        {"alegra\r\nu@example.invalid", "alegra\r\nu@example.invalid"},
        {"preALEGRAsuffix:u@example.invalid", "ALEGRAsuffix:u@example.invalid"},
        {"alegra User+tag@Example.invalid", "User+tag@Example.invalid"},
        {"alegra x\"a\\ b\"@Example.invalid", "b\"@Example.invalid"},
        {"alegra user@[127.0.0.1]x", "user@[127.0.0.1]"},
    };
    for (size_t i = 0; i < sizeof(tails) / sizeof(tails[0]); ++i) {
        const credential expected[] = {{text(token), text(tails[i].id)}};
        data = make_input(input, sizeof(input), token, text(tails[i].input));
        expect_extraction(detector, data, expected, 1);
    }
    data = make_input(input, sizeof(input), token, text("alegra user@[127.0.0.1]"));
    expect_extraction(detector, data, NULL, 0); /* The pinned EmailPattern ends in a word boundary. */

    const unsigned char nul_line[] = "alegra\0u@example.invalid";
    const unsigned char nul_first[] = "alegra \0u@example.invalid";
    const unsigned char nul_gap[] = "alegra\0gap u@example.invalid";
    const credential binary[] = {{text(token), {nul_line, sizeof(nul_line) - 1}}};
    data = make_input(input, sizeof(input), token, (br_slice){nul_line, sizeof(nul_line) - 1});
    expect_extraction(detector, data, binary, 1);
    const credential leading_nul[] = {{text(token), {nul_first + 7, sizeof(nul_first) - 8}}};
    data = make_input(input, sizeof(input), token, (br_slice){nul_first, sizeof(nul_first) - 1});
    expect_extraction(detector, data, leading_nul, 1);
    data = make_input(input, sizeof(input), token, (br_slice){nul_gap, sizeof(nul_gap) - 1});
    expect_extraction(detector, data, one, 1);

    char padding[42];
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(line, sizeof(line), "alegra%.*s%s", gap, padding, token);
        int n = snprintf((char *)input, sizeof(input), "%s\n%48s\nalegra u@example.invalid", line, "");
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_extraction(detector, (br_slice){input, (size_t)n}, one, gap == 40 ? 1 : 0);
        snprintf(line, sizeof(line), "alegra%.*su@example.invalid", gap, padding);
        data = make_input(input, sizeof(input), token, text(line));
        expect_extraction(detector, data, one, gap == 40 ? 1 : 0);
    }
    const char *invalid_tokens[] = {"_%s", "%s_", "%.19s", "%sz"};
    for (size_t i = 0; i < sizeof(invalid_tokens) / sizeof(invalid_tokens[0]); ++i) {
        char invalid[24];
        snprintf(invalid, sizeof(invalid), invalid_tokens[i], token);
        data = make_input(input, sizeof(input), invalid, text("alegra u@example.invalid"));
        expect_extraction(detector, data, NULL, 0);
    }
    memcpy(changed, token, sizeof(changed));
    changed[10] = 'A';
    data = make_input(input, sizeof(input), changed, text("alegra u@example.invalid"));
    expect_extraction(detector, data, NULL, 0);
    changed[10] = '-';
    const credential hyphen[] = {{text(changed), one[0].id}};
    data = make_input(input, sizeof(input), changed, text("alegra u@example.invalid"));
    expect_extraction(detector, data, hyphen, 1);
    memset(changed, 'a', 20);
    changed[20] = '\0';
    const credential low_entropy[] = {{text(changed), one[0].id}};
    data = make_input(input, sizeof(input), changed, text("alegra u@example.invalid"));
    expect_extraction(detector, data, low_entropy, 1);

    int n = snprintf((char *)input, sizeof(input),
        "alegra %s\nalegra %s\nalegra %s\n%48s\nalegra User@Example.invalid\nalegra u@example.invalid\nalegra User@Example.invalid",
        other, token, other, "");
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const credential product[] = {
        {text(other), text("User@Example.invalid")}, {text(other), one[0].id},
        {text(token), text("User@Example.invalid")}, one[0],
    };
    expect_extraction(detector, (br_slice){input, (size_t)n}, product, 4);

    static const unsigned char binary_lines[] =
        "alegra\0u@example.invalid\nalegra\0v@example.invalid\nalegra\0u@example.invalid";
    static const unsigned char second_id[] = "alegra\0v@example.invalid";
    const credential unique_binary[] = {binary[0], {text(token), {second_id, sizeof(second_id) - 1}}};
    data = make_input(input, sizeof(input), token, (br_slice){binary_lines, sizeof(binary_lines) - 1});
    expect_extraction(detector, data, unique_binary, 2);
}

typedef struct { const credential *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    credential pair = expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.alegra.com/api/v1/users/self"));
    CHECK(request->detector_type == 375 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    char *auth = NULL;
    CHECK(br_http_basic_auth(pair.id, pair.token, &auth, NULL) == 0 && auth);
    CHECK(!strcmp(request->headers[0].value, auth));
    free(auth);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog alegra-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                br_slice input, credential pair, bool verified, const char *error)
{
    expected_requests expected = {&pair, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "alegra-test"};
    br_results results = test_scan(detector, &ctx, true, input.data, input.len);
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_pair(&results.items[0], pair);
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
        char token[21];
        memcpy(token, pair.token.data, pair.token.len);
        token[pair.token.len] = '\0';
        CHECK(!strstr(results.items[0].verification_error, token));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *token, const char *other)
{
    unsigned char input[512];
    credential pair = {text(token), text("u@example.invalid")};
    br_slice data = make_input(input, sizeof(input), token, text("alegra u@example.invalid"));
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {401, false, NULL},
        {403, false, "unexpected HTTP response status 403"},
        {201, false, "unexpected HTTP response status 201"},
        {500, false, "unexpected HTTP response status 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = "ignored drain failure"}};
        expect_verification(detector, &http, data, pair, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, data, pair, false, send_errors[i]);
    }
    char sensitive_error[128];
    snprintf(sensitive_error, sizeof(sensitive_error),
             "account u@example.invalid rejected %s then %s", token, token);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, data, pair, false,
                        "account u@example.invalid rejected [REDACTED] then [REDACTED]");
    http.send_error = NULL;
    expect_verification(detector, &http, data, pair, false, "HTTP transport failed");

    static const unsigned char binary_line[] = "alegra\0u@example.invalid";
    data = make_input(input, sizeof(input), token, (br_slice){binary_line, sizeof(binary_line) - 1});
    pair.id = (br_slice){binary_line, sizeof(binary_line) - 1};
    http = (test_http){.response = {.status = 200}};
    expect_verification(detector, &http, data, pair, true, NULL);

    /* Request creation's nil-context error is suppressed, unlike transport failure. */
    br_results results = test_scan(detector, NULL, true, data.data, data.len);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    check_pair(&results.items[0], pair);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    results = test_scan(detector, &offline, true, data.data, data.len);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    check_pair(&results.items[0], pair);
    br_results_clear(&results);

    const credential product[] = {
        {text(other), text("u@example.invalid")}, {text(other), text("v@example.invalid")},
        {text(token), text("u@example.invalid")}, {text(token), text("v@example.invalid")},
    };
    int n = snprintf((char *)input, sizeof(input),
        "alegra %s\nalegra %s\nalegra %s\n%48s\nalegra u@example.invalid\nalegra v@example.invalid\nalegra u@example.invalid",
        other, token, other, "");
    CHECK(n > 0 && (size_t)n < sizeof(input));
    expected_requests expected = {product, 4};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "alegra-test"};
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], product[i]);
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, "alegra u@example.invalid", strlen("alegra u@example.invalid"));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char token[21], other[21];
    test_secret(token, 20, 0);
    test_secret(other, 20, 9);
    extraction(detector, token, other);
    verification(detector, token, other);
    return test_finish("Alegra");
}
