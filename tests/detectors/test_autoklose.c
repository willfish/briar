/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[33], other[33];

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_autoklose_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_autoklose_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_autoklose_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 323 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Autoklose") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Autoklose is a sales automation tool that allows users to streamline their email outreach and follow-up processes. "
        "Autoklose API tokens can be used to access and manage campaigns, contacts, and other related data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "autoklose"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *token, const char *email, size_t email_len)
{
    /* Reuse the common key checks; check the optional enrichment separately.
     * This borrowed copy is never cleared or used to transfer ownership. */
    br_result base = *result;
    base.extra_data = NULL;
    test_key_result(&base, 323, token, "key");
    if (!email) CHECK(!result->extra_data);
    else {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        br_json *value = NULL;
        CHECK(json_object_object_get_ex(result->extra_data, "email", &value));
        CHECK(json_object_is_type(value, json_type_string) && (size_t)json_object_get_string_len(value) == email_len);
        CHECK(!email_len || !memcmp(json_object_get_string(value), email, email_len));
    }
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const char *const *tokens, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        check_result(&results.items[i], tokens[i], NULL, 0);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[33];
    const char *const one[] = {key}, *const hyphenated[] = {other}, *const ordered[] = {key, other, key};
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "autoklose %s", other);
    expect_extraction(detector, input, hyphenated, 1);
    snprintf(input, sizeof(input), "preAUTOKLOSEsuffix:%s\nautoklose\r\n%s\nautoklose %s", key, other, key);
    expect_extraction(detector, input, ordered, 3);
    snprintf(input, sizeof(input), "autoklose \xc3\xa9%s\xc3\xa9", key);
    expect_extraction(detector, input, one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "autoklose");
        memset(input + at, '-', gap);
        snprintf(input + at + gap, sizeof(input) - at - gap, "%s", key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *const wrappers[] = {"autoklose _%s", "autoklose %s_", "autoklose %sQ"};
    for (size_t i = 0; i < sizeof(wrappers) / sizeof(wrappers[0]); ++i) {
        snprintf(input, sizeof(input), wrappers[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "autoklose %.31s", key);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[7] = '%';
    snprintf(input, sizeof(input), "autoklose %s", changed);
    expect_extraction(detector, input, NULL, 0);
    const char *const local[] = {changed};
    memset(changed, 'a', 32);
    changed[32] = '\0';
    snprintf(input, sizeof(input), "autoklose %s", changed);
    expect_extraction(detector, input, local, 1);
    /* Hyphens at capture edges use the source's literal word boundaries. */
    memcpy(changed, key, sizeof(changed));
    changed[0] = '-';
    snprintf(input, sizeof(input), "autoklose Q%s", changed);
    expect_extraction(detector, input, local, 1);
    snprintf(input, sizeof(input), "autoklose %s", changed);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[31] = '-';
    snprintf(input, sizeof(input), "autoklose %sQ", changed);
    expect_extraction(detector, input, local, 1);
}

typedef struct { const char *const *tokens; size_t count; } requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    char url[128];
    snprintf(url, sizeof(url), "https://api.autoklose.com/api/me/?api_token=%s", expected->tokens[http->calls - 1]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 323);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog autoklose-test"));
}

typedef struct {
    const char *body, *body_error, *email, *error;
    size_t email_len;
    int status, send_rc;
    const char *send_error;
} verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[64];
    snprintf(input, sizeof(input), "autoklose %s", key);
    const char *const tokens[] = {key};
    requests expected = {tokens, 1};
    test_http http = {
        .response = {.status = fixture.status ? fixture.status : 200,
            .body = {(const unsigned char *)fixture.body, fixture.body ? strlen(fixture.body) : 0}, .body_error = fixture.body_error},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error, .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "autoklose-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, fixture.email,
                 fixture.email_len ? fixture.email_len : fixture.email ? strlen(fixture.email) : 0);
    CHECK(results.items[0].verified == (!fixture.error && (!fixture.status || fixture.status == 200)));
    if (fixture.error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, fixture.error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void responses(const br_detector *detector)
{
    const verification_case fixtures[] = {
        {.body = "{\"email\":\"synthetic@example.invalid\"}", .email = "synthetic@example.invalid"},
        {.body = "{}"},
        {.body = "null"},
        {.body = "{\"email\":null}"},
        {.body = "{\"email\":42}"},
        {.body = "{\"email\":[\"not a string\"]}"},
        {.body = "{\"email\":\"\"}", .email = ""},
        {.body = "{\"email\":\"A\\u0000B\"}", .email = "A\0B", .email_len = 3},
        {.body = "{\"email\":\"first\",\"email\":\"last\"}", .email = "last"},
        {.body = "{\"email\":\"first\",\"email\":null}"},
        {.body = "{\"email\":\"first\",\"email\":false}"},
        {.body = "{\"email\":null,\"email\":\"last\"}", .email = "last"},
        {.body = "{\"EMAIL\":\"ignored\",\"nested\":{\"email\":\"ignored\"}}"},
        {.body = "{\"email\\u0000suffix\":\"ignored\"}"},
        {.body = "{\"email\":\"keep\",\"email\\u0000suffix\":\"ignored\"}", .email = "keep"},
        {.body = "{\"1e309\":\"ignored\",\"email\":\"text \\\"1e309\\\" and \\\\ end\"}", .email = "text \"1e309\" and \\ end"},
        {.body = "{\"email\":\"kept\" \n } \t\r\n", .email = "kept"},
        {.body = "{\"email\":\"must not escape\"} {}", .error = "invalid character '{' after top-level value"},
        {.body = "", .error = "unexpected end of JSON input"},
        {.body = "{\"email\":", .error = "unexpected end of JSON input"},
        {.body = "{\"email\":\"must not escape\"}", .body_error = "read failed", .error = "read failed"},
        {.body = "{\"n\":1e309}", .body_error = "read failed before decoding", .error = "read failed before decoding"},
        {.body = "true", .error = "json: cannot unmarshal bool into Go value of type map[string]interface {}"},
        {.body = "\"email\"", .error = "json: cannot unmarshal string into Go value of type map[string]interface {}"},
        {.body = "[1e309]", .error = "json: cannot unmarshal array into Go value of type map[string]interface {}"},
        {.body = "1e309", .error = "json: cannot unmarshal number into Go value of type map[string]interface {}"},
        {.status = 401, .body = "not JSON", .body_error = "ignored"},
        {.status = 403, .body_error = "ignored", .error = "unexpected status code: 403"},
        {.status = 500, .error = "unexpected status code: 500"},
        {.status = 201, .body = "{}", .error = "unexpected status code: 201"},
        {.send_rc = -1, .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.send_rc = -1, .send_error = "context canceled", .error = "context canceled"},
        {.send_rc = -1, .error = "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); ++i) verify_case(detector, fixtures[i]);
}

static void numeric_ranges(const br_detector *detector)
{
    /* Source/stdlib probe regressions: int64 saturation is NOT float64 overflow,
     * and ERANGE on finite underflow must not reject a generic-map response. */
    verify_case(detector, (verification_case){.body = "{\"n\":10000000000000000000000000000000000000000,\"email\":\"finite\"}", .email = "finite"});
    verify_case(detector, (verification_case){.body = "{\"n\":1e308,\"email\":\"finite exponent\"}", .email = "finite exponent"});
    verify_case(detector, (verification_case){.body = "{\"n\":1e-4000,\"email\":\"underflow\"}", .email = "underflow"});
    const char *const overflow[] = {
        "{\"n\":1e309,\"email\":\"must not escape\"}",
        "{\"ignored\":[{\"n\":1e309}],\"email\":\"must not escape\"}",
        "{\"n\":1e309,\"n\":0,\"email\":\"must not escape\"}",
        "{\"n\":{\"x\":1e309},\"n\":{},\"email\":\"must not escape\"}",
        "{\"email\":{\"n\":1e309},\"email\":\"must not escape\"}",
    };
    const char *range_error = "json: cannot unmarshal number 1e309 into Go value of type float64";
    for (size_t i = 0; i < sizeof(overflow) / sizeof(overflow[0]); ++i)
        verify_case(detector, (verification_case){.body = overflow[i], .error = range_error});
    verify_case(detector, (verification_case){.body = "{\"n\":-1E+309}",
        .error = "json: cannot unmarshal number -1E+309 into Go value of type float64"});

    char number[311], body[512], cause[512];
    number[0] = '1';
    memset(number + 1, '0', 309);
    number[310] = '\0';
    snprintf(body, sizeof(body), "{\"n\":%s,\"email\":\"must not escape\"}", number);
    snprintf(cause, sizeof(cause), "json: cannot unmarshal number %s into Go value of type float64", number);
    verify_case(detector, (verification_case){.body = body, .error = cause});
}

static void duplicates_and_redaction(const br_detector *detector)
{
    char input[192], cause[192], for_key[192], for_other[192];
    snprintf(input, sizeof(input), "autoklose %s\nautoklose %s\nautoklose %s", key, other, key);
    snprintf(cause, sizeof(cause), "key=%s repeated=%s other=%s", key, key, other);
    snprintf(for_key, sizeof(for_key), "key=[REDACTED] repeated=[REDACTED] other=%s", other);
    snprintf(for_other, sizeof(for_other), "key=%s repeated=%s other=[REDACTED]", key, key);
    const char *const tokens[] = {key, other, key};
    static const unsigned char body[] = "{\"email\":\"synthetic@example.invalid\"}";
    for (int mode = 0; mode < 2; ++mode) {
        requests expected = {tokens, 3};
        test_http http = {
            .response = {.status = 200, .body = {body, sizeof(body) - 1}},
            .send_rc = mode ? -1 : 0, .send_error = mode ? cause : NULL, .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "autoklose-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t r = 0; r < results.len; ++r) {
            check_result(&results.items[r], tokens[r], mode ? NULL : "synthetic@example.invalid", strlen("synthetic@example.invalid"));
            CHECK(results.items[r].verified == (mode == 0));
            if (mode) CHECK(results.items[r].verification_error && !strcmp(results.items[r].verification_error, r == 1 ? for_other : for_key));
            else CHECK(!results.items[r].verification_error);
        }
        br_results_clear(&results);
    }
    verify_case(detector, (verification_case){.body = "{\"email\":", .body_error = cause, .error = for_key});

    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t r = 0; r < results.len; ++r) {
        check_result(&results.items[r], tokens[r], NULL, 0);
        CHECK(!results.items[r].verified && results.items[r].verification_error &&
              !strcmp(results.items[r].verification_error, "HTTP transport not installed"));
    }
    br_results_clear(&results);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, "autoklose too-short", strlen("autoklose too-short"));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other, 32, 9);
    key[0] = 'B';
    other[0] = 'M';
    other[7] = '-';
    other[19] = '-';
    const br_detector *detector = detector_init();
    extraction(detector);
    responses(detector);
    numeric_ranges(detector);
    duplicates_and_redaction(detector);
    return test_finish("Autoklose");
}
