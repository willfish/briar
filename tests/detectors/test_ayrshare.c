/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char synthetic_key[] = "G7H9J2K5-M6N8P3Q4-R1S0T2U4-V6W8X1Y3";
static const char synthetic_other[] = "Z8Y7X6W5-V4U3T2S1-R0Q9P8N7-M6K5J4H3";
typedef struct { const char *const *keys; size_t len; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_ayrshare_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 163 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Ayrshare"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Ayrshare provides social media management services. "
        "Ayrshare API keys can be used to manage social media accounts and posts."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ayrshare"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_ayrshare_init(&again, &error) == 0 && !error && again == detector);
    CHECK(br_ayrshare_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                              const void *input, size_t len, const char *key, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 163, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256];
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    /* The synthetic uppercase keys are 8-8-8-8 alphanumeric, not hex/UUIDs. */
    const struct { const char *format; size_t count; } cases[] = {
        {"ayrshare '%s'", 1},
        {"AYRSHARE = %s", 1},
        {"prefixayrsharesuffix %s", 1},
        {"%s", 0},
        {"ayr share %s", 0},
        {"ayrshare _%s", 0},
        {"ayrshare %s_", 0},
        {"ayrshare %sZ", 0},
        {"ayrshare %.34s", 0},
        {"ayrshare\r\n'%s'", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, synthetic_key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)len, synthetic_key, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ayrshare", 8);
        memset(input + 8, '-', gap);
        snprintf(input + 8 + gap, sizeof(input) - 8 - gap, "%s", synthetic_key);
        expect_extraction(detector, &ctx, input, strlen(input), synthetic_key, gap == 40 ? 1 : 0);
    }
    char changed[sizeof(synthetic_key)];
    memcpy(changed, synthetic_key, sizeof(changed));
    changed[0] = 'g';
    snprintf(input, sizeof(input), "ayrshare %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memcpy(changed, synthetic_key, sizeof(changed));
    changed[8] = '_';
    snprintf(input, sizeof(input), "ayrshare %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    const char uuid[] = "ayrshare A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6";
    expect_extraction(detector, &ctx, uuid, sizeof(uuid) - 1, NULL, 0);
    const char zeros[] = "00000000-00000000-00000000-00000000";
    snprintf(input, sizeof(input), "ayrshare %s", zeros);
    expect_extraction(detector, &ctx, input, strlen(input), zeros, 1);
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    char authorization[sizeof("Bearer ") + 35];
    snprintf(authorization, sizeof(authorization), "Bearer %s", expected->keys[http->calls - 1]);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://app.ayrshare.com/api/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 163);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ?
                  "TruffleHog ayrshare-test" : "TruffleHog"));
}

static void test_occurrences(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "ayrshare %s\nayrshare %s\nayrshare %s",
             synthetic_key, synthetic_other, synthetic_key);
    const char *keys[] = {synthetic_key, synthetic_other, synthetic_key};
    expected_requests expected = {keys, sizeof(keys) / sizeof(keys[0])};
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {
            .response = {.status = 200}, .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == expected.len);
        CHECK(http.calls == (verify ? expected.len : 0) && http.releases == http.calls);
        for (size_t i = 0; i < results.len; ++i) {
            test_key_result(&results.items[i], 163, keys[i], "key");
            CHECK(results.items[i].verified == (bool)verify && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_email_enrichment(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "ayrshare %s", synthetic_key);
    const char *keys[] = {synthetic_key};
    expected_requests expected = {keys, 1};
    static const char nul_email[] = "before\0after";
    const struct { const char *body, *email; size_t email_len; } cases[] = {
        {"{\"email\":\"kept\"}", "kept", 4},
        {" \r\n{\"email\":\"\"}\n\t", "", 0},
        {"{\"email\":\"before\\u0000after\"}", nul_email, sizeof(nul_email) - 1},
        {"{\"email\":\"first\",\"email\":\"last\"}", "last", 4},
        {"{\"email\":\"first\",\"em\\u0061il\":\"last\"}", "last", 4},
        {"{\"email\":\"first\",\"email\":null}", NULL, 0},
        {"{\"email\":\"first\",\"email\":42}", NULL, 0},
        {"{\"email\":false,\"email\":\"\"}", "", 0},
        {"{\"Email\":\"other\",\"nested\":{\"email\":\"other\"}}", NULL, 0},
        {"{\"email\":\"kept\",\"email\\u0000suffix\":\"other\"}", "kept", 4},
        {"null", NULL, 0},
        {"[\"email\"]", NULL, 0},
        {"\"email\"", NULL, 0},
        {"42", NULL, 0},
        {"true", NULL, 0},
        {"", NULL, 0},
        {"{\"email\":\"partial\"", NULL, 0},
        {"{\"email\":\"kept\",\"broken\":}", NULL, 0},
        {"{\"email\":\"kept\"} trailing", NULL, 0},
        {"{\"email\":\"kept\"}{\"email\":\"other\"}", NULL, 0},
        {"{\"email\":\"kept\",\"n\":1e400}", NULL, 0},
        {"{\"email\":\"kept\",\"nested\":{\"n\":1e400}}", NULL, 0},
        {"{\"email\":\"kept\",\"n\":1e400,\"n\":0}", NULL, 0},
        {"{\"email\":1e400,\"email\":\"last\"}", NULL, 0},
        {"{\"email\":\"kept\",\"n\":1e-400}", "kept", 4},
        {"{\"email\":\"kept\",\"n\":18446744073709551616}", "kept", 4},
        {"{\"email\":\"kept\",\"n\":\"1e400\"}", "kept", 4},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = 200,
                         .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}},
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        br_result key_fields = *result;
        key_fields.extra_data = NULL;
        test_key_result(&key_fields, 163, synthetic_key, "key");
        CHECK(result->verified && !result->verification_error);
        if (cases[i].email) {
            CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
            br_json *email = NULL;
            CHECK(json_object_object_get_ex(result->extra_data, "email", &email));
            CHECK(json_object_is_type(email, json_type_string));
            CHECK((size_t)json_object_get_string_len(email) == cases[i].email_len);
            CHECK(!memcmp(json_object_get_string(email), cases[i].email, cases[i].email_len));
        } else CHECK(!result->extra_data);
        br_results_clear(&results);
    }
}

static void test_verification_branches(const br_detector *detector)
{
    char input[64], sensitive_error[128];
    snprintf(input, sizeof(input), "ayrshare %s", synthetic_key);
    snprintf(sensitive_error, sizeof(sensitive_error), "key=%s again=%s", synthetic_key, synthetic_key);
    const char *keys[] = {synthetic_key};
    expected_requests expected = {keys, 1};
    static const unsigned char valid[] = "{\"email\":\"must not be retained\"}";
    static const unsigned char invalid_key[] = "\0prefix API Key not valid suffix";
    static const unsigned char wrong_case[] = "api key not valid";
    const struct {
        int status;
        br_slice body;
        const char *read_error;
        int send_rc;
        const char *send_error, *error;
    } cases[] = {
        {200, {valid, sizeof(valid) - 1}, sensitive_error, 0, NULL,
         "key=[REDACTED] again=[REDACTED]"},
        {401, {valid, sizeof(valid) - 1}, sensitive_error, 0, NULL, NULL},
        {403, {invalid_key, sizeof(invalid_key) - 1}, NULL, 0, NULL, NULL},
        {403, {invalid_key, sizeof(invalid_key) - 1}, sensitive_error, 0, NULL,
         "key=[REDACTED] again=[REDACTED]"},
        {403, {NULL, 0}, NULL, 0, NULL, "unexpected status code: 403"},
        {403, {wrong_case, sizeof(wrong_case) - 1}, NULL, 0, NULL, "unexpected status code: 403"},
        {201, {valid, sizeof(valid) - 1}, sensitive_error, 0, NULL, "unexpected status code: 201"},
        {302, {NULL, 0}, NULL, 0, NULL, "unexpected status code: 302"},
        {429, {NULL, 0}, NULL, 0, NULL, "unexpected status code: 429"},
        {500, {invalid_key, sizeof(invalid_key) - 1}, sensitive_error, 0, NULL,
         "unexpected status code: 500"},
        {200, {valid, sizeof(valid) - 1}, NULL, 1, sensitive_error,
         "key=[REDACTED] again=[REDACTED]"},
        {200, {valid, sizeof(valid) - 1}, NULL, 1, "context deadline exceeded", "context deadline exceeded"},
        {200, {valid, sizeof(valid) - 1}, NULL, 1, "context canceled", "context canceled"},
        {200, {valid, sizeof(valid) - 1}, NULL, 1, NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status, .body = cases[i].body,
                         .body_error = cases[i].read_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "ayrshare-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        test_key_result(result, 163, synthetic_key, "key");
        CHECK(!result->verified);
        if (cases[i].error) {
            CHECK(result->verification_error && !strcmp(result->verification_error, cases[i].error));
            CHECK(!strstr(result->verification_error, synthetic_key));
        } else CHECK(!result->verification_error);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_occurrences(detector);
    test_email_enrichment(detector);
    test_verification_branches(detector);
    return test_finish("Ayrshare");
}
