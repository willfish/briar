/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static void check_descriptor(const br_detector *detector, int32_t type, const char *name)
{
    CHECK(detector->type == type && detector->version == 0);
    CHECK(!strcmp(detector->name, name) && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Airtable is a cloud collaboration service that offers database-like features. Airtable OAuth tokens can be used to access and modify data within Airtable bases."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "airtable"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_detector_is_default(detector, NULL));
}

static void expect_extraction(const br_detector *detector, const char *input,
                              const char *const *tokens, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], detector->type, tokens[i], "token");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void oauth_extraction(const br_detector *detector, const char *token)
{
    const char *one[] = {token};
    /* Direct scans do not require the engine's airtable keyword. */
    expect_extraction(detector, token, one, 1);
    const struct { const char *input, *captured; } cases[] = {
        {"A.v1.B.c", "A.v1.B.c"}, {"9.v1._-.0", "9.v1._-.0"},
        {"Token.V1.Payload.abc", NULL}, {"Token.v2.Payload.abc", NULL},
        {"Token.v1.Payload.ABC", NULL}, {"Token.v1.Payload.abz", NULL},
        {"Token.v1..abc", NULL}, {".v1.Payload.abc", NULL},
        {"Token.v1.Payload.", NULL}, {"_.v1.Payload.abc", NULL},
        {"\xc3\xa9.v1.Payload.abc", NULL}, {"Token.v1.\xc3\xa9.abc", NULL},
        {"_Token.v1.Payload.abc", NULL}, {"Token.v1.Payload.abc_", NULL},
        {"Token.v1.Payload.abc-extra", "Token.v1.Payload.abc"},
        {"Token.v1.Payload.abc.more", "Token.v1.Payload.abc"},
        {"\xc3\xa9Token.v1.Payload.abc\xc3\xa9", "Token.v1.Payload.abc"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const char *expected[] = {cases[i].captured};
        expect_extraction(detector, cases[i].input, expected, cases[i].captured ? 1 : 0);
    }
    expect_extraction(detector, "", NULL, 0);
}

static void pat_extraction(const br_detector *detector, const char *token)
{
    char input[256], changed[83];
    const char *one[] = {token};
    CHECK(strlen(token) == 82);
    expect_extraction(detector, token, NULL, 0);
    snprintf(input, sizeof(input), "%s airtable", token);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "preAIRTABLEsuffix:'%s'", token);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "AiRtAbLe\r\n'%s'", token);
    expect_extraction(detector, input, one, 1);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "airtable%.*s%s", gap,
                 "-----------------------------------------", token);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *invalid_forms[] = {
        "airtable _%s", "airtable %s_", "airtable %.81s", "airtable %sf",
    };
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], token);
        expect_extraction(detector, input, NULL, 0);
    }
    const struct { size_t at; char value; } mutations[] = {
        {0, 'P'}, {3, '_'}, {3, '-'}, {18, 'A'},
    };
    for (size_t i = 0; i < sizeof(mutations) / sizeof(mutations[0]); ++i) {
        memcpy(changed, token, sizeof(changed));
        changed[mutations[i].at] = mutations[i].value;
        snprintf(input, sizeof(input), "airtable %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "airtable pat%.*s.%s", 13, token + 3, token + 18);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "airtable pat%.*sZ.%s", 14, token + 3, token + 18);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "airtable patAbCd\xc3\xa9" "f01234567.%s", token + 18);
    expect_extraction(detector, input, NULL, 0);
    expect_extraction(detector, "", NULL, 0);
}

typedef struct {
    int32_t type;
    const char *const *tokens;
    size_t count;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    const char *token = expected->tokens[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.airtable.com/v0/meta/whoami"));
    CHECK(request->detector_type == expected->type && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, token));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog airtable-test"));
}

static void uniqueness(const br_detector *detector, const char *prefix,
                        const char *token, const char *other)
{
    char input[512];
    snprintf(input, sizeof(input), "%s%s\n%s%s\n%s%s", prefix, other, prefix, token, prefix, other);
    const char *tokens[] = {other, token};
    expected_requests expected = {detector->type, tokens, 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "airtable-test"};
    for (int verify = 0; verify <= 1; ++verify) {
        http.calls = http.releases = 0;
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 2);
        CHECK(http.calls == (verify ? 2u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < results.len; ++i) {
            test_key_result(&results.items[i], detector->type, tokens[i], "token");
            CHECK(results.items[i].verified == (bool)verify && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void expect_verification(const br_detector *detector, test_http *http,
                                const char *input, const char *token,
                                bool verified, const char *error)
{
    const char *tokens[] = {token};
    expected_requests expected = {detector->type, tokens, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "airtable-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], detector->type, token, "token");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
        CHECK(!strstr(results.items[0].verification_error, token));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *input, const char *token)
{
    const struct {
        int status;
        const char *body_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, NULL, true, NULL}, {200, "ignored drain failure", true, NULL},
        {401, "ignored drain failure", false, NULL},
        {403, "ignored drain failure", false, "unexpected HTTP response status 403"},
        {201, "ignored drain failure", false, "unexpected HTTP response status 201"},
        {500, "ignored drain failure", false, "unexpected HTTP response status 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = cases[i].body_error}};
        expect_verification(detector, &http, input, token, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, input, token, false, send_errors[i]);
    }
    char sensitive_error[256];
    snprintf(sensitive_error, sizeof(sensitive_error),
             "request %s failed for synthetic-account: %s", token, token);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, input, token, false,
                        "request [REDACTED] failed for synthetic-account: [REDACTED]");
    http.send_error = NULL;
    expect_verification(detector, &http, input, token, false, "HTTP transport failed");

    http = (test_http){0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, "airtable", strlen("airtable"));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

static void long_oauth(const br_detector *detector)
{
    const size_t part = 4096, len = part * 3 + 5;
    char *token = malloc(len + 1);
    CHECK(token != NULL);
    memset(token, 'A', part);
    memcpy(token + part, ".v1.", 4);
    memset(token + part + 4, '_', part);
    token[part * 2 + 4] = '.';
    memset(token + part * 2 + 5, 'f', part);
    token[len] = '\0';
    const char *one[] = {token};
    expect_extraction(detector, token, one, 1);
    test_http http = {.response = {.status = 200, .body_error = "ignored drain failure"}};
    expect_verification(detector, &http, token, token, true, NULL);
    free(token);
}

int main(void)
{
    const br_detector *oauth = NULL, *pat = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_airtableoauth_init(&oauth, &error) == 0 && !error && oauth);
    CHECK(br_airtablepersonalaccesstoken_init(&pat, &error) == 0 && !error && pat);
    const void *oauth_state = oauth->state, *pat_state = pat->state;
    CHECK(br_airtableoauth_init(&again, &error) == 0 && !error && again == oauth);
    CHECK(oauth->state == oauth_state);
    CHECK(br_airtablepersonalaccesstoken_init(&again, &error) == 0 && !error && again == pat);
    CHECK(pat->state == pat_state);
    CHECK(oauth != pat && oauth_state != pat_state && oauth->scan == pat->scan);
    check_descriptor(oauth, 1014, "AirtableOAuth");
    check_descriptor(pat, 1015, "AirtablePersonalAccessToken");

    const char *oauth_token = "Synthetic7.v1.Synthetic_-Payload.1a2b3c";
    const char *oauth_other = "Other9.v1._-Synthetic.9f8e7d";
    const char *pat_token = "patAbCdEf01234567."
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *pat_other = "patZyXwVu76543210."
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    oauth_extraction(oauth, oauth_token);
    pat_extraction(pat, pat_token);
    uniqueness(oauth, "", oauth_token, oauth_other);
    uniqueness(pat, "airtable ", pat_token, pat_other);
    verification(oauth, oauth_token, oauth_token);
    char pat_input[96];
    snprintf(pat_input, sizeof(pat_input), "airtable %s", pat_token);
    verification(pat, pat_input, pat_token);
    long_oauth(oauth);
    return test_finish("Airtable OAuth/PAT");
}
