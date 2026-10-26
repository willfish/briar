/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static char token[41], other[41];
typedef struct { const char *const *tokens; size_t count; uint32_t timeout_limit; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bitlyaccesstoken_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 43 && detector->version == 0);
    CHECK(!strcmp(detector->name, "BitLyAccessToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Bitly is a URL shortening service. Bitly access tokens can be used to interact with "
        "the Bitly API, allowing users to create, manage, and track shortened URLs."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bitly"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_bitlyaccesstoken_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_bitlyaccesstoken_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_bitlyaccesstoken_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_bitlyaccesstoken_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                               const void *input, size_t len, const char *const *tokens, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 43, tokens[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[41];
    const char *one[] = {token};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"bitly = '%s'", 1}, {"BITLY: %s", 1}, {"preBiTlYsuffix=%s", 1},
        {"%s", 0}, {"%s bitly", 0}, {"bitly%s", 0},
        {"bitly _%s", 0}, {"bitly %s_", 0}, {"bitly %sQ", 0},
        {"bitly %.39s", 0}, {"bitly\r\n%s", 1}, {"bitly %s=", 1},
        {"bitly %s %s", 1}, /* A later occurrence needs its own keyword prefix. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].format, token, other);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)n, one, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    memcpy(changed, token, sizeof(token));
    const char *changed_token[] = {changed};
    changed[10] = '-';
    snprintf(input, sizeof(input), "bitly %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), changed_token, 1); /* Literal hyphen, not strict alnum/hex. */
    changed[10] = '_';
    snprintf(input, sizeof(input), "bitly %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    changed[10] = '+';
    snprintf(input, sizeof(input), "bitly %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memcpy(changed, token, sizeof(token));
    changed[0] = '-';
    snprintf(input, sizeof(input), "bitly %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "bitly%s", changed); /* Keyword's final word byte supplies the LEFT boundary. */
    expect_extraction(detector, &ctx, input, strlen(input), changed_token, 1);
    snprintf(input, sizeof(input), "bitly x%s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), changed_token, 1);
    memcpy(changed, token, sizeof(token));
    changed[39] = '-';
    snprintf(input, sizeof(input), "bitly %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "bitly %sQ", changed); /* Outside word byte supplies the RIGHT boundary. */
    expect_extraction(detector, &ctx, input, strlen(input), changed_token, 1);
    memset(changed, '-', 40);
    changed[40] = '\0';
    snprintf(input, sizeof(input), "bitly%sQ", changed);
    expect_extraction(detector, &ctx, input, strlen(input), changed_token, 1); /* Both boundary quirks; no entropy filter. */
    memset(changed, 'a', 40);
    snprintf(input, sizeof(input), "bitly %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), changed_token, 1);
    const char prefix[] = "bitly";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, token, sizeof(token));
        expect_extraction(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), token, sizeof(token) - 1);
    expect_extraction(detector, &ctx, input, sizeof(prefix) + sizeof(token) - 1, one, 1);
    CHECK(!http.calls && !http.releases);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls);
    const char *expected_token = expected->tokens[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api-ssl.bitly.com/v4/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 43);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Authorization")) {
            ++auth;
            CHECK(!strncmp(header->value, "Bearer ", 7) && !strcmp(header->value + 7, expected_token));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog bitly-test" : "TruffleHog"));
        } else CHECK(!"unexpected BitLyAccessToken header (no Accept or Content-Type)");
    }
    CHECK(auth == 1 && agent == 1);
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *value, bool verified, const char *error)
{
    char input[80];
    int n = snprintf(input, sizeof(input), "bitly %s", value);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results results = test_scan(detector, ctx, verify, input, (size_t)n);
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 43, value, "key");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
        if (strstr(error, value)) CHECK(strstr(results.items[0].verification_error, value) && !strstr(results.items[0].verification_error, "[REDACTED]"));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_unique_tokens(const br_detector *detector)
{
    char input[256], case_variant[41];
    memcpy(case_variant, token, sizeof(token));
    case_variant[0] = 'a';
    snprintf(input, sizeof(input), "bitly %s\nbitly %s\nbitly %s\nbitly %s", token, other, token, case_variant);
    const char *tokens[] = {token, other, case_variant};
    expected_requests expected = {tokens, 3, 0};
    test_http http = {.response = {.status = 200, .body_error = "ignored drain failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_extraction(detector, &ctx, input, strlen(input), tokens, 3); /* Bytewise unique, not case-folded. */
    CHECK(!http.calls && !http.releases);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 43, tokens[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_status_and_unredacted_errors(const br_detector *detector)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL},
        {201, false, "unexpected status code: 201"}, {204, false, "unexpected status code: 204"},
        {400, false, "unexpected status code: 400"}, {500, false, "unexpected status code: 500"},
    };
    const unsigned char body[] = {0, 0xff, '<', 'n', 'o', '-', 'j', 's', 'o', 'n'};
    const char *tokens[] = {token};
    expected_requests expected = {tokens, 1, 0};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain/close error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "bitly-test"};
        expect_one(detector, &ctx, true, token, statuses[i].verified, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, token, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char sensitive[160];
    snprintf(sensitive, sizeof(sensitive), "synthetic token %s failed; Authorization: Bearer %s", token, token);
    const char *causes[] = {
        "lookup synthetic: no such host", "context canceled", "context deadline exceeded",
        "unsupported: synthetic SANE transport", sensitive, NULL,
    };
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body)}, .body_error = "must not replace transport cause"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = causes[i], .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        /* SetVerificationError has NO secret arguments upstream. Preserve the
         * exact synthetic token-bearing cause instead of inventing redaction. */
        expect_one(detector, &ctx, true, token, false, causes[i] ? causes[i] : "HTTP transport failed");
        CHECK(http.calls == 1 && http.releases == 1);
        http.calls = http.releases = 0;
        http.send_error = NULL;
        http.send_rc = 0;
        expect_one(detector, &ctx, true, token, true, NULL); /* No cross-scan cache. */
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context_and_creation(const br_detector *detector)
{
    const char *tokens[] = {other};
    expected_requests expected = {tokens, 1, 2000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_one(detector, &ctx, true, other, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 1;
    expect_one(detector, &ctx, true, other, false, "context deadline exceeded");
    CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 0;
    ctx.cancelled = cancelled;
    expect_one(detector, &ctx, true, other, false, "context canceled");
    CHECK(!http.calls && http.releases == 1);
    expect_one(detector, &ctx, false, other, false, NULL);
    CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL;
    http.calls = http.releases = 0;
    expected.timeout_limit = 0;
    expect_one(detector, &ctx, true, other, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
    expect_one(detector, NULL, true, token, false, "net/http: nil Context");
    expect_one(detector, NULL, false, token, false, NULL);
    br_scan_ctx missing_transport = {0};
    expect_one(detector, &missing_transport, true, token, false, "HTTP transport not installed");
    CHECK(http.calls == 1 && http.releases == 1);
}

int main(void)
{
    test_secret(token, 40, 0);
    test_secret(other, 40, 11);
    token[0] = 'A'; token[39] = 'Z'; other[0] = 'Y'; other[17] = '-'; other[39] = 'Q';
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_unique_tokens(detector);
    test_status_and_unredacted_errors(detector);
    test_context_and_creation(detector);
    return test_finish("BitLyAccessToken unique hyphen tokens + source-unredacted errors");
}
