/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static const char header[] = "eyJhbGciOiJIUzI1NiJ9";
static char token[156], other[156];
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, value, len);
    return copy;
}

typedef struct {
    const char *const *tokens;
    size_t count;
    uint32_t timeout_limit;
    const int *statuses;
} expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_caflou_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 647 && detector->version == 0 && !strcmp(detector->name, "Caflou"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Caflou is a business management software used for managing projects, tasks, and finances. "
        "Caflou API keys can be used to access and modify this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "caflou"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_caflou_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_caflou_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_caflou_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_caflou_init(NULL, NULL) != 0);
    return detector;
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) {
        test_key_result(&results.items[0], 647, expected, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[384], changed[156];
    extraction_case(detector, token, token); /* caflou is dispatch-only, not an extraction prefix. */
    snprintf(input, sizeof(input), "CAFLOU: %s", token); extraction_case(detector, input, token);
    snprintf(input, sizeof(input), "(%s)", token); extraction_case(detector, input, token);
    snprintf(input, sizeof(input), "x%s", token); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "_%s", token); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "%s_", token); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "%sQ", token); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "%.154s", token); extraction_case(detector, input, NULL);
    memcpy(changed, token, sizeof(token)); changed[0] = 'E'; extraction_case(detector, changed, NULL);
    memcpy(changed, token, sizeof(token)); changed[2] = 'j'; extraction_case(detector, changed, NULL);
    memcpy(changed, token, sizeof(token)); changed[80] = '+'; extraction_case(detector, changed, NULL);
    changed[80] = '/'; extraction_case(detector, changed, NULL);
    changed[80] = '!'; extraction_case(detector, changed, NULL);
    memcpy(changed, header, sizeof(header) - 1);
    memset(changed + sizeof(header) - 1, 'a', 135); changed[155] = '\0';
    extraction_case(detector, changed, changed); /* No periods/segments, Base64 or entropy validation. */
    const char endings[] = {'-', '.', '_'};
    for (size_t i = 0; i < sizeof(endings); ++i) {
        memcpy(changed, token, sizeof(token)); changed[154] = endings[i];
        extraction_case(detector, changed, endings[i] == '_' ? changed : NULL);
        if (endings[i] != '_') {
            snprintf(input, sizeof(input), "%sQ", changed);
            extraction_case(detector, input, changed); /* Outside word byte supplies boundary after '.'/'-'. */
        }
    }
    extraction_case(detector, "caflou", NULL); extraction_case(detector, "", NULL);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count && http->releases + 1 == http->calls);
    const char *value = expected->tokens[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://app.caflou.com/api/v1/accounts"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 647);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 10000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 10000); /* Explicit override, not SANE's 5000. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *field = &request->headers[i];
        if (!strcmp(field->name, "Authorization")) {
            ++auth; CHECK(!strncmp(field->value, "Bearer ", 7) && !strcmp(field->value + 7, value));
        } else if (!strcmp(field->name, "User-Agent")) {
            ++agent; CHECK(!strcmp(field->value, ctx->user_agent ? "TruffleHog caflou-test" : "TruffleHog"));
        } else CHECK(!"unexpected Caflou header (no Accept, Content-Type or explicit length)");
    }
    CHECK(auth == 1 && agent == 1);
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *value, bool verified, const char *error)
{
    br_results results = test_scan(detector, ctx, verify, value, strlen(value));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 647, value, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_occurrences(const br_detector *detector)
{
    char input[512]; snprintf(input, sizeof(input), "%s\n%s\n%s", token, other, token);
    const char *tokens[] = {token, other, token}; expected_requests expected = {.tokens = tokens, .count = 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored read/drain error"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) { test_key_result(&results.items[i], 647, tokens[i], "key"); CHECK(!results.items[i].verified && !results.items[i].verification_error); }
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) { test_key_result(&results.items[i], 647, tokens[i], "key"); CHECK(results.items[i].verified && !results.items[i].verification_error); }
    br_results_clear(&results);
}

static void test_status_and_redaction(const br_detector *detector)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {201, false, "unexpected status code: 201"},
        {204, false, "unexpected status code: 204"}, {403, false, "unexpected status code: 403"}, {503, false, status_503},
    };
    static const unsigned char body[] = "\xff\0not JSON";
    const char *tokens[] = {token}; expected_requests expected = {.tokens = tokens, .count = 1};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body) - 1}, .body_error = "ignored body/read/drain/close error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "caflou-test"};
        expect_one(detector, &ctx, true, token, statuses[i].verified, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, token, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char cause[640], redacted[384];
    snprintf(cause, sizeof(cause), "token=%s repeat=%s; keep %s header=%s", token, token, other, header);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] repeat=[REDACTED]; keep %s header=%s", other, header);
    const struct { const char *cause, *error; } failures[] = {
        {cause, redacted}, {"lookup synthetic: no such host", "lookup synthetic: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}, .body_error = "must not replace transport cause"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, token, false, failures[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        http.calls = http.releases = 0; http.send_error = NULL; http.send_rc = 0;
        expect_one(detector, &ctx, true, token, true, NULL); CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context_and_creation(const br_detector *detector)
{
    const char *tokens[] = {other}; expected_requests expected = {.tokens = tokens, .count = 1, .timeout_limit = 2000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_one(detector, &ctx, true, other, true, NULL); CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 1;
    expect_one(detector, &ctx, true, other, false, "context deadline exceeded"); CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 0; ctx.cancelled = cancelled;
    expect_one(detector, &ctx, true, other, false, "context canceled"); CHECK(!http.calls && http.releases == 1);
    expect_one(detector, &ctx, false, other, false, NULL); CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL; http.calls = http.releases = 0; expected.timeout_limit = 0;
    expect_one(detector, &ctx, true, other, true, NULL); CHECK(http.calls == 1 && http.releases == 1); /* Restores local 10s, no shared mutation. */
    expect_one(detector, NULL, true, token, false, "net/http: nil Context");
    expect_one(detector, NULL, false, token, false, NULL);
    br_scan_ctx missing_transport = {0}; expect_one(detector, &missing_transport, true, token, false, "HTTP transport not installed");
    CHECK(http.calls == 1 && http.releases == 1);
}

static void test_positive_setter_failure_rollback(const br_detector *detector)
{
    char input[384]; snprintf(input, sizeof(input), "%s\n%s", token, other);
    const char *tokens[] = {token, other}; const int statuses[] = {200, 503};
    expected_requests expected = {.tokens = tokens, .count = 2, .statuses = statuses};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    unsigned char *saved = results.items[0].raw.data; fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && *error);
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    test_key_result(&results.items[0], 647, token, "key"); CHECK(results.items[0].verified && !results.items[0].verification_error);
    test_key_result(&results.items[1], 647, other, "key"); CHECK(!results.items[1].verified && results.items[1].verification_error && !strcmp(results.items[1].verification_error, status_503));
    br_results_clear(&results);
}

int main(void)
{
    CHECK(sizeof(header) - 1 == 20);
    memcpy(token, header, 20); test_secret(token + 20, 135, 0);
    memcpy(other, header, 20); test_secret(other + 20, 135, 17);
    token[20] = 'A'; token[40] = '.'; token[80] = '_'; token[120] = '-'; token[154] = 'Z'; other[154] = 'Q';
    CHECK(strlen(token) == 155 && strlen(other) == 155);
    const br_detector *detector = test_descriptor();
    test_extraction(detector); test_occurrences(detector); test_status_and_redaction(detector);
    test_context_and_creation(detector); test_positive_setter_failure_rollback(detector);
    return test_finish("Caflou direct 155-byte tokens + request-local 10s + token-only redaction");
}
