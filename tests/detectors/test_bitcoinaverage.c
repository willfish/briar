/* SPDX-License-Identifier: AGPL-3.0-only */
/* get_ticket can issue auth artifacts: all verification uses injected HTTP. */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

#define SLICE(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
#define MSG_TYPE(value) "json: cannot unmarshal " value " into Go struct field response.msg of type string"
#define SUCCESS_TYPE(value) "json: cannot unmarshal " value " into Go struct field response.success of type bool"
#define ROOT_TYPE(value) "json: cannot unmarshal " value " into Go value of type bitcoinaverage.response"
static char key[44], other[44];
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

/* Target the core setter's positive-1 resource failure, not a decode outcome. */
char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, value, len);
    return copy;
}

typedef struct { const char *const *keys; size_t count; uint32_t timeout_limit; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bitcoinaverage_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 432 && detector->version == 0);
    CHECK(!strcmp(detector->name, "BitcoinAverage") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "BitcoinAverage is a service that provides cryptocurrency market data. "
        "BitcoinAverage API keys can be used to access and retrieve this market data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bitcoinaverage"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_bitcoinaverage_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_bitcoinaverage_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_bitcoinaverage_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_bitcoinaverage_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                               const void *input, size_t len, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 432, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[44];
    const char *one[] = {key};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"bitcoinaverage = '%s'", 1}, {"BITCOINAVERAGE: %s", 1}, {"preBitcoinaveragesuffix=%s", 1},
        {"%s", 0}, {"%s bitcoinaverage", 0}, {"bitcoinaverage%s", 0},
        {"bitcoinaverage _%s", 0}, {"bitcoinaverage %s_", 0}, {"bitcoinaverage %sQ", 0},
        {"bitcoinaverage %.42s", 0}, {"bitcoinaverage\r\n%s", 1}, {"bitcoinaverage %s=", 1},
        {"bitcoinaverage %s %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].format, key, other);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)n, one, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    memcpy(changed, key, sizeof(key));
    changed[10] = '+';
    snprintf(input, sizeof(input), "bitcoinaverage %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memset(changed, 'a', 43);
    changed[43] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "bitcoinaverage %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), low_entropy, 1);
    const char prefix[] = "bitcoinaverage";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, key, sizeof(key));
        expect_extraction(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, sizeof(key) - 1);
    expect_extraction(detector, &ctx, input, sizeof(prefix) + sizeof(key) - 1, one, 1);
    CHECK(!http.calls && !http.releases);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls);
    const char *expected_key = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://apiv2.bitcoinaverage.com/websocket/v3/get_ticket"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 432);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "x-ba-key")) {
            ++auth;
            CHECK(!strcmp(header->value, expected_key));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog bitcoinaverage-test" : "TruffleHog"));
        } else CHECK(!"unexpected BitcoinAverage header (no Accept or Content-Type)");
    }
    CHECK(auth == 1 && agent == 1);
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *value, bool verified, const char *error)
{
    char input[80];
    int n = snprintf(input, sizeof(input), "bitcoinaverage %s", value);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results results = test_scan(detector, ctx, verify, input, (size_t)n);
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 432, value, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void expect_json(const br_detector *detector, br_slice body, const char *read_error,
                        bool verified, const char *error)
{
    const char *keys[] = {key};
    expected_requests expected = {keys, 1, 0};
    test_http http = {.response = {.status = 200, .body = body, .body_error = read_error},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_one(detector, &ctx, true, key, verified, error);
    CHECK(http.calls == 1 && http.releases == 1);
}

static void test_typed_fields(const br_detector *detector)
{
    const struct { const char *body; bool verified; const char *error; } cases[] = {
        {"{}", false, NULL}, {"null", false, NULL}, {"{\"success\":true}", true, NULL},
        {"{\"success\":false,\"msg\":\"ok\"}", false, NULL},
        {"{\"msg\":null,\"success\":null}", false, NULL},
        {"{\"success\":true,\"success\":false}", false, NULL},
        {"{\"success\":false,\"success\":true}", true, NULL},
        {"{\"success\":true,\"success\":null}", true, NULL},
        {"{\"msg\":\"old\",\"msg\":null,\"success\":true}", true, NULL},
        {"{\"MSG\":\"ok\",\"SUCCESS\":true}", true, NULL},
        {"{\"Success\":true,\"SUCCESS\":false}", false, NULL},
        {"{\"\\u017fucce\\u017f\\u017f\":true}", true, NULL},
        {"{\"msg\":\"before\\u0000after\",\"success\":true}", true, NULL},
        {"{\"msg\":false,\"success\":true}", false, MSG_TYPE("bool")},
        {"{\"success\":true,\"msg\":1}", false, MSG_TYPE("number")},
        {"{\"success\":true,\"msg\":[]}", false, MSG_TYPE("array")},
        {"{\"success\":true,\"msg\":{}}", false, MSG_TYPE("object")},
        {"{\"success\":\"true\"}", false, SUCCESS_TYPE("string")},
        {"{\"success\":1e999}", false, SUCCESS_TYPE("number")},
        {"{\"success\":{}}", false, SUCCESS_TYPE("object")},
        {"{\"success\":[]}", false, SUCCESS_TYPE("array")},
        {"{\"success\":\"bad\",\"success\":true}", false, SUCCESS_TYPE("string")},
        {"{\"msg\":1,\"msg\":\"fixed\",\"success\":true}", false, MSG_TYPE("number")},
        {"{\"success\":7,\"msg\":false}", false, SUCCESS_TYPE("number")},
        {"{\"msg\":1e999,\"success\":true}", false, MSG_TYPE("number")},
        {"{\"unknown\":1e999,\"success\":true}", true, NULL},
        {"{\"unknown\":{\"n\":[1e999,-1e999,184467440737095516161234]},\"success\":true}", true, NULL},
        {"[]", false, ROOT_TYPE("array")}, {"\"wrong\"", false, ROOT_TYPE("string")},
        {"17", false, ROOT_TYPE("number")}, {"true", false, ROOT_TYPE("bool")},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        expect_json(detector, (br_slice){(const unsigned char *)cases[i].body, strlen(cases[i].body)},
                    NULL, cases[i].verified, cases[i].error);
}

static void test_stream_boundaries(const br_detector *detector)
{
    expect_json(detector, SLICE("{\"success\":true}{\"success\":false}"), NULL, true, NULL);
    expect_json(detector, SLICE("{} {\"success\":true}"), NULL, false, NULL);
    expect_json(detector, SLICE("{\"success\":true}garbage\0tail"), NULL, true, NULL);
    expect_json(detector, SLICE("{\"msg\":1,\"success\":true}]ignored"), NULL, false, MSG_TYPE("number"));
    expect_json(detector, (br_slice){NULL, 0}, NULL, false, "EOF");
    expect_json(detector, SLICE("{\"success\":true"), NULL, false, "unexpected EOF");
    char read_error[128], redacted[128];
    snprintf(read_error, sizeof(read_error), "read key=%s failed again %s", key, key);
    snprintf(redacted, sizeof(redacted), "read key=[REDACTED] failed again [REDACTED]");
    expect_json(detector, SLICE("{\"success\":true}"), read_error, true, NULL);
    expect_json(detector, SLICE("{\"msg\":1,\"success\":true}"), read_error, false, MSG_TYPE("number"));
    expect_json(detector, SLICE("{\"success\":true"), read_error, false, redacted);
    expect_json(detector, SLICE("{\"msg\":1,"), read_error, false, redacted); /* Read/syntax phase precedes field typing. */
    expect_json(detector, SLICE("@"), read_error, false, "invalid character '@' looking for beginning of value");
    expect_json(detector, SLICE("\"wrong\""), read_error, false, redacted); /* Terminal scalar needs a delimiter or EOF. */
    expect_json(detector, SLICE("\"wrong\" "), read_error, false, ROOT_TYPE("string"));
}

static void test_occurrences(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "bitcoinaverage %s\nbitcoinaverage %s\nbitcoinaverage %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected_requests expected = {keys, 3, 0};
    test_http http = {.response = {.status = 200, .body = SLICE("{\"success\":true}"), .body_error = "later drain failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_extraction(detector, &ctx, input, strlen(input), keys, 3);
    CHECK(!http.calls && !http.releases);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 432, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_status_and_transport_policy(const br_detector *detector)
{
    const struct { int status; const char *error; } statuses[] = {
        {401, NULL}, {201, "unexpected status code: 201"},
        {403, "unexpected status code: 403"}, {500, "unexpected status code: 500"},
    };
    const char *keys[] = {key};
    expected_requests expected = {keys, 1, 0};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = SLICE("{\"msg\":1,\"success\":true}"),
                                       .body_error = "ignored non-200 body error"}, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "bitcoinaverage-test"};
        expect_one(detector, &ctx, true, key, false, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, key, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char sensitive[160];
    snprintf(sensitive, sizeof(sensitive), "key %s failed again %s; keep %s", key, key, other);
    char redacted[128];
    snprintf(redacted, sizeof(redacted), "key [REDACTED] failed again [REDACTED]; keep %s", other);
    const struct { const char *cause, *error; } failures[] = {
        {"lookup synthetic: no such host", "lookup synthetic: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"},
        {sensitive, redacted}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = SLICE("{\"success\":true}"), .body_error = "not the transport cause"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, key, false, failures[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context_and_creation(const br_detector *detector)
{
    const char *keys[] = {other};
    expected_requests expected = {keys, 1, 2000};
    test_http http = {.response = {.status = 200, .body = SLICE("{\"success\":true}")}, .inspect = inspect_request, .user = &expected};
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
    expect_one(detector, NULL, true, key, false, "net/http: nil Context");
    expect_one(detector, NULL, false, key, false, NULL);
}

static void test_positive_setter_failure(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "bitcoinaverage %s\nbitcoinaverage %s", key, other);
    const char *keys[] = {key};
    expected_requests expected = {keys, 1, 0};
    test_http http = {.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0};
    br_result prior = {0};
    char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc != 0 && error);
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 43, 0);
    test_secret(other, 43, 11);
    key[0] = 'A'; key[42] = 'Z'; other[1] = 'Y'; other[42] = 'Q';
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_typed_fields(detector);
    test_stream_boundaries(detector);
    test_occurrences(detector);
    test_status_and_transport_policy(detector);
    test_context_and_creation(detector);
    test_positive_setter_failure(detector);
    return test_finish("BitcoinAverage typed first-document native fixtures");
}
