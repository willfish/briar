/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <time.h>

static const char key[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char other[] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
typedef struct { const char *const *keys; size_t count; uint32_t timeout_limit; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_besnappy_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 867 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Besnappy") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Besnappy is a customer service platform. The detected key can be used to access "
        "Besnappy's API, potentially exposing sensitive customer service data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "besnappy"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_besnappy_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_besnappy_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_besnappy_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_besnappy_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                               const void *input, size_t len, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 867, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[66];
    const char *one[] = {key};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"besnappy = '%s'", 1}, {"BESNAPPY: %s", 1}, {"preBesnappysuffix=%s", 1},
        {"%s", 0}, {"%s besnappy", 0}, {"besnappy%s", 0},
        {"besnappy _%s", 0}, {"besnappy %s_", 0}, {"besnappy %s0", 0},
        {"besnappy %.63s", 0}, {"besnappy\r\n%s", 1}, {"besnappy %s=", 1},
        {"besnappy %s %s", 1}, /* A second key requires another provider prefix. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].format, key, other);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)n, one, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    memcpy(changed, key, sizeof(key));
    changed[10] = 'A';
    snprintf(input, sizeof(input), "BESNAPPY %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0); /* Only the provider prefix is CI. */
    changed[10] = 'g';
    snprintf(input, sizeof(input), "besnappy %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    changed[10] = '-';
    snprintf(input, sizeof(input), "besnappy %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memset(changed, 'f', 64);
    changed[64] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "besnappy %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), low_entropy, 1);
    const char prefix[] = "besnappy";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, key, sizeof(key));
        expect_extraction(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix)); /* A NUL in the prefix gap is not part of the key. */
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
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://app.besnappy.com/api/v1/accounts"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 867);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    char plain[67], auth[95];
    int n = snprintf(plain, sizeof(plain), "%s:x", expected_key);
    CHECK(n == 66);
    memcpy(auth, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)auth + 6, (const unsigned char *)plain, n) == 88);
    if (!strcmp(expected_key, key))
        CHECK(!strcmp(auth, "Basic MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjp4"));
    size_t authorization = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Authorization")) {
            ++authorization;
            CHECK(!strcmp(header->value, auth));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog besnappy-test" : "TruffleHog"));
        } else CHECK(!"unexpected Besnappy header (no Accept or Content-Type)");
    }
    CHECK(authorization == 1 && agent == 1);
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *value, bool verified, const char *error)
{
    char input[96];
    int n = snprintf(input, sizeof(input), "besnappy %s", value);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results results = test_scan(detector, ctx, verify, input, (size_t)n);
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 867, value, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_occurrences(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "besnappy %s\nbesnappy %s\nbesnappy %s", key, other, key);
    const char *keys[] = {key, other, key};
    expected_requests expected = {keys, 3, 0};
    test_http http = {.response = {.status = 200, .body_error = "ignored drain failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_extraction(detector, &ctx, input, strlen(input), keys, 3);
    CHECK(!http.calls && !http.releases);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 867, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_status_and_transport_policy(const br_detector *detector)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {201, false, "unexpected status code: 201"},
        {204, false, "unexpected status code: 204"}, {400, false, "unexpected status code: 400"},
        {403, false, "unexpected status code: 403"}, {500, false, "unexpected status code: 500"},
    };
    const unsigned char body[] = {0, 0xff, '<', 'n', 'o', '-', 'j', 's', 'o', 'n'};
    const char *keys[] = {key};
    expected_requests expected = {keys, 1, 0};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "besnappy-test"};
        expect_one(detector, &ctx, true, key, statuses[i].verified, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, key, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char sensitive[192];
    snprintf(sensitive, sizeof(sensitive), "user=%s password=x / %s; keep x", key, key);
    const struct { const char *cause, *error; } failures[] = {
        {"lookup synthetic: no such host", "lookup synthetic: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"},
        {sensitive, "user=[REDACTED] password=x / [REDACTED]; keep x"}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body)}, .body_error = "must not replace transport cause"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, key, false, failures[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        http.calls = http.releases = 0;
        http.send_error = NULL;
        http.send_rc = 0;
        expect_one(detector, &ctx, true, key, true, NULL); /* DNS/other errors never cache or suppress later candidates. */
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context_and_creation(const br_detector *detector)
{
    const char *keys[] = {other};
    expected_requests expected = {keys, 1, 2000};
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
    expect_one(detector, NULL, true, key, false, "net/http: nil Context");
    expect_one(detector, NULL, false, key, false, NULL);
    br_scan_ctx missing_transport = {0};
    expect_one(detector, &missing_transport, true, key, false, "HTTP transport not installed");
    CHECK(http.calls == 1 && http.releases == 1);
}

int main(void)
{
    CHECK(strlen(key) == 64 && strlen(other) == 64);
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_occurrences(detector);
    test_status_and_transport_policy(detector);
    test_context_and_creation(detector);
    return test_finish("Besnappy direct native fixtures (source default disabled)");
}
