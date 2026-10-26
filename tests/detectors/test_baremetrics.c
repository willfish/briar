/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <time.h>

static const char sandbox[] = "sk_AbCdEf0123456789Gh";
static const char production[] = "lk_AbCdEfGhIjKlMnOpQrStUvWxY";
typedef struct { const char *const *keys; size_t count; uint32_t timeout_limit; } expected_requests;

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_baremetrics_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 377 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Baremetrics") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Baremetrics is a subscription analytics and insights tool. Baremetrics API keys "
        "can be used to access and analyze subscription data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "baremetrics"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_baremetrics_init(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(br_baremetrics_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_baremetrics_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_baremetrics_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                               const void *input, size_t len, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 377, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[256], changed[32], payload[27];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const char *one[] = {sandbox};
    const struct { const char *format; size_t count; } cases[] = {
        {"baremetrics = '%s'", 1}, {"BAREMETRICS: %s", 1}, {"preBaremetricssuffix=%s", 1},
        {"%s", 0}, {"%s baremetrics", 0}, {"baremetrics%s", 0},
        {"baremetrics _%s", 0}, {"baremetrics %s_", 0},
        {"baremetrics\r\n%s", 1}, {"baremetrics %s==", 1}, {"baremetrics %s-", 1},
        {"baremetrics %s %s", 1}, /* A later occurrence needs its own provider prefix. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int n = snprintf(input, sizeof(input), cases[i].format, sandbox, production);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)n, one, cases[i].count);
    }
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    const size_t lengths[] = {17, 18, 25, 26};
    for (size_t i = 0; i < 4; ++i) {
        test_secret(payload, lengths[i], 3);
        snprintf(changed, sizeof(changed), "sk_%s", payload);
        const char *expected[] = {changed};
        snprintf(input, sizeof(input), "baremetrics %s", changed);
        expect_extraction(detector, &ctx, input, strlen(input), expected, lengths[i] == 18 || lengths[i] == 25 ? 1 : 0);
    }
    const char *valid[] = {sandbox, production, "sk_aaaaaaaaaaaaaaaaaa", "lk_exampleexampleexam"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        snprintf(input, sizeof(input), "baremetrics %s", valid[i]);
        expect_extraction(detector, &ctx, input, strlen(input), &valid[i], 1); /* No entropy/digit/default-word filter. */
    }
    const char *uppercase[] = {"SK_AbCdEf0123456789Gh", "LK_AbCdEfGhIjKlMnOpQrStUvWxY"};
    for (size_t i = 0; i < 2; ++i) {
        snprintf(input, sizeof(input), "BAREMETRICS %s", uppercase[i]);
        expect_extraction(detector, &ctx, input, strlen(input), NULL, 0); /* CI applies only to the provider keyword. */
    }
    memcpy(changed, sandbox, sizeof(sandbox));
    changed[8] = '-';
    snprintf(input, sizeof(input), "baremetrics %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    changed[8] = '+';
    snprintf(input, sizeof(input), "baremetrics %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    snprintf(changed, sizeof(changed), "%sQ", sandbox);
    const char *extended[] = {changed};
    snprintf(input, sizeof(input), "baremetrics %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), extended, 1); /* Variable, not fixed, payload length. */
    const char prefix[] = "baremetrics";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, sandbox, sizeof(sandbox));
        expect_extraction(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix)); /* Embedded NUL is a prefix-gap rune, never part of capture 1. */
    memcpy(input + sizeof(prefix), sandbox, sizeof(sandbox) - 1);
    expect_extraction(detector, &ctx, input, sizeof(prefix) + sizeof(sandbox) - 1, one, 1);
    CHECK(!http.calls && !http.releases);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(http->releases + 1 == http->calls);
    const char *key = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.baremetrics.com/v1/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 377);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Authorization")) {
            ++auth;
            CHECK(!strncmp(header->value, "Bearer ", 7) && !strcmp(header->value + 7, key));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog baremetrics-test" : "TruffleHog"));
        } else CHECK(!"unexpected Baremetrics header (no Accept or Content-Type)");
    }
    CHECK(auth == 1 && agent == 1);
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      const char *key, bool verified, const char *error)
{
    char input[64];
    int n = snprintf(input, sizeof(input), "baremetrics %s", key);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results results = test_scan(detector, ctx, verify, input, (size_t)n);
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 377, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_occurrences(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "baremetrics %s\nbaremetrics %s\nbaremetrics %s", sandbox, production, sandbox);
    const char *keys[] = {sandbox, production, sandbox};
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
        test_key_result(&results.items[i], 377, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_status_and_transport_policy(const br_detector *detector)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL},
        {201, false, "unexpected status code: 201"}, {204, false, "unexpected status code: 204"},
        {403, false, "unexpected status code: 403"}, {500, false, "unexpected status code: 500"},
    };
    const unsigned char body[] = {0, 0xff, '<', 'n', 'o', '-', 'j', 's', 'o', 'n'};
    const char *keys[] = {sandbox};
    expected_requests expected = {keys, 1, 0};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body)}, .body_error = "ignored read/drain error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "baremetrics-test"};
        expect_one(detector, &ctx, true, sandbox, statuses[i].verified, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, sandbox, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char sensitive[128];
    snprintf(sensitive, sizeof(sensitive), "key %s rejected again %s", sandbox, sandbox);
    const char *causes[] = {
        "lookup synthetic: no such host", "context canceled", "context deadline exceeded",
        "unsupported: synthetic SANE transport", sensitive, NULL,
    };
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body)}, .body_error = "ignored body error"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = causes[i], .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, sandbox, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
        /* No DNS cache or candidate suppression; a later scan still attempts I/O. */
        http.calls = http.releases = 0;
        http.send_error = NULL;
        http.send_rc = 0;
        expect_one(detector, &ctx, true, sandbox, true, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context_and_creation(const br_detector *detector)
{
    const char *keys[] = {production};
    expected_requests expected = {keys, 1, 2000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_one(detector, &ctx, true, production, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 1;
    expect_one(detector, &ctx, true, production, false, NULL); /* Expired context is a suppressed Do error. */
    CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 0;
    ctx.cancelled = cancelled;
    expect_one(detector, &ctx, true, production, false, NULL);
    CHECK(!http.calls && http.releases == 1);
    expect_one(detector, &ctx, false, production, false, NULL);
    CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL;
    http.calls = http.releases = 0;
    expected.timeout_limit = 0;
    expect_one(detector, &ctx, true, production, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1); /* No shared-client deadline mutation. */
    expect_one(detector, NULL, true, sandbox, false, "net/http: nil Context"); /* Creation error retained, not skipped. */
    expect_one(detector, NULL, false, sandbox, false, NULL);
    br_scan_ctx missing_transport = {0};
    expect_one(detector, &missing_transport, true, sandbox, false, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
}

int main(void)
{
    CHECK(strlen(sandbox) == 21 && strlen(production) == 28);
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_occurrences(detector);
    test_status_and_transport_policy(detector);
    test_context_and_creation(detector);
    return test_finish("Baremetrics");
}
