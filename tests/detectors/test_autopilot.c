/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

/* Synthetic lowercase hex, never a service credential. */
static const char key[] = "0123456789abcdef0123456789abcdef";
static const char other[] = "fedcba9876543210fedcba9876543210";

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_autopilot_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_autopilot_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 511 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AutoPilot") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "AutoPilot is a marketing automation platform. AutoPilot API keys can be used "
                  "to access and manage marketing data and campaigns."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "autopilot"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_autopilot_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid AutoPilot detector output"));
    free(error);
    CHECK(br_autopilot_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 511, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char input[160], changed[33];
    const char *one[] = {key};
    const struct { const char *format; bool matches; } cases[] = {
        {"autopilot %s", true}, {"preAUTOPILOTsuffix:%s", true},
        {"autopilot\r\n'%s'", true}, {"autopilot %s-", true},
        {"%s", false}, {"autopilot %.31s", false}, {"autopilot %s0", false},
        {"autopilot _%s", false}, {"autopilot %s_", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_extraction(detector, input, one, cases[i].matches ? 1 : 0);
    }
    expect_extraction(detector, "", NULL, 0);
    memcpy(changed, key, sizeof(changed));
    const char invalid[] = {'A', 'g', '_', '-'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        changed[10] = invalid[i];
        snprintf(input, sizeof(input), "autopilot %s", changed);
        expect_extraction(detector, input, NULL, 0); /* Hex only; prefix case-folding must not widen it. */
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "autopilot", 9);
        memset(input + 9, '!', gap);
        memcpy(input + 9 + gap, key, sizeof(key));
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(http->calls > 0 && http->calls <= expected->count);
    /* Every preceding response is already released, including failed sends. */
    CHECK(http->releases + 1 == http->calls);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api2.autopilothq.com/v1/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 511);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "autopilotapikey"));
    CHECK(!strcmp(request->headers[0].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog autopilot-test"));
}

static void test_occurrences(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "autopilot %s\nautopilot %s\nautopilot %s", key, other, key);
    const char *keys[] = {key, other, key};
    expect_extraction(detector, input, keys, 3);
    expected_requests expected = {keys, 3};
    test_http http = {.response = {.status = 299, .body_error = "ignored body failure"},
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "autopilot-test"};
    for (size_t failure = 0; failure < 2; ++failure) {
        http.calls = http.releases = 0;
        http.send_rc = failure ? -1 : 0;
        http.send_error = failure ? "context canceled" : NULL;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < results.len; ++i) {
            test_key_result(&results.items[i], 511, keys[i], "key");
            CHECK(results.items[i].verified == !failure);
            CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

typedef struct { int status, send_rc; const char *send_error; bool verified; } verification_case;

static void verify_case(const br_detector *detector, verification_case fixture)
{
    char input[64];
    snprintf(input, sizeof(input), "autopilot %s", key);
    const char *keys[] = {key};
    expected_requests expected = {keys, 1};
    static const unsigned char body[] = {0, 0xff, '{'};
    test_http http = {
        .response = {.status = fixture.status, .body = {body, sizeof(body)}, .body_error = "ignored body/drain error"},
        .send_rc = fixture.send_rc, .send_error = fixture.send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "autopilot-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], 511, key, "key");
    CHECK(results.items[0].verified == fixture.verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    const verification_case cases[] = {
        {.status = 199}, {.status = 200, .verified = true}, {.status = 201, .verified = true},
        {.status = 204, .verified = true}, {.status = 206, .verified = true}, {.status = 299, .verified = true},
        {.status = 300}, {.status = 400}, {.status = 401}, {.status = 403}, {.status = 500},
        {.status = 200, .send_rc = -1, .send_error = "context canceled"},
        {.status = 299, .send_rc = -1, .send_error = "context deadline exceeded"},
        {.status = 200, .send_rc = -1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) verify_case(detector, cases[i]);
    char cause[128];
    snprintf(cause, sizeof(cause), "candidate=%s candidate-again=%s", key, key);
    verify_case(detector, (verification_case){.status = 200, .send_rc = -1, .send_error = cause});

    char input[64];
    snprintf(input, sizeof(input), "autopilot %s", key);
    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    test_key_result(&results.items[0], 511, key, "key");
    br_results_clear(&results);
    /* Explicit ABI1 gap: nil Go context skips this candidate at NewRequest;
     * the shared C scanner retains it and suppresses the invalid-context error. */
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    test_key_result(&results.items[0], 511, key, "key");
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init(), *again = NULL;
    const void *state = detector->state;
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    test_extraction(detector);
    test_occurrences(detector);
    test_verification(detector);
    CHECK(br_autopilot_init(&again, NULL) == 0 && again == detector && again->state == state);
    return test_finish("AutoPilot");
}
