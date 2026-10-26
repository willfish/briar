/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static const char first_key[] = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z";
static const char second_key[] = "z4YxW1vUt8SrQ5pOn2MlK9jIh6FeD3bA";
typedef struct { const char *const *keys; size_t len; } expected_requests;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bitbar_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_bitbar_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 387 && detector->version == 0 && !strcmp(detector->name, "Bitbar"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Bitbar provides a cloud-based mobile app testing platform. "
        "Bitbar API keys can be used to access and manage testing resources and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bitbar"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_bitbar_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *key, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && http.calls == 0 && http.releases == 0);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 387, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[160];
    const struct { const char *format; size_t count; } cases[] = {
        {"bitbar '%s'", 1},
        {"BITBAR=%s", 1},
        {"BiTbAr\t%s", 1},
        {"prefixbitbarsuffix %s", 1},
        {"bitbar\r\n%s\t", 1},
        {"%s", 0},
        {"bit bar %s", 0},
        {"bitbar %.31s", 0},
        {"bitbar A%s", 0},
        {"bitbar %sA", 0},
        {"bitbar _%s", 0},
        {"bitbar %s_", 0},
        {"bitbar +%s/", 1},
        {"bitbar %s=", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, first_key);
        expect_extraction(detector, input, strlen(input), first_key, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "bitbar", 6); memset(input + 6, '-', gap);
        snprintf(input + 6 + gap, sizeof(input) - 6 - gap, "%s", first_key);
        expect_extraction(detector, input, strlen(input), first_key, gap == 40 ? 1 : 0);
    }
    char changed[33]; memcpy(changed, first_key, sizeof(changed)); changed[16] = '_';
    snprintf(input, sizeof(input), "bitbar %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(changed, 'Z', 32); changed[32] = 0;
    snprintf(input, sizeof(input), "bitbar %s", changed);
    expect_extraction(detector, input, strlen(input), changed, 1); /* Nonhex and no local entropy/FP filter. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://cloud.bitbar.com/api/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 387);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    const char *authorization = request->headers[1].value;
    CHECK(strlen(authorization) == 50 && !strncmp(authorization, "Basic ", 6));
    /* Decode independently of br_http_basic_auth: exactly KEY + ':' proves
     * both username direction and an empty (not literal 'x') password. */
    unsigned char decoded[64];
    CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)authorization + 6, 44) == 33);
    CHECK(!memcmp(decoded, expected->keys[http->calls - 1], 32) && decoded[32] == ':');
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog bitbar-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1);
}

static void occurrences(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "bitbar %s\nbitbar %s\nbitbar %s", first_key, second_key, first_key);
    const char *keys[] = {first_key, second_key, first_key};
    expected_requests expected = {keys, sizeof(keys) / sizeof(keys[0])};
    for (int mode = 0; mode < 3; ++mode) {
        bool verify = mode != 0;
        const char *dns_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL;
        test_http http = {.response = {.status = 200}, .send_rc = mode == 2 ? 1 : 0, .send_error = dns_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 387, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1));
            if (dns_error) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, dns_error));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 3); /* Request-creation failures never skip occurrences. */
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 387, keys[i], "key");
        CHECK(!results.items[i].verified && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
    }
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 387, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[96], sensitive[256];
    snprintf(input, sizeof(input), "bitbar %s", second_key);
    snprintf(sensitive, sizeof(sensitive), "url=https://cloud.bitbar.com/api/me key=%s again=%s", second_key, second_key);
    const char *redacted = "url=https://cloud.bitbar.com/api/me key=[REDACTED] again=[REDACTED]";
    const char *keys[] = {second_key}; expected_requests expected = {keys, 1};
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {403, 0, NULL, false, "unexpected status code: 403"},
        {429, 0, NULL, false, "unexpected status code: 429"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "lookup synthetic.invalid: no such host", false, "lookup synthetic.invalid: no such host"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, 1, sensitive, false, redacted},
        {200, 1, NULL, false, "HTTP transport failed"},
        {200, 0, NULL, true, NULL},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "bitbar-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0]; test_key_result(result, 387, second_key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error && !strcmp(result->verification_error, cases[i].error));
            CHECK(!strstr(result->verification_error, second_key));
        } else CHECK(!result->verification_error);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_errors(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "bitbar %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        test_key_result(&results.items[0], 387, first_key, "key");
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

int main(void)
{
    CHECK(strlen(first_key) == 32 && strlen(second_key) == 32);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification(detector); context_errors(detector);
    return test_finish("Bitbar");
}
