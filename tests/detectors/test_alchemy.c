/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static void expect_keys(const br_detector *detector, const char *input,
                         const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 907, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *legacy, const char *modern)
{
    char input[512];
    const char *one[] = {legacy}, *prefixed[] = {modern}, *both[] = {legacy, modern};
    snprintf(input, sizeof(input), "ALCHEMY %s", legacy);
    expect_keys(detector, input, one, 1);
    snprintf(input, sizeof(input), "alchemy %s", modern);
    expect_keys(detector, input, prefixed, 1);
    snprintf(input, sizeof(input), "alchemy %s\nalchemy %s\nalchemy %s", legacy, modern, legacy);
    expect_keys(detector, input, both, 2);

    /* alcht_ is an engine prefilter keyword, not a PrefixRegex alternative. */
    expect_keys(detector, modern, NULL, 0);
    snprintf(input, sizeof(input), "alcht_ %s", legacy);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "alchemy ALCHT_%s", modern + 6);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "alchemy %sx", legacy);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "alchemy %sx", modern);
    expect_keys(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "alchemy %.31s", legacy);
    expect_keys(detector, input, NULL, 0);

    /* A 32-byte alcht_-shaped value is still accepted by the legacy branch. */
    char short_prefixed[33];
    memcpy(short_prefixed, modern, 32);
    short_prefixed[32] = '\0';
    const char *short_key[] = {short_prefixed};
    snprintf(input, sizeof(input), "alchemy %s", short_prefixed);
    expect_keys(detector, input, short_key, 1);

    memcpy(input, "alchemy", 7);
    memset(input + 7, '!', 40);
    strcpy(input + 47, legacy);
    expect_keys(detector, input, one, 1);
    memset(input + 7, '!', 41);
    strcpy(input + 48, legacy);
    expect_keys(detector, input, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const char *key = http->user;
    char url[144];
    snprintf(url, sizeof(url),
             "https://eth-mainnet.g.alchemy.com/v2/%s/getNFTs/?owner=vitalik.eth", key);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 907);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog alchemy-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                 const char *key, bool verified, const char *error)
{
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = (void *)key;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "alchemy-test"};
    char input[128];
    snprintf(input, sizeof(input), "alchemy %s\nalchemy %s", key, key);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 907, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
        CHECK(!strstr(results.items[0].verification_error, key));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *legacy, const char *modern)
{
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {401, false, NULL},
        {201, false, "unexpected HTTP response status 201"},
        {403, false, "unexpected HTTP response status 403"},
        {429, false, "unexpected HTTP response status 429"},
        {500, false, "unexpected HTTP response status 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = "ignored body-read failure"}};
        expect_verification(detector, &http, legacy, cases[i].verified, cases[i].error);
        expect_verification(detector, &http, modern, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = -1,
                       .send_error = "synthetic transport failure"};
    expect_verification(detector, &http, legacy, false, "synthetic transport failure");
    char sensitive[128];
    snprintf(sensitive, sizeof(sensitive), "request %s failed: %s", modern, modern);
    http.send_error = sensitive;
    expect_verification(detector, &http, modern, false, "request [REDACTED] failed: [REDACTED]");
    http.send_error = NULL;
    expect_verification(detector, &http, legacy, false, "HTTP transport failed");
}

int main(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_alchemy_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(br_alchemy_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_alchemy_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 907 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Alchemy") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Alchemy is a blockchain development platform that provides a suite of tools and services "
        "for building and scaling decentralized applications. Alchemy API keys can be used to access these services."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "alchemy") &&
          !strcmp(detector->keywords[1], "alcht_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(br_detector_is_default(detector, NULL));
    char legacy[33], modern[37];
    test_secret(legacy, 32, 3);
    legacy[0] = 'B';
    legacy[7] = legacy[15] = '_';
    memcpy(modern, "alcht_", 6);
    test_secret(modern + 6, 30, 9);
    modern[6] = 'B';
    extraction(detector, legacy, modern);
    verification(detector, legacy, modern);
    return test_finish("Alchemy");
}
