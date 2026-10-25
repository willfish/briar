/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_abyssale_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector && detector->type == 239 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Abyssale"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Abyssale is a service offering various API functionalities for marketing "
        "automation and services such as images and ad campaigns. Abyssale API "
        "keys can be used to access and interact with this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "abyssale"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_abyssale_init(&again, NULL) == 0 && again == detector);
    CHECK(br_abyssale_init(NULL, &error) != 0 && error != NULL);
    free(error);
    CHECK(br_abyssale_init(NULL, NULL) != 0);
    return detector;
}

static void expect_keys(const br_detector *detector, const br_scan_ctx *ctx,
                        const void *input, size_t len,
                        const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 239, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[41], second[41], input[256];
    test_secret(key, 40, 0);
    test_secret(second, 40, 9);
    key[0] = 'B';
    key[8] = 'Z';
    const char *keys[] = {key, second};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"abyssale = '%s'", 1},
        {"ABYSSALE: %s", 1},
        {"prefixabyssalesuffix=%s", 1},
        {"%s", 0},
        {"%s abyssale", 0},
        {"abyssale%s", 0},
        {"abyssale _%s", 0},
        {"abyssale %s_", 0},
        {"abyssale %.39s", 0},
        {"abyssale %sq", 0},
        {"abyssale\r%s", 1},
        {"abyssale\n%s", 1},
        {"abyssale\r\n%s", 1},
        {"abyssale \xc3\xa9%s\xc3\xa9", 1},
        {"abyssale %s\nabyssale %s", 2},
        {"abyssale %s %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, second);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_keys(detector, &ctx, input, (size_t)len, keys, cases[i].count);
    }
    expect_keys(detector, &ctx, NULL, 0, NULL, 0);

    memcpy(input, "abyssale\0", 9);
    memcpy(input + 9, key, 40);
    expect_keys(detector, &ctx, input, 49, keys, 1);

    char invalid[41];
    memcpy(invalid, key, sizeof(invalid));
    invalid[20] = '-';
    snprintf(input, sizeof(input), "abyssale %s", invalid);
    expect_keys(detector, &ctx, input, strlen(input), NULL, 0);

    const char *duplicates[] = {key, key};
    snprintf(input, sizeof(input), "abyssale %s\nabyssale %s", key, key);
    expect_keys(detector, &ctx, input, strlen(input), duplicates, 2);

    memset(second, 'a', 40);
    const char *low_entropy[] = {second};
    snprintf(input, sizeof(input), "abyssale %s", second);
    expect_keys(detector, &ctx, input, strlen(input), low_entropy, 1);
    CHECK(http.calls == 0 && http.releases == 0);

    /* PrefixRegex counts Unicode runes. CR matches both prefix alternatives;
     * an out-of-range CR prefix must still reject without exhausting matching. */
    const char *separators[] = {"-", "\n", "\xc3\xa9", "\r"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        for (size_t gap = 40; gap <= 41; ++gap) {
            memcpy(input, "abyssale", 8);
            size_t at = 8, width = strlen(separators[i]);
            for (size_t j = 0; j < gap; ++j) {
                memcpy(input + at, separators[i], width);
                at += width;
            }
            memcpy(input + at, key, 40);
            expect_keys(detector, &ctx, input, at + 40, keys, gap == 40 ? 1 : 0);
        }
    }
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const char *key = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.abyssale.com/ready"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 239);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "x-api-key")) {
            ++auth;
            CHECK(!strcmp(header->value, key));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ?
                          "TruffleHog abyssale-test" : "TruffleHog"));
        } else {
            CHECK(!"unexpected Abyssale request header");
        }
    }
    CHECK(auth == 1 && agent == 1);
}

static void test_verification(const br_detector *detector)
{
    char key[41], input[128], sensitive_error[128];
    test_secret(key, 40, 0);
    snprintf(input, sizeof(input), "abyssale %s", key);
    snprintf(sensitive_error, sizeof(sensitive_error), "request %s failed: %s", key, key);
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected HTTP response status 201"},
        {401, 0, NULL, false, "unexpected HTTP response status 401"},
        {429, 0, NULL, false, "unexpected HTTP response status 429"},
        {500, 0, NULL, false, "unexpected HTTP response status 500"},
        {200, 1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, 1, "context canceled", false, "context canceled"},
        {200, 1, sensitive_error, false, "request [REDACTED] failed: [REDACTED]"},
        {200, 1, NULL, false, "HTTP transport failed"},
    };
    const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {.status = cases[i].status,
                         .body = {body, sizeof(body)}, .body_error = sensitive_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = key,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "abyssale-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        test_key_result(result, 239, key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error);
            CHECK(!strcmp(result->verification_error, cases[i].error));
            CHECK(!strstr(result->verification_error, key));
        } else {
            CHECK(!result->verification_error);
        }
        br_results_clear(&results);
    }

    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const char no_key[] = "abyssale no candidate";
    br_results results = test_scan(detector, &ctx, true, no_key, sizeof(no_key) - 1);
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "abyssale %s\nabyssale %s", key, key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 239, key, "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_verification(detector);
    test_extraction(detector);
    return test_finish("Abyssale");
}
