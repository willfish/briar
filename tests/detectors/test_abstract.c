/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static void expect_keys(const br_detector *detector, const br_scan_ctx *ctx,
                        const void *input, size_t len, const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 384, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_descriptor(const br_detector *detector)
{
    CHECK(BR_ABI_REVISION == 1);
    CHECK(detector->type == 384 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Abstract") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
                  "Abstract API provides various services including exchange rates. "
                  "The API keys can be used to access these services and retrieve data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "abstract"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(!br_detector_is_default(detector, NULL));

    const br_detector *again = NULL;
    char *error = NULL;
    CHECK(br_abstract_init(&again, &error) == 0 && !error && again == detector);
    CHECK(br_abstract_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_abstract_init(NULL, NULL) != 0);
}

static void test_extraction(const br_detector *detector, const char *key)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const char *one[] = {key};
    char input[256];
    const struct {
        const char *format;
        size_t count;
    } cases[] = {
        {"abstract = '%s'", 1},
        {"AbStRaCt = %s", 1},
        {"preabstractsuffix:%s", 1},
        {"%s", 0},
        {"%s abstract", 0},
        {"abstract%s", 0},
        {"abstract _%s", 0},
        {"abstract %s_", 0},
        {"abstract x%s", 0},
        {"abstract %sx", 0},
        {"abstract %.31s", 0},
        {"abstract\r%s", 1},
        {"abstract\n%s", 1},
        {"abstract\r\n%s", 1},
        {"abstract \xc3\xa9%s\xc3\xa9", 1}, /* ASCII word boundaries. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key);
        expect_keys(detector, &ctx, input, strlen(input), one, cases[i].count);
    }
    expect_keys(detector, &ctx, NULL, 0, NULL, 0);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "abstract", 8);
        memset(input + 8, '-', gap);
        memcpy(input + 8 + gap, key, 33);
        expect_keys(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);

        /* PrefixRegex counts characters, not UTF-8 bytes. */
        size_t at = 8;
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        memcpy(input + at, key, 33);
        expect_keys(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);
    }

    char changed[33];
    memcpy(changed, key, sizeof(changed));
    changed[0] = 'B'; /* Keyword case folding must not affect the capture. */
    snprintf(input, sizeof(input), "abstract %s", changed);
    expect_keys(detector, &ctx, input, strlen(input), NULL, 0);
    changed[0] = '_';
    snprintf(input, sizeof(input), "abstract %s", changed);
    expect_keys(detector, &ctx, input, strlen(input), NULL, 0);

    memset(changed, 'a', 32);
    changed[32] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "abstract %s", changed);
    expect_keys(detector, &ctx, input, strlen(input), low_entropy, 1);

    char second[33];
    test_secret(second, 32, 9);
    const char *three[] = {key, second, key};
    snprintf(input, sizeof(input), "abstract %s\nabstract %s\nabstract %s", key, second, key);
    expect_keys(detector, &ctx, input, strlen(input), three, 3);
    snprintf(input, sizeof(input), "abstract %s %s", key, second);
    expect_keys(detector, &ctx, input, strlen(input), one, 1);

    memcpy(input, "abstract\0", 9);
    memcpy(input + 9, key, 32);
    expect_keys(detector, &ctx, input, 41, one, 1);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    const char *key = http->user;
    char url[160];
    snprintf(url, sizeof(url),
             "https://exchange-rates.abstractapi.com/v1/live/?api_key=%s&base=USD", key);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 384);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog"));
}

static void test_verification(const br_detector *detector, char *key)
{
    char secret_error[128], input[64];
    snprintf(secret_error, sizeof(secret_error), "timeout for %s; key=%s", key, key);
    snprintf(input, sizeof(input), "abstract %s", key);
    const struct {
        int status;
        const char *body_error, *send_error;
        int send_rc;
        bool verified;
        const char *expected_error;
    } cases[] = {
        {.status = 200, .verified = true},
        {.status = 200, .body_error = "body read failed", .verified = true},
        {.status = 401},
        {.status = 401, .body_error = "body read failed"},
        {.status = 403, .expected_error = "unexpected HTTP response status 403"},
        {.status = 500, .body_error = "body read failed",
         .expected_error = "unexpected HTTP response status 500"},
        {.status = 200, .send_rc = 1, .send_error = "context deadline exceeded",
         .expected_error = "context deadline exceeded"},
        {.status = 200, .send_rc = 1, .send_error = "context canceled",
         .expected_error = "context canceled"},
        {.status = 200, .send_rc = 1, .expected_error = "HTTP transport failed"},
        {.status = 200, .send_rc = 1, .send_error = secret_error,
         .expected_error = "timeout for [REDACTED]; key=[REDACTED]"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {
            .response = {
                .status = cases[i].status,
                .body = {(const unsigned char *)"not JSON", 8},
                .body_error = cases[i].body_error,
            },
            .send_error = cases[i].send_error, .send_rc = cases[i].send_rc,
            .inspect = inspect_request, .user = key,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 384, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].expected_error) {
            CHECK(results.items[0].verification_error);
            CHECK(!strcmp(results.items[0].verification_error, cases[i].expected_error));
            CHECK(!strstr(results.items[0].verification_error, key));
        } else {
            CHECK(!results.items[0].verification_error);
        }
        br_results_clear(&results);
    }

    br_scan_ctx ctx = {0};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 384, key, "key");
    CHECK(results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_abstract_init(&detector, &error) == 0 && !error && detector);
    test_descriptor(detector);
    char key[33];
    test_secret(key, 32, 0);
    test_extraction(detector, key);
    test_verification(detector, key);
    return test_finish("Abstract");
}
