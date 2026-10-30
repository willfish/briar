/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_tradier_init(const br_detector **out, char **error);

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_tradier_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector && detector->type == 372 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Tradier"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description, "Tradier is a financial services provider that offers a trading platform and API. Tradier API keys can be used to access and manage trading accounts and execute trades."));
    CHECK(detector->nkeywords == 1);
    CHECK(!strcmp(detector->keywords[0], "tradier"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_tradier_init(&again, NULL) == 0 && again == detector);
    CHECK(br_tradier_init(NULL, &error) != 0 && error != NULL);
    free(error);
    CHECK(br_tradier_init(NULL, NULL) != 0);
    return detector;
}

static void expect_keys(const br_detector *detector, const void *input, size_t len,
                        const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 372, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[29], second[29], input[256];
    test_secret(key, 28, 0);
    test_secret(second, 28, 4);
    const char *keys[] = {key, second};
    snprintf(input, sizeof(input), "tradier = '%s'", key);
    expect_keys(detector, input, strlen(input), keys, 1);
    snprintf(input, sizeof(input), "prefixtradier=%s", key);
    expect_keys(detector, input, strlen(input), keys, 1);
    snprintf(input, sizeof(input), "%s", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "tradier %s_", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "tradier %.27s", key);
    expect_keys(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "tradier\n%s\ntradier %s", key, second);
    expect_keys(detector, input, strlen(input), keys, 2);
    const char *dups[] = {key, key};
    snprintf(input, sizeof(input), "tradier %s tradier %s", key, key);
    expect_keys(detector, input, strlen(input), dups, 2);
    char upper[29];
    memcpy(upper, key, 29);
    upper[0] = 'A';
    snprintf(input, sizeof(input), "tradier %s", upper);
    expect_keys(detector, input, strlen(input), (const char *const[]){upper}, 1);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = http->user;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.tradier.com/v1/watchlists"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 372);
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->nheaders == 2);
    char bearer[64];
    snprintf(bearer, sizeof(bearer), "Bearer %s", key);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, bearer));
    (void)ctx;
}

static void test_verification(const br_detector *detector)
{
    char key[29], input[64];
    test_secret(key, 28, 1);
    snprintf(input, sizeof(input), "tradier %s", key);
    const struct { int status, send_rc; bool verified; } cases[] = {
        {200, 0, true}, {299, 0, true}, {300, 0, false}, {401, 0, false}, {200, 1, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .send_rc = cases[i].send_rc,
                          .send_error = cases[i].send_rc ? "dial failed" : NULL,
                          .inspect = inspect_request, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == cases[i].verified);
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results skipped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    return test_finish("Tradier");
}
