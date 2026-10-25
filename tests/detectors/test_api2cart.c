/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct {
    const char *keys[2];
    size_t len;
    bool seen[2];
} expected_requests;

static void make_key(char key[33], size_t shift)
{
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) key[i] = hex[(i + shift) % 16];
    key[32] = '\0';
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_api2cart_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 458 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Api2Cart"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Api2Cart is a unified shopping cart data interface that allows interaction with "
        "multiple shopping cart platforms. Api2Cart API keys can be used to access and "
        "manipulate shopping cart data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "api2cart"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_api2cart_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_api2cart_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_api2cart_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_api2cart_init(NULL, NULL) != 0);
    return detector;
}

static void expect_key(const br_detector *detector, const br_scan_ctx *ctx,
                       const void *input, size_t len, const char *key, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    if (count) {
        CHECK(count == 1);
        test_key_result(&results.items[0], 458, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[33], changed[33], input[256];
    make_key(key, 0);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"api2cart = '%s'", 1},
        {"API2CART: %s", 1},
        {"prefixapi2cartsuffix=%s", 1},
        {"%s", 0},
        {"%s api2cart", 0},
        {"api2cart%s", 0},
        {"api2cart _%s", 0},
        {"api2cart %s_", 0},
        {"api2cart %.31s", 0},
        {"api2cart %sa", 0},
        {"api2cart A%.31s", 0},
        {"api2cart\r\n%s", 1},
        {"api2cart %s\napi2cart %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, key);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_key(detector, &ctx, input, (size_t)len, key, cases[i].count);
    }
    expect_key(detector, &ctx, NULL, 0, NULL, 0);
    const char prefix[] = "api2cart";
    size_t prefix_len = sizeof(prefix) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key, sizeof(key));
        expect_key(detector, &ctx, input, strlen(input), key, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, 32);
    expect_key(detector, &ctx, input, sizeof(prefix) + 32, key, 1);
    memcpy(changed, key, sizeof(changed));
    changed[16] = 'g';
    snprintf(input, sizeof(input), "api2cart %s", changed);
    expect_key(detector, &ctx, input, strlen(input), NULL, 0);
    memset(key, 'a', 32);
    snprintf(input, sizeof(input), "api2cart %s", key);
    expect_key(detector, &ctx, input, strlen(input), key, 1);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(expected->len <= sizeof(expected->keys) / sizeof(expected->keys[0]));
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    size_t i = 0;
    for (; i < expected->len; ++i) {
        char url[160];
        snprintf(url, sizeof(url),
                 "https://api.api2cart.com/v1.1/account.cart.list.json?api_key=%s", expected->keys[i]);
        if (!strcmp(request->url, url)) break;
    }
    CHECK(i < expected->len && !expected->seen[i]);
    expected->seen[i] = true;
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 458);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t accept = 0, agent = 0;
    for (size_t h = 0; h < request->nheaders; ++h) {
        const br_header *header = &request->headers[h];
        if (!strcmp(header->name, "Accept")) {
            ++accept;
            CHECK(!strcmp(header->value, "application/json"));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog api2cart-test" : "TruffleHog"));
        } else {
            CHECK(!"unexpected Api2Cart request header");
        }
    }
    CHECK(accept == 1 && agent == 1);
}

static void verification_case(const br_detector *detector, const char *key,
                              br_http_response response, int send_rc, const char *send_error,
                              bool verified, const char *expected_error)
{
    expected_requests expected = {.keys = {key}, .len = 1};
    test_http http = {
        .response = response, .send_rc = send_rc, .send_error = send_error,
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "api2cart-test"};
    char input[64];
    snprintf(input, sizeof(input), "api2cart %s", key);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    const br_result *result = &results.items[0];
    test_key_result(result, 458, key, "key");
    CHECK(result->verified == verified);
    if (expected_error) {
        CHECK(result->verification_error);
        /* Upstream omits secret arguments; compare without logging the cause. */
        CHECK(!strcmp(result->verification_error, expected_error));
    } else {
        CHECK(!result->verification_error);
    }
    br_results_clear(&results);
}

static void test_unique_keys(const br_detector *detector)
{
    char first[33], second[33], input[256];
    make_key(first, 0);
    make_key(second, 5);
    snprintf(input, sizeof(input), "api2cart %s\napi2cart %s\napi2cart %s\napi2cart %s",
             first, second, first, second);
    static const unsigned char zero_response[] = "{}";
    for (int verify = 0; verify <= 1; ++verify) {
        expected_requests expected = {.keys = {first, second}, .len = 2};
        test_http http = {
            .response = {.status = 200, .body = {zero_response, sizeof(zero_response) - 1}},
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 2 && http.calls == (verify ? 2u : 0u) && http.releases == http.calls);
        bool seen[2] = {0};
        for (size_t i = 0; i < results.len; ++i) {
            const br_result *result = &results.items[i];
            CHECK(result->raw.data && result->raw.len == 32);
            size_t j = !memcmp(result->raw.data, first, 32) ? 0 : 1;
            CHECK(!seen[j]);
            seen[j] = true;
            test_key_result(result, 458, expected.keys[j], "key");
            CHECK(result->verified == (bool)verify && !result->verification_error);
        }
        br_results_clear(&results);
    }
}

static void test_status_and_read_errors(const br_detector *detector)
{
    char key[33], sensitive[128];
    make_key(key, 0);
    snprintf(sensitive, sizeof(sensitive), "API key %s failed", key);
    const struct { int status; const char *error; } cases[] = {
        {401, NULL}, {403, NULL},
        {201, "unexpected status code: 201"},
        {404, "unexpected status code: 404"},
        {429, "unexpected status code: 429"},
        {500, "unexpected status code: 500"},
    };
    const unsigned char invalid[] = "{";
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_http_response response = {
            .status = cases[i].status, .body = {invalid, sizeof(invalid) - 1}, .body_error = sensitive,
        };
        verification_case(detector, key, response, 0, NULL, false, cases[i].error);
    }
    verification_case(detector, key, (br_http_response){.status = 200, .body_error = sensitive},
                      0, NULL, false, sensitive);
    const unsigned char valid[] = "{\"return_code\":0}";
    br_http_response response = {
        .status = 200, .body = {valid, sizeof(valid) - 1}, .body_error = "body read failed",
    };
    verification_case(detector, key, response, 0, NULL, false, "body read failed");
    const char *errors[] = {"context deadline exceeded", "context canceled", sensitive, NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i)
        verification_case(detector, key, response, 1, errors[i], false,
                          errors[i] ? errors[i] : "HTTP transport failed");
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);
}

static void test_json_response(const br_detector *detector)
{
    char key[33];
    make_key(key, 0);
    const char *string_error = "json: cannot unmarshal string into Go struct field Response.return_code of type int";
    const struct { const char *body; bool verified; const char *error; } cases[] = {
        {"{\"return_code\":0}", true, NULL},
        {"{\"return_code\":-0} \r\n\t", true, NULL},
        {"{\"return_code\":1}", false, NULL},
        {"{\"return_code\":-1}", false, NULL},
        {"{}", true, NULL},
        {"null", true, NULL},
        {"{\"return_code\":null}", true, NULL},
        {"{\"result\":{\"return_code\":7}}", true, NULL},
        {"{\"ReturnCode\":7}", true, NULL},
        {"{\"RETURN_CODE\":0}", true, NULL},
        {"{\"Return_Code\":7}", false, NULL},
        {"{\"return_\\u0063ode\":0}", true, NULL},
        {"{\"return_code\":1,\"return_code\":0}", true, NULL},
        {"{\"return_code\":0,\"RETURN_CODE\":1}", false, NULL},
        {"{\"return_code\":1,\"return_code\":null}", false, NULL},
        {"{\"return_code\":null,\"return_code\":0}", true, NULL},
        {"{\"return_code\":\"0\"}", false, string_error},
        {"{\"return_code\":false}", false,
         "json: cannot unmarshal bool into Go struct field Response.return_code of type int"},
        {"{\"return_code\":[]}", false,
         "json: cannot unmarshal array into Go struct field Response.return_code of type int"},
        {"{\"return_code\":\"bad\",\"RETURN_CODE\":0}", false, string_error},
        {"{\"return_code\":\"bad\",\"return_code\":false}", false, string_error},
        {"[]", false, "json: cannot unmarshal array into Go value of type api2cart.Response"},
        {"123", false, "json: cannot unmarshal number into Go value of type api2cart.Response"},
        {"{\"return_code\":9223372036854775807}", false, NULL},
        {"{\"return_code\":-9223372036854775808}", false, NULL},
        {"{\"return_code\":9223372036854775808}", false,
         "json: cannot unmarshal number 9223372036854775808 into Go struct field Response.return_code of type int"},
        {"{\"return_code\":1.5}", false,
         "json: cannot unmarshal number 1.5 into Go struct field Response.return_code of type int"},
        {"{\"return_code\":0e0}", false,
         "json: cannot unmarshal number 0e0 into Go struct field Response.return_code of type int"},
        {"{\"return_code\":0.0,\"return_code\":0}", false,
         "json: cannot unmarshal number 0.0 into Go struct field Response.return_code of type int"},
        {"", false, "unexpected end of JSON input"},
        {" \r\n\t ", false, "unexpected end of JSON input"},
        {"{", false, "unexpected end of JSON input"},
        {"{\"return_code\":", false, "unexpected end of JSON input"},
        {"{\"return_code\":0} garbage", false, "invalid character 'g' after top-level value"},
        {"{} {}", false, "invalid character '{' after top-level value"},
        {"{return_code:0}", false, "invalid character 'r' looking for beginning of object key string"},
        /* Valid JSON outside json-c's native integer range must still reach the
         * typed member decoder with its original numeric text. */
        {"{\"ignored\":-9223372036854775809,\"return_code\":0}", true, NULL},
        {"{\"ignored\":\"-9223372036854775809\",\"return_code\":0}", true, NULL},
        {"{\"ignored\":-9223372036854775809,\"return_code\":\"0\"}", false, string_error},
        {"{\"return_code\":-9223372036854775809} garbage", false,
         "invalid character 'g' after top-level value"},
        {"{\"return_code\":18446744073709551616}", false,
         "json: cannot unmarshal number 18446744073709551616 into Go struct field Response.return_code of type int"},
        {"{\"return_code\":-9223372036854775809}", false,
         "json: cannot unmarshal number -9223372036854775809 into Go struct field Response.return_code of type int"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_http_response response = {
            .status = 200,
            .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)},
        };
        verification_case(detector, key, response, 0, NULL, cases[i].verified, cases[i].error);
    }
}

static void test_range_syntax(const br_detector *detector)
{
    const char *invalid[] = {
        "{\"return_code\":00}",
        "{\"ignored\":-9223372036854775809,\"return_code\":00}",
        "{\"ignored\":-9223372036854775809,\"return_code\":--9223372036854775809}",
        "{\"ignored\":-9223372036854775809,}",
        "{\"ignored\":-9223372036854775809,/*comment*/\"return_code\":0}",
        "{\"ignored\":-9223372036854775809,\"return_code\":0e}",
        "{\"ignored\":-9223372036854775809,\"return_code\":NaN}",
    };
    char key[33], input[64];
    make_key(key, 0);
    snprintf(input, sizeof(input), "api2cart %s", key);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        test_http http = {.response = {.status = 200,
            .body = {(const unsigned char *)invalid[i], strlen(invalid[i])}}};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        if (results.items[0].verified || !results.items[0].verification_error)
            fprintf(stderr, "range syntax case %zu accepted\n", i);
        CHECK(!results.items[0].verified && results.items[0].verification_error);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_unique_keys(detector);
    test_status_and_read_errors(detector);
    test_json_response(detector);
    test_range_syntax(detector);
    return test_finish("Api2Cart");
}
