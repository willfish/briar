/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *const *keys; size_t len; } expected_requests;

static void make_key(char key[89], size_t shift)
{
    test_secret(key, 88, shift);
    key[0] = 'B';
    key[20] = '=';
    key[21] = '=';
    key[36] = '+';
    key[45] = 'Z';
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_appointedd_init(&detector, &error) == 0 && !error);
    CHECK(detector && detector->type == 816 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Appointedd"));
    CHECK(detector->custom_name && !detector->custom_name[0]);
    CHECK(!strcmp(detector->description,
        "Appointedd provides online booking and scheduling services. "
        "The API key can be used to access and manage booking data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "appointedd"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(br_appointedd_init(&again, &error) == 0 && !error && again == detector);
    CHECK(again->state == pattern);
    CHECK(br_appointedd_init(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(br_appointedd_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_appointedd_init(NULL, NULL) != 0);
    return detector;
}

static void expect_extraction(const br_detector *detector, const br_scan_ctx *ctx,
                              const void *input, size_t len,
                              const char *const *keys, size_t count)
{
    br_results results = test_scan(detector, ctx, false, input, len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 816, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[89], second[89], changed[89], input[512];
    make_key(key, 0);
    make_key(second, 9);
    const char *one[] = {key};
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { const char *format; size_t count; } cases[] = {
        {"appointedd = '%s'", 1},
        {"APPOINTEDD: %s", 1},
        {"prefixappointeddsuffix:%s", 1},
        {"%s", 0},
        {"%s appointedd", 0},
        {"appointedd%s", 0},
        {"appointedd _%s", 0},
        {"appointedd %.87s", 0},
        {"appointedd %sQ", 1},
        {"appointedd %s_", 1},
        {"appointedd\r\n%s", 1},
        {"appointedd %s %s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int len = snprintf(input, sizeof(input), cases[i].format, key, second);
        CHECK(len >= 0 && (size_t)len < sizeof(input));
        expect_extraction(detector, &ctx, input, (size_t)len, one, cases[i].count);
    }
    /* At a word-to-'=' boundary, '=' can be the first captured byte. */
    changed[0] = '=';
    memcpy(changed + 1, key, 87);
    changed[88] = '\0';
    const char *equals[] = {changed};
    snprintf(input, sizeof(input), "prefixappointeddsuffix=%s", key);
    expect_extraction(detector, &ctx, input, strlen(input), equals, 1);
    expect_extraction(detector, &ctx, NULL, 0, NULL, 0);
    const char prefix[] = "appointedd";
    size_t prefix_len = sizeof(prefix) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key, sizeof(key));
        expect_extraction(detector, &ctx, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), key, 88);
    expect_extraction(detector, &ctx, input, sizeof(prefix) + 88, one, 1);

    memcpy(changed, key, sizeof(changed));
    changed[40] = '/';
    snprintf(input, sizeof(input), "appointedd %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    changed[40] = '_';
    snprintf(input, sizeof(input), "appointedd %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);

    /* '+' is nonword: a zero gap after the keyword provides the left boundary,
     * whereas a preceding space does not. No Base64 padding rules are imposed. */
    memcpy(changed, key, sizeof(changed));
    changed[0] = '+';
    const char *plus[] = {changed};
    snprintf(input, sizeof(input), "appointedd%s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), plus, 1);
    snprintf(input, sizeof(input), "appointedd %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), NULL, 0);
    memcpy(changed, key, sizeof(changed));
    changed[87] = '=';
    snprintf(input, sizeof(input), "appointedd %s", changed);
    expect_extraction(detector, &ctx, input, strlen(input), plus, 1);

    const char *three[] = {key, second, key};
    snprintf(input, sizeof(input), "appointedd %s\nappointedd %s\nappointedd %s", key, second, key);
    expect_extraction(detector, &ctx, input, strlen(input), three, 3);
    memset(key, 'a', 88);
    snprintf(input, sizeof(input), "appointedd %s", key);
    expect_extraction(detector, &ctx, input, strlen(input), one, 1);
    CHECK(http.calls == 0 && http.releases == 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    const char *key = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.appointedd.com/v1/availability/slots"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 816);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "X-API-KEY")) {
            ++auth;
            CHECK(!strcmp(header->value, key));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ?
                          "TruffleHog appointedd-test" : "TruffleHog"));
        } else {
            CHECK(!"unexpected Appointedd request header");
        }
    }
    CHECK(auth == 1 && agent == 1);
}

static void test_occurrences(const br_detector *detector)
{
    char first[89], second[89], input[512];
    make_key(first, 0);
    make_key(second, 9);
    const char *keys[] = {first, second, first};
    expected_requests expected = {keys, 3};
    static const unsigned char body[] = "total";
    test_http http = {
        .response = {.status = 200, .body = {body, sizeof(body) - 1}},
        .inspect = inspect_request, .user = &expected,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "appointedd %s\nappointedd %s\nappointedd %s", first, second, first);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 816, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    char key[89], input[128], sensitive[256];
    make_key(key, 0);
    snprintf(input, sizeof(input), "appointedd %s", key);
    snprintf(sensitive, sizeof(sensitive), "read key %s failed; again %s", key, key);
    const unsigned char total[] = "total";
    const unsigned char json[] = "{\"total\":0}";
    const unsigned char substring[] = "subtotal";
    const unsigned char after_nul[] = {0, 0xff, 't', 'o', 't', 'a', 'l', 0};
    const unsigned char wrong_case[] = "Total TOTAL";
    const unsigned char absent[] = "not JSON: to tal";
    const char *redacted = "read key [REDACTED] failed; again [REDACTED]";
    const struct {
        int status;
        br_slice body;
        const char *body_error;
        int send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {.status = 200},
        {.status = 200, .body = {total, sizeof(total) - 1}, .verified = true},
        {.status = 200, .body = {json, sizeof(json) - 1}, .verified = true},
        {.status = 200, .body = {substring, sizeof(substring) - 1}, .verified = true},
        {.status = 200, .body = {after_nul, sizeof(after_nul)}, .verified = true},
        {.status = 200, .body = {wrong_case, sizeof(wrong_case) - 1}},
        {.status = 200, .body = {absent, sizeof(absent) - 1}},
        {.status = 200, .body = {total, sizeof(total) - 1}, .body_error = sensitive, .error = redacted},
        {.status = 200, .body_error = "body read failed", .error = "body read failed"},
        {.status = 401, .body = {total, sizeof(total) - 1}, .body_error = sensitive},
        {.status = 403, .body = {total, sizeof(total) - 1}, .body_error = sensitive},
        {.status = 201, .body_error = sensitive, .error = "unexpected status code: 201"},
        {.status = 404, .body_error = sensitive, .error = "unexpected status code: 404"},
        {.status = 429, .body_error = sensitive, .error = "unexpected status code: 429"},
        {.status = 500, .body_error = sensitive, .error = "unexpected status code: 500"},
        {.status = 200, .send_rc = 1,
         .send_error = "context deadline exceeded", .error = "context deadline exceeded"},
        {.status = 200, .send_rc = 1, .send_error = "context canceled", .error = "context canceled"},
        {.status = 200, .send_rc = 1, .send_error = sensitive, .error = redacted},
        {.status = 200, .send_rc = 1, .error = "HTTP transport failed"},
    };
    const char *keys[] = {key};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {keys, 1};
        test_http http = {
            .response = {.status = cases[i].status, .body = cases[i].body,
                         .body_error = cases[i].body_error},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "appointedd-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0];
        test_key_result(result, 816, key, "key");
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
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_occurrences(detector);
    test_verification(detector);
    return test_finish("Appointedd");
}
