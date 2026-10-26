/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char first_key[33], second_key[33];
static const unsigned char marker[] = "\"message\":\"Successful\",";
static bool fail_status_copy;
typedef struct { const char *const *keys; size_t len; bool fail_second; } expected_requests;

/* Fail just this setter copy to exercise its real positive +1 return. */
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, "unexpected status code: 429")) {
        fail_status_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bulbul_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_bulbul_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 317 && detector->version == 0 && !strcmp(detector->name, "Bulbul"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Bulbul is an API service. Bulbul API keys can be used to access and modify data within the service."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bulbul"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_bulbul_init(NULL, &error) != 0 && error);
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
        test_key_result(&results.items[i], 317, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[160], changed[34];
    const struct { const char *format; size_t count; } cases[] = {
        {"bulbul '%s'", 1}, {"BULBUL=%s", 1}, {"BuLbUl\t%s", 1},
        {"prefixbulbulsuffix %s", 1}, {"bulbul\r\n%s\t", 1},
        {"%s", 0}, {"bul bul %s", 0}, {"bulbul %.31s", 0},
        {"bulbul a%s", 0}, {"bulbul %sa", 0}, {"bulbul _%s", 0}, {"bulbul %s_", 0},
        {"bulbul +%s/", 1}, {"bulbul %s=", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, first_key);
        expect_extraction(detector, input, strlen(input), first_key, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "bulbul", 6); memset(input + 6, ':', gap);
        snprintf(input + 6 + gap, sizeof(input) - 6 - gap, "%s", first_key);
        expect_extraction(detector, input, strlen(input), first_key, gap == 40 ? 1 : 0);
    }
    memcpy(changed, first_key, sizeof(first_key)); changed[0] = 'B';
    snprintf(input, sizeof(input), "BULBUL %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, first_key, sizeof(first_key));
    for (size_t i = 0; i < 32; ++i)
        if (changed[i] >= 'a' && changed[i] <= 'z') changed[i] += 'A' - 'a';
    snprintf(input, sizeof(input), "BULBUL %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0); /* CI remains scoped to keyword. */
    memcpy(changed, first_key, sizeof(first_key)); changed[16] = '-';
    snprintf(input, sizeof(input), "bulbul %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(changed, 'z', 32); changed[32] = 0;
    snprintf(input, sizeof(input), "bulbul %s", changed);
    expect_extraction(detector, input, strlen(input), changed, 1); /* Nonhex, low entropy, still accepted. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    char url[144];
    snprintf(url, sizeof(url), "https://prod-api.bulbul.io/view_all_users?api_key=%s", expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 317);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ? "TruffleHog bulbul-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1);
    if (expected->fail_second && http->calls == 2) {
        http->response.status = 429;
        fail_status_copy = true;
    }
}

static void occurrences(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "bulbul %s\nBULBUL %s\nbulbul %s", first_key, second_key, first_key);
    const char *keys[] = {first_key, second_key, first_key}; expected_requests expected = {keys, 3, false};
    for (int mode = 0; mode < 3; ++mode) {
        const char *cause = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL;
        test_http http = {.response = {.status = 200, .body = {marker, sizeof(marker) - 1}},
                          .send_rc = mode == 2 ? 1 : 0, .send_error = cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (mode ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 317, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1));
            if (cause) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, cause));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 317, keys[i], "key");
            CHECK(!results.items[i].verified);
            if (verify) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void verification(const br_detector *detector)
{
    char input[96], unredacted[256]; snprintf(input, sizeof(input), "bulbul %s", second_key);
    snprintf(unredacted, sizeof(unredacted), "GET https://prod-api.bulbul.io/view_all_users?api_key=%s read/Do error again=%s", second_key, second_key);
    const char *keys[] = {second_key}; expected_requests expected = {keys, 1, false};
    static const unsigned char json[] = "{\"message\":\"Successful\",\"users\":[]}";
    static const unsigned char no_comma[] = "{\"message\":\"Successful\"}";
    static const unsigned char spaced[] = "{\"message\": \"Successful\",\"users\":[]}";
    static const unsigned char lower[] = "{\"message\":\"successful\",\"users\":[]}";
    static const unsigned char wrong_field[] = "{\"Message\":\"Successful\",\"users\":[]}";
    static const unsigned char binary[] = "x\0\xff\"message\":\"Successful\",junk";
    const br_slice exact_body = {marker, sizeof(marker) - 1}, binary_body = {binary, sizeof(binary) - 1};
    const struct { int status; br_slice body; const char *read_error; int send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, {json, sizeof(json) - 1}, NULL, 0, NULL, true, NULL},
        {200, exact_body, NULL, 0, NULL, true, NULL}, /* Not JSON: only literal substring matters. */
        {200, binary_body, NULL, 0, NULL, true, NULL}, /* Full search past NUL/invalid UTF-8. */
        {200, {no_comma, sizeof(no_comma) - 1}, NULL, 0, NULL, false, NULL},
        {200, {spaced, sizeof(spaced) - 1}, NULL, 0, NULL, false, NULL},
        {200, {lower, sizeof(lower) - 1}, NULL, 0, NULL, false, NULL},
        {200, {wrong_field, sizeof(wrong_field) - 1}, NULL, 0, NULL, false, NULL},
        {200, {NULL, 0}, NULL, 0, NULL, false, NULL},
        {200, binary_body, unredacted, 0, NULL, false, unredacted}, /* Read error wins over present marker. */
        {401, binary_body, unredacted, 0, NULL, false, NULL},
        {403, binary_body, unredacted, 0, NULL, false, "unexpected status code: 403"},
        {201, binary_body, unredacted, 0, NULL, false, "unexpected status code: 201"},
        {500, binary_body, unredacted, 0, NULL, false, "unexpected status code: 500"},
        {200, binary_body, NULL, 1, "lookup synthetic.invalid: no such host", false, "lookup synthetic.invalid: no such host"},
        {200, binary_body, NULL, -1, "context canceled", false, "context canceled"},
        {200, binary_body, NULL, 1, unredacted, false, unredacted},
        {200, binary_body, NULL, 1, NULL, false, "HTTP transport failed"},
        {200, binary_body, NULL, 0, NULL, true, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "bulbul-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 317, second_key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        if (cases[i].error == unredacted) {
            CHECK(strstr(results.items[0].verification_error, second_key));
            CHECK(!strstr(results.items[0].verification_error, "[REDACTED]"));
        }
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void contexts(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "bulbul %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1, false};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        test_key_result(&results.items[0], 317, first_key, "key");
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_status_copy = true;
    CHECK(br_result_set_verification_error(&probe, "unexpected status code: 429", NULL, 0) == 1);
    CHECK(!fail_status_copy && !probe.verification_error); br_result_clear(&probe);
    char input[192]; snprintf(input, sizeof(input), "bulbul %s\nbulbul %s\nbulbul %s", first_key, second_key, first_key);
    const char *keys[] = {first_key, second_key, first_key}; expected_requests expected = {keys, 3, true};
    test_http http = {.response = {.status = 200, .body = {marker, sizeof(marker) - 1}}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!fail_status_copy && http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); br_results_clear(&results);
    expected.fail_second = false; http.calls = http.releases = 0; http.response.status = 200;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) { test_key_result(&results.items[i], 317, keys[i], "key"); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    test_secret(first_key, 32, 0); test_secret(second_key, 32, 7);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification(detector); contexts(detector); resource_rollback(detector);
    return test_finish("Bulbul");
}
