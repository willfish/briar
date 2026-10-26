/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char first_key[114], second_key[114], third_key[114];
static bool fail_status_copy;
typedef struct { const char *const *keys; size_t len; bool fail_second; } expected_requests;

/* Force the real core setter's +1 resource return for one status-error copy. */
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

static void make_key(char *out, size_t first, size_t tail, size_t shift)
{
    static const char hex[] = "abcdef0123456789";
    for (size_t i = 0; i < first; ++i) out[i] = hex[(i + shift) % 16];
    out[first] = '-';
    for (size_t i = 0; i < tail; ++i) out[first + 1 + i] = hex[(i + shift + 7) % 16];
    out[first + 1 + tail] = 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_budibase_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_budibase_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 953 && detector->version == 0 && !strcmp(detector->name, "Budibase"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Budibase is a low-code platform for creating internal tools. Budibase API keys can be used to access and modify applications and data within the platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "budibase"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_budibase_init(NULL, &error) != 0 && error);
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
        test_key_result(&results.items[i], 953, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[116];
    const struct { const char *format; size_t count; } cases[] = {
        {"budibase '%s'", 1}, {"BUDIBASE=%s", 1}, {"BuDiBaSe\t%s", 1},
        {"prefixbudibasesuffix %s", 1}, {"budibase\r\n%s\t", 1},
        {"%s", 0}, {"budi base %s", 0}, {"budibase a%s", 0},
        {"budibase _%s", 0}, {"budibase %s_", 0}, {"budibase %sZ", 0},
        {"budibase +%s/", 1}, {"budibase %s=", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, first_key);
        expect_extraction(detector, input, strlen(input), first_key, cases[i].count);
    }
    for (size_t tail = 77; tail <= 81; ++tail) {
        make_key(changed, 32, tail, 0);
        snprintf(input, sizeof(input), "budibase %s", changed);
        expect_extraction(detector, input, strlen(input), changed, tail >= 78 && tail <= 80 ? 1 : 0);
    }
    for (size_t first = 31; first <= 33; first += 2) {
        make_key(changed, first, 78, 0);
        snprintf(input, sizeof(input), "budibase %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "budibase", 8); memset(input + 8, ':', gap);
        snprintf(input + 8 + gap, sizeof(input) - 8 - gap, "%s", first_key);
        expect_extraction(detector, input, strlen(input), first_key, gap == 40 ? 1 : 0);
    }
    memcpy(changed, first_key, strlen(first_key) + 1); changed[0] = 'A';
    snprintf(input, sizeof(input), "BUDIBASE %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, first_key, strlen(first_key) + 1); changed[60] = 'F';
    snprintf(input, sizeof(input), "BUDIBASE %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0); /* CI only on provider, not either hex group. */
    memcpy(changed, first_key, strlen(first_key) + 1); changed[60] = 'g';
    snprintf(input, sizeof(input), "budibase %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, first_key, strlen(first_key) + 1); changed[32] = '_';
    snprintf(input, sizeof(input), "budibase %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(changed, '0', 111); changed[32] = '-'; changed[111] = 0;
    snprintf(input, sizeof(input), "budibase %s", changed);
    expect_extraction(detector, input, strlen(input), changed, 1); /* No local entropy/FP filter. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://budibase.app/api/public/v1/applications/search"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 953);
    static const char body[] = "{\"name\":\"qwerty\"}";
    CHECK(request->body.data && request->body.len == sizeof(body) - 1 && !memcmp(request->body.data, body, sizeof(body) - 1));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json") && !strcmp(request->headers[1].name, "x-budibase-api-key"));
    CHECK(!strcmp(request->headers[1].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog budibase-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* No logical Accept, Authorization or Content-Length header. */
    if (expected->fail_second && http->calls == 2) {
        http->response.status = 429;
        fail_status_copy = true;
    }
}

static void occurrences(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "budibase %s\nBUDIBASE %s\nbudibase %s", first_key, third_key, first_key);
    const char *keys[] = {first_key, third_key, first_key}; expected_requests expected = {keys, 3, false};
    for (int mode = 0; mode < 3; ++mode) {
        const char *cause = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL;
        test_http http = {.response = {.status = 200}, .send_rc = mode == 2 ? 1 : 0, .send_error = cause,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (mode ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 953, keys[i], "key");
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
            test_key_result(&results.items[i], 953, keys[i], "key");
            CHECK(!results.items[i].verified);
            if (verify) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void verification(const br_detector *detector)
{
    char input[160], unredacted[384]; snprintf(input, sizeof(input), "budibase %s", second_key);
    snprintf(unredacted, sizeof(unredacted), "POST https://budibase.app/api/public/v1/applications/search key=%s again=%s", second_key, second_key);
    const char *keys[] = {second_key}; expected_requests expected = {keys, 1, false};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL}, {401, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {403, 0, NULL, false, "unexpected status code: 403"},
        {429, 0, NULL, false, "unexpected status code: 429"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "lookup synthetic.invalid: no such host", false, "lookup synthetic.invalid: no such host"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, 1, unredacted, false, unredacted},
        {200, 1, NULL, false, "HTTP transport failed"},
        {200, 0, NULL, true, NULL},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = unredacted},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "budibase-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 953, second_key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        if (cases[i].send_error == unredacted) {
            CHECK(strstr(results.items[0].verification_error, second_key));
            CHECK(!strstr(results.items[0].verification_error, "[REDACTED]"));
        }
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void contexts(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "budibase %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1, false};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        test_key_result(&results.items[0], 953, first_key, "key");
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
    char input[512]; snprintf(input, sizeof(input), "budibase %s\nbudibase %s\nbudibase %s", first_key, second_key, third_key);
    const char *keys[] = {first_key, second_key, third_key}; expected_requests expected = {keys, 3, true};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
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
    for (size_t i = 0; i < 3; ++i) { test_key_result(&results.items[i], 953, keys[i], "key"); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    make_key(first_key, 32, 78, 0); make_key(second_key, 32, 79, 3); make_key(third_key, 32, 80, 6);
    CHECK(strlen(first_key) == 111 && strlen(second_key) == 112 && strlen(third_key) == 113);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification(detector); contexts(detector); resource_rollback(detector);
    return test_finish("Budibase");
}
