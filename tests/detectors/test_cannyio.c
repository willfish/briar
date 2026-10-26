/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key1[] = "g7h8ijkl-m9n0-opqr-stuv-wxyz1234abcd";
static const char key2[] = "12345678-90ab-cdef-ghij-klmnopqrstuv";
static size_t fail_finding_after;
typedef struct { const char *const *keys; size_t len; } expected_requests;

/* Target the provider finding allocation, not the combined adapter/Do domain.
 * All fixture captures are 36 non-NUL ASCII bytes, so the string constructor
 * preserves their bytes while the real finding helper handles NULL parts. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 36);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[37]; memcpy(copy, value, 36); copy[36] = 0;
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_cannyio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_cannyio_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 158 && detector->version == 0 && !strcmp(detector->name, "CannyIo"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Canny is a user feedback tool that helps you track and prioritize feature requests. Canny API keys can be used to access and manage feedback boards and other related data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "canny"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_cannyio_init(NULL, &error) != 0 && error);
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
        test_key_result(&results.items[i], 158, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192];
    const struct { const char *format; size_t count; } cases[] = {
        {"canny '%s'", 1}, {"CANNY=%s", 1}, {"CaNnY\t%s", 1}, {"cannyio %s", 1},
        {"prefixcannysuffix %s", 1}, {"canny\r\n%s\t", 1},
        {"%s", 0}, {"can ny %s", 0}, {"canny %.35s", 0},
        {"canny a%s", 0}, {"canny %sa", 0}, {"canny _%s", 0}, {"canny %s_", 0},
        {"canny +%s/", 1}, {"canny %s=", 1}, {"canny %s-extra", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        expect_extraction(detector, input, strlen(input), key1, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "canny", 5); memset(input + 5, ':', gap);
        snprintf(input + 5 + gap, sizeof(input) - 5 - gap, "%s", key1);
        expect_extraction(detector, input, strlen(input), key1, gap == 40 ? 1 : 0);
    }
    char changed[37]; memcpy(changed, key1, sizeof(changed)); changed[0] = 'G';
    snprintf(input, sizeof(input), "CANNY %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key1, sizeof(changed));
    for (size_t i = 0; i < 36; ++i)
        if (changed[i] >= 'a' && changed[i] <= 'z') changed[i] += 'A' - 'a';
    snprintf(input, sizeof(input), "CANNY %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0); /* Keyword CI does not widen captures. */
    memcpy(changed, key1, sizeof(changed)); changed[8] = '_';
    snprintf(input, sizeof(input), "canny %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    const char *nil_uuid = "00000000-0000-0000-0000-000000000000";
    snprintf(input, sizeof(input), "canny %s", nil_uuid);
    expect_extraction(detector, input, strlen(input), nil_uuid, 1); /* No UUID/version/variant/entropy/FP validation. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://canny.io/api/v1/boards/list"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 158);
    CHECK(request->body.data && request->body.len == 43 && !memcmp(request->body.data, "apiKey=", 7));
    CHECK(!memcmp(request->body.data + 7, expected->keys[http->calls - 1], 36));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog cannyio-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* ABI lifecycle, not source's scan-deferred close timing. */
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "canny %s\nCANNY %s\ncanny %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; expected_requests expected = {keys, 3};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (mode ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 158, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 158, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0); /* Only known constructor failures skip candidates. */
    br_results_clear(&results);
}

static void status_and_do_errors(const br_detector *detector)
{
    char input[96], sensitive[192]; snprintf(input, sizeof(input), "canny %s", key2);
    snprintf(sensitive, sizeof(sensitive), "synthetic Do/read error apiKey=%s", key2);
    const char *keys[] = {key2}; expected_requests expected = {keys, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true},
        {299, 0, NULL, true}, {300, 0, NULL, false}, {400, 0, NULL, false}, {401, 0, NULL, false},
        {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false},
        {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {302, 1, "unsupported: redirects for native HTTP POST", false},
        {200, 1, "out of memory constructing HTTP headers", false}, /* Same adapter/Do domain, no text classifier. */
        {200, 1, NULL, false}, {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "cannyio-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        test_key_result(&results.items[0], 158, key2, "key");
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void suppressed_preflight_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "canny %s", key1);
    const char *keys[] = {key1}; expected_requests expected = {keys, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == (mode == 2 ? 0u : 1u));
        test_key_result(&results.items[0], 158, key1, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_finding_after = 1;
    CHECK(br_finding_key_bytes(&probe, 158, (br_slice){(const unsigned char *)key1, 36}, "key") != 0);
    CHECK(!fail_finding_after && !probe.raw.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1); /* Public core failures need not be negative. */

    char input[256]; snprintf(input, sizeof(input), "canny %s\ncanny %s\ncanny %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; expected_requests expected = {keys, 3};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating CannyIo result"));
    CHECK(!fail_finding_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == 0 && !error && results.len == 1 && results.items[0].raw.data == original_raw);
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 158, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 36 && strlen(key2) == 36);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); status_and_do_errors(detector);
    suppressed_preflight_errors(detector); resource_rollback(detector);
    return test_finish("CannyIo");
}
