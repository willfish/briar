/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char key[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char other_key[] = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
static bool fail_503_dup;

char *strdup(const char *value)
{
    if (fail_503_dup && !strcmp(value, "unexpected status code: 503")) {
        fail_503_dup = false; return NULL;
    }
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 64 && strlen(other_key) == 64);
    CHECK(br_boostnote_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid BoostNote detector output")); free(error); error = NULL;
    CHECK(!br_boostnote_init(&detector, &error) && detector && !error);
    CHECK(!br_boostnote_init(&again, NULL) && again == detector);
    CHECK(detector->type == 707 && detector->version == 0 && !strcmp(detector->name, "BoostNote"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "BoostNote is a note-taking application. The secret detected here is likely an API key or token used to access BoostNote services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "boostnote"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, bool verified, const char *error)
{
    test_key_result(result, 707, secret, "key");
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1 : 0) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[67];
    const char *formats[] = {"boostnote %s", "BOOSTNOTE '%s'", "prefixboostnotesuffix=%s", "boostnote\r\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, key);
    }
    extraction_case(detector, "", NULL);
    extraction_case(detector, key, NULL);
    const char *bad[] = {"boostnote _%s", "boostnote %s_", "boostnote %sx", "boostnote %.63s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[20] = 'A';
    snprintf(input, sizeof(input), "BOOSTNOTE %s", changed);
    extraction_case(detector, input, NULL); /* Keyword CI is scoped, capture remains lowercase. */
    changed[20] = 'g';
    snprintf(input, sizeof(input), "boostnote %s", changed);
    extraction_case(detector, input, NULL); /* HEX only, not general lowercase alnum. */
    changed[20] = '-';
    snprintf(input, sizeof(input), "boostnote %s", changed);
    extraction_case(detector, input, NULL);
    memset(changed, 'a', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "boostnote %s", changed);
    extraction_case(detector, input, changed); /* No entropy filter. */
    memcpy(changed, key, 64); memcpy(changed + 64, "==", 3);
    snprintf(input, sizeof(input), "boostnote %s", changed);
    extraction_case(detector, input, key);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "boostnote", 9); memset(input + 9, '.', gap);
        snprintf(input + 9 + gap, sizeof(input) - 9 - gap, "%s", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
}

typedef struct { const char *keys[3]; size_t len; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://boostnote.io/api/docs"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 707);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* Bearer Authorization + default UA only. */
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 71 && !memcmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog boostnote-test"));
}

static void occurrences(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "boostnote %s\nBOOSTNOTE %s\nboostnote %s", key, other_key, key);
    expected_requests expected = {{key, other_key, key}, 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "boostnote-test"};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], verify, NULL);
        br_results_clear(&results);
    }
    http = (test_http){.send_rc = 1, .send_error = "no such host", .inspect = inspect_request, .user = &expected};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], false, "no such host");
    br_results_clear(&results);
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    char input[80]; snprintf(input, sizeof(input), "boostnote %s", key);
    expected_requests expected = {{key}, 1};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "boostnote-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_result(&results.items[0], key, verified, error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const int statuses[] = {200, 401, 201, 204, 403, 302, 500};
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80]; snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read/drain failure"}};
        verify_case(detector, &http, i == 0, i < 2 ? NULL : error);
    }
    const char *errors[] = {"no such host", "context canceled", "context deadline exceeded", "unsupported: SANE redirect policy", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = errors[i]};
        verify_case(detector, &http, false, errors[i] ? errors[i] : "HTTP transport failed");
    }
    char echoed[384]; snprintf(echoed, sizeof(echoed), "key=%s again=%s other=%s", key, key, other_key);
    test_http http = {.send_rc = 1, .send_error = echoed};
    verify_case(detector, &http, false, echoed); /* ZERO source secret arguments: keep echoed key UNREDACTED. */
    http.send_error = "no such host";
    verify_case(detector, &http, false, http.send_error); /* No DNS cache/suppression. */
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "boostnote %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, "net/http: nil Context"); br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, "HTTP transport not installed"); br_results_clear(&results);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1);
        check_result(&results.items[0], key, false, deadline ? "context deadline exceeded" : "context canceled");
        br_results_clear(&results);
    }
    expected_requests expected = {{key}, 1};
    http = (test_http){.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "boostnote-test"};
    char *error = NULL;
    fail_503_dup = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!fail_503_dup && !results.len && http.calls == 1 && http.releases == 1);
    free(error); br_results_clear(&results);
    http = (test_http){.response = {.status = 503}};
    verify_case(detector, &http, false, "unexpected status code: 503");
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences(detector);
    verification(detector);
    context_and_resource(detector);
    return test_finish("BoostNote");
}
