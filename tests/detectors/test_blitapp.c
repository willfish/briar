/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[40], other_key[40];
static bool fail_503_dup;

/* A positive core setter allocation failure is NOT a suppressed Client.Do error. */
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
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_blitapp_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid BlitApp detector output")); free(error); error = NULL;
    CHECK(!br_blitapp_init(&detector, &error) && detector && !error);
    CHECK(!br_blitapp_init(&again, NULL) && again == detector);
    CHECK(detector->type == 523 && detector->version == 0 && !strcmp(detector->name, "BlitApp"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "BlitApp is a service used for managing applications. BlitApp API keys can be used to access and modify application data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "blitapp"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, bool verified, const char *error)
{
    test_key_result(result, 523, secret, "key");
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
    char input[192], changed[42];
    const char *formats[] = {"blitapp %s", "BLITAPP '%s'", "prefixblitappsuffix=%s", "blitapp\r\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, key);
    }
    extraction_case(detector, "", NULL);
    extraction_case(detector, key, NULL);
    const char *bad[] = {"blitapp _%s", "blitapp %s_", "blitapp %sx", "blitapp %.38s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[16] = '*';
    snprintf(input, sizeof(input), "blitapp %s", changed);
    extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[38] = '-';
    snprintf(input, sizeof(input), "blitapp %s", changed);
    extraction_case(detector, input, NULL); /* Final non-word '-' has no boundary before EOF. */
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "blitapp %s", changed);
    extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "blitappX%s ", changed);
    extraction_case(detector, input, changed); /* Exact source word boundary before '-'. */
    memset(changed, '_', 39); changed[39] = '\0';
    snprintf(input, sizeof(input), "blitapp %s", changed);
    extraction_case(detector, input, changed); /* '_' is a word byte; no entropy filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "blitapp", 7); memset(input + 7, '.', gap);
        snprintf(input + 7 + gap, sizeof(input) - 7 - gap, "%s", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
}

typedef struct { const char *keys[3]; size_t len; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://blitapp.com/api/apps/all"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 523);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* API-Key + default UA only; no Accept/Content-Type. */
    CHECK(!strcmp(request->headers[0].name, "API-Key") && !strcmp(request->headers[0].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog blitapp-test"));
}

static void occurrences(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "blitapp %s\nBLITAPP %s\nblitapp %s", key, other_key, key);
    expected_requests expected = {{key, other_key, key}, 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "blitapp-test"};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], verify, NULL);
        br_results_clear(&results);
    }
    http = (test_http){.response = {.status = 200}, .send_rc = 1, .send_error = "lookup: no such host", .inspect = inspect_request, .user = &expected};
    for (int scan = 0; scan < 2; ++scan) {
        http.calls = http.releases = 0;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], false, NULL);
        br_results_clear(&results);
    } /* Every duplicate remains, with no DNS cache, suppression or success break. */
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    char input[64]; snprintf(input, sizeof(input), "blitapp %s", key);
    expected_requests expected = {{key}, 1};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "blitapp-test"};
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
        verify_case(detector, &http, false, NULL); /* ALL Client.Do errors suppressed, never status fallback. */
    }
    char echoed[192]; snprintf(echoed, sizeof(echoed), "candidate=%s again=%s", key, key);
    test_http http = {.send_rc = 1, .send_error = echoed};
    verify_case(detector, &http, false, NULL); /* Discard cause entirely, not an invented redaction. */
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "blitapp %s", key);
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
    }
    br_scan_ctx missing = {0};
    br_results results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1);
        check_result(&results.items[0], key, false, NULL); /* Includes wrapper-level cancellation/deadline errors. */
        br_results_clear(&results);
    }
    expected_requests expected = {{key}, 1};
    http = (test_http){.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "blitapp-test"};
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
    test_secret(key, 39, 0); key[0] = 'A'; key[14] = '-'; key[25] = '_'; key[38] = 'Z';
    test_secret(other_key, 39, 13); other_key[0] = 'Q'; other_key[8] = '_'; other_key[20] = '-'; other_key[38] = 'Y';
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences(detector);
    verification(detector);
    context_and_resource(detector);
    return test_finish("BlitApp");
}
