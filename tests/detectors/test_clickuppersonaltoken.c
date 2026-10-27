/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static const char key7[] = "pk_0000001_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
static const char key8[] = "pk_12345678_ZYXWVUTSRQPONMLKJIHGFEDCBA987654";
static const char key9[] = "pk_123456789_0123456789ABCDEFGHIJKLMNOPQRSTUV";
static const char status_503[] = "unexpected status code 503";
static bool fail_status_copy;

/* One precise core-setter +1 failure, without a production hook. */
char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key7) == 43 && strlen(key8) == 44 && strlen(key9) == 45);
    CHECK(br_clickuppersonaltoken_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid ClickupPersonalToken detector output")); free(error); error = NULL;
    CHECK(!br_clickuppersonaltoken_init(&detector, &error) && detector && !error);
    CHECK(!br_clickuppersonaltoken_init(&again, NULL) && again == detector);
    CHECK(detector->type == 366 && detector->version == 0 && !strcmp(detector->name, "ClickupPersonalToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "ClickUp is a project management tool. Personal tokens can be used to access and modify data within ClickUp on behalf of a user."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "clickup"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *token, bool verified, const char *error)
{
    test_key_result(result, 366, token, "key");
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
    char input[192], changed[46];
    const char *tokens[] = {key7, key8, key9};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(input, sizeof(input), "CLICKUP '%s'", tokens[i]);
        extraction_case(detector, input, tokens[i]); /* Exact 7/8/9 digits; leading zeros and G-Z allowed. */
    }
    const char *formats[] = {"prefixClIcKuPsuffix=%s", "clickup\r\n%s", "clickup \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key7);
        extraction_case(detector, input, key7);
    }
    extraction_case(detector, "", NULL); extraction_case(detector, key7, NULL);
    const char *bad[] = {"clickup _%s", "clickup %s_", "clickup x%s", "clickup %sA", "clickup %.42s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key7); extraction_case(detector, input, NULL);
    }
    memcpy(changed, key7, sizeof(key7)); changed[0] = 'P';
    snprintf(input, sizeof(input), "CLICKUP %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key7, sizeof(key7)); changed[1] = 'K';
    snprintf(input, sizeof(input), "clickup %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key7, sizeof(key7)); changed[5] = 'X';
    snprintf(input, sizeof(input), "clickup %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key7, sizeof(key7)); changed[11] = 'a';
    snprintf(input, sizeof(input), "CLICKUP %s", changed); extraction_case(detector, input, NULL); /* Prefix CI MUST NOT widen suffix case. */
    snprintf(input, sizeof(input), "clickup pk_123456_%s", key7 + 11); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "clickup pk_1234567890_%s", key7 + 11); extraction_case(detector, input, NULL);
    memcpy(changed, "pk_0000000_", 11); memset(changed + 11, 'Z', 32); changed[43] = '\0';
    snprintf(input, sizeof(input), "clickup %s", changed); extraction_case(detector, input, changed); /* No entropy/hex filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "clickup", 7); memset(input + 7, '.', gap);
        snprintf(input + 7 + gap, sizeof(input) - 7 - gap, "%s", key7);
        extraction_case(detector, input, gap == 40 ? key7 : NULL);
    }
}

typedef struct {
    const char *tokens[3]; size_t len; uint32_t timeout_limit;
    bool second_503, mutate_error, mutated; char *returned_error;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.clickup.com/api/v2/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 366);
    if (expected->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    else CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* Literal token Authorization + shared UA; no Type/Accept/manual Content-Length. */
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, expected->tokens[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    if (expected->second_503) http->response.status = http->calls == 1 ? 200 : 503;
}

static int send_response(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                          br_http_response *response, char **error)
{
    test_http *http = user; expected_requests *expected = http->user;
    int rc = test_http_send(user, ctx, request, response, error);
    expected->returned_error = *error;
    return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_requests *expected = http->user;
    if (expected->mutate_error && expected->returned_error) {
        memset(expected->returned_error, '!', strlen(expected->returned_error)); expected->mutated = true;
    }
    expected->returned_error = NULL;
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, send_response, release_response}; }

static void uniqueness(const br_detector *detector)
{
    char input[320]; snprintf(input, sizeof(input), "clickup %s\nCLICKUP %s\nclickup %s\nclickup %s\nclickup %s", key7, key8, key7, key9, key8);
    expected_requests expected = {.tokens = {key7, key8, key9}, .len = 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.tokens[i], verify, NULL);
        br_results_clear(&results);
    }
    http = (test_http){.send_rc = 1, .send_error = "no such host", .inspect = inspect_request, .user = &expected};
    for (int retry = 0; retry < 2; ++retry) {
        http.calls = http.releases = 0;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.tokens[i], false, "no such host");
        br_results_clear(&results);
    }
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error, bool mutate)
{
    char input[64]; snprintf(input, sizeof(input), "clickup %s", key7);
    expected_requests expected = {.tokens = {key7}, .len = 1, .mutate_error = mutate};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = transport_for(http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    CHECK(expected.mutated == mutate);
    check_result(&results.items[0], key7, verified, error); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const int statuses[] = {200, 401, 201, 204, 299, 302, 403, 503};
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80]; snprintf(error, sizeof(error), "unexpected status code %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read/drain/close error"}};
        verify_case(detector, &http, statuses[i] == 200, i < 2 ? NULL : error, false);
    }
    char echoed[320], redacted[256];
    snprintf(echoed, sizeof(echoed), "token=%s twice=%s prefix=%.10s suffix=%s other=%s", key7, key7, key7, key7 + 11, key8);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] twice=[REDACTED] prefix=%.10s suffix=%s other=%s", key7, key7 + 11, key8);
    test_http http = {.response = {.status = 200}, .send_rc = -1, .send_error = echoed};
    verify_case(detector, &http, false, redacted, true); /* Full current token ONLY; copy/redact BEFORE release mutation. */
    const char *errors[] = {"no such host", "context canceled", "context deadline exceeded", "unsupported: native SANE policy", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        http = (test_http){.response = {.status = 200}, .send_rc = 1, .send_error = errors[i]};
        verify_case(detector, &http, false, errors[i] ? errors[i] : "HTTP transport failed", false);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "clickup %s", key7);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key7, false, NULL); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key7, false, "net/http: nil Context"); br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key7, false, "HTTP transport not installed"); br_results_clear(&results);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(&results.items[0], key7, false, NULL); br_results_clear(&results);
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1);
        check_result(&results.items[0], key7, false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    expected_requests expected = {.tokens = {key7}, .len = 1, .timeout_limit = 2000};
    http = (test_http){.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    check_result(&results.items[0], key7, true, NULL); br_results_clear(&results);

    br_result probe = {0}; fail_status_copy = true;
    CHECK(br_result_set_verification_error(&probe, status_503, NULL, 0) == 1 && !fail_status_copy && !probe.verification_error); br_result_clear(&probe);
    snprintf(input, sizeof(input), "clickup %s\nclickup %s", key7, key8);
    expected = (expected_requests){.tokens = {key7, key8}, .len = 2, .second_503 = true};
    http = (test_http){.inspect = inspect_request, .user = &expected}; ctx.deadline_monotonic_ms = 0;
    br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].detector_type == 777 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key7, true, NULL); check_result(&results.items[1], key8, false, status_503);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); uniqueness(detector); verification(detector); context_and_resource(detector);
    return test_finish("ClickupPersonalToken");
}
