/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char token[52], other_token[52];
static bool fail_503_dup;
static const char status_503[] = "unexpected HTTP response status 503";

/* One named core-setter allocation failure, without a production hook. */
char *strdup(const char *value)
{
    if (fail_503_dup && !strcmp(value, status_503)) { fail_503_dup = false; return NULL; }
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(token) == 51 && strlen(other_token) == 51);
    CHECK(br_braintrust_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Braintrust detector output")); free(error); error = NULL;
    CHECK(!br_braintrust_init(&detector, &error) && detector && !error);
    CHECK(!br_braintrust_init(&again, NULL) && again == detector);
    CHECK(detector->type == 1053 && detector->version == 0 && !strcmp(detector->name, "BrainTrustApiKey"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Braintrust is an AI evaluation and observability platform. Braintrust API keys can be used to access evaluation, observability, and AI development resources within the Braintrust platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "braintrust"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, bool verified, const char *error)
{
    /* Reuse ordinary key-only invariants; separately check this provider's
     * unconditional, owned display string rather than weakening shared tests. */
    br_result view = *result;
    view.redacted = NULL;
    test_key_result(&view, 1053, secret, "token");
    CHECK(result->redacted && strlen(result->redacted) == 11);
    CHECK(!memcmp(result->redacted, secret, 8) && !strcmp(result->redacted + 8, "..."));
    CHECK(result->redacted != (char *)result->raw.data && result->redacted[11] == '\0');
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
    char input[192], changed[54];
    /* Direct scanner matches WITHOUT its engine dispatch keyword. No engine,
     * registry feature policy or CLI behavior is asserted by these calls. */
    const char *formats[] = {"%s", "unrelated_api='%s'", "%s braintrust", "BRAINTRUST %s", "-%s-"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], token);
        extraction_case(detector, input, token);
    }
    memcpy(input, "braintrust", 10); memset(input + 10, '.', 96);
    snprintf(input + 106, sizeof(input) - 106, "%s", token);
    extraction_case(detector, input, token); /* No 40-byte extraction-prefix limit. */
    extraction_case(detector, "", NULL);
    extraction_case(detector, "braintrust", NULL);
    const char *bad[] = {"x%s", "_%s", "%s_", "%sA", "%.50s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], token);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, token, sizeof(token)); changed[0] = 'S';
    extraction_case(detector, changed, NULL);
    memcpy(changed, token, sizeof(token)); changed[1] = 'K';
    extraction_case(detector, changed, NULL);
    memcpy(changed, token, sizeof(token)); changed[27] = '_';
    extraction_case(detector, changed, NULL);
    changed[27] = '-'; extraction_case(detector, changed, NULL);
    memcpy(changed, "sk-", 3); memset(changed + 3, 'a', 48); changed[51] = '\0';
    extraction_case(detector, changed, changed); /* No entropy filtering. */
}

typedef struct { const char *tokens[2]; size_t len; uint32_t timeout_limit; bool second_503; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.braintrust.dev/v1/project?limit=1"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1053);
    if (expected->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    else CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* Bearer + default UA only; no Content-Type or Accept. */
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 58 && !memcmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, expected->tokens[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    if (expected->second_503) http->response.status = http->calls == 1 ? 200 : 503;
}

static void uniqueness(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", token, other_token, token, other_token);
    expected_requests expected = {.tokens = {token, other_token}, .len = 2};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 2 && http.calls == (verify ? 2 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], expected.tokens[i], verify, NULL);
        CHECK(results.items[0].redacted != results.items[1].redacted);
        br_results_clear(&results);
    }
    http = (test_http){.send_rc = 1, .send_error = "no such host", .inspect = inspect_request, .user = &expected};
    for (int retry = 0; retry < 2; ++retry) {
        http.calls = http.releases = 0;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], expected.tokens[i], false, "no such host");
        br_results_clear(&results);
    }
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    expected_requests expected = {.tokens = {token}, .len = 1};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, token, strlen(token)); /* No dispatch keyword. */
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_result(&results.items[0], token, verified, error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const int statuses[] = {200, 403, 401, 201, 204, 302, 400, 500};
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        bool verified = statuses[i] == 200 || statuses[i] == 403;
        char error[80]; snprintf(error, sizeof(error), "unexpected HTTP response status %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read/drain error"}};
        verify_case(detector, &http, verified, verified || statuses[i] == 401 ? NULL : error);
    }
    const char *errors[] = {"no such host", "context canceled", "context deadline exceeded", "unsupported: SANE redirect policy", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = errors[i]};
        verify_case(detector, &http, false, errors[i] ? errors[i] : "HTTP transport failed");
    }
    char echoed[256], redacted[256];
    snprintf(echoed, sizeof(echoed), "token=%s repeat=%s prefix=%.8s other=%s", token, token, token, other_token);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] repeat=[REDACTED] prefix=%.8s other=%s", token, other_token);
    test_http http = {.send_rc = -1, .send_error = echoed};
    verify_case(detector, &http, false, redacted); /* Only full current-token occurrences are sanitized. */
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    br_results results = test_scan(detector, NULL, false, token, strlen(token));
    CHECK(results.len == 1); check_result(&results.items[0], token, false, NULL); br_results_clear(&results);
    results = test_scan(detector, NULL, true, token, strlen(token));
    CHECK(results.len == 1); check_result(&results.items[0], token, false, "net/http: nil Context"); br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, token, strlen(token));
    CHECK(results.len == 1); check_result(&results.items[0], token, false, "HTTP transport not installed"); br_results_clear(&results);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, false, token, strlen(token));
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(&results.items[0], token, false, NULL); br_results_clear(&results);
        results = test_scan(detector, &ctx, true, token, strlen(token));
        CHECK(results.len == 1 && !http.calls && http.releases == 1);
        check_result(&results.items[0], token, false, deadline ? "context deadline exceeded" : "context canceled");
        br_results_clear(&results);
    }
    expected_requests expected = {.tokens = {token}, .len = 1, .timeout_limit = 2000};
    http = (test_http){.response = {.status = 403}, .inspect = inspect_request, .user = &expected};
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    results = test_scan(detector, &ctx, true, token, strlen(token));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    check_result(&results.items[0], token, true, NULL); br_results_clear(&results);

    char input[128]; snprintf(input, sizeof(input), "%s %s", token, other_token);
    expected = (expected_requests){.tokens = {token, other_token}, .len = 2, .second_503 = true};
    http = (test_http){.inspect = inspect_request, .user = &expected}; ctx.deadline_monotonic_ms = 0;
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data;
    fail_503_dup = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_503_dup && rc == -1 && error && !strcmp(error, "out of memory recording Braintrust verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].detector_type == 777 && results.items[0].raw.data == saved);
    CHECK(results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], token, true, NULL);
    check_result(&results.items[1], other_token, false, status_503);
    br_results_clear(&results);
}

int main(void)
{
    memcpy(token, "sk-", 3); test_secret(token + 3, 48, 0); token[3] = 'A'; token[4] = 'Z';
    memcpy(other_token, "sk-", 3); test_secret(other_token + 3, 48, 7); other_token[3] = 'Q';
    const br_detector *detector = descriptor();
    extraction(detector);
    uniqueness(detector);
    verification(detector);
    context_and_resource(detector);
    return test_finish("Braintrust");
}
