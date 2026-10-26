/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

#define SLICE(text) {(const unsigned char *)(text), sizeof(text) - 1}
static char key[35], other_key[35];
static bool fail_503_dup;
static const char status_503[] = "unexpected status code: 503";
static const char url_prefix[] = "https://api.bscscan.com/api?module=account&action=balance&address=0x70F657164e5b75689b64B7fd1fA275F334f28e18&apikey=";

/* One precise core-setter allocation failure, with no production hook. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 34 && strlen(other_key) == 34);
    CHECK(br_bscscan_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid BscScan detector output")); free(error); error = NULL;
    CHECK(!br_bscscan_init(&detector, &error) && detector && !error);
    CHECK(!br_bscscan_init(&again, NULL) && again == detector);
    CHECK(detector->type == 910 && detector->version == 0 && !strcmp(detector->name, "BscScan"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "BscScan is a block explorer and analytics platform for Binance Smart Chain. BscScan API keys can be used to access data from the Binance Smart Chain blockchain."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bscscan"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *secret, bool verified, const char *error)
{
    test_key_result(result, 910, secret, "key");
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
    char input[192], changed[35];
    const char *formats[] = {"bscscan %s", "BSCSCAN '%s'", "prefixbScScAnSuffix=%s", "bscscan\r\n%s", "bscscan \t(%s)==\r\n"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, key);
    }
    extraction_case(detector, "", NULL);
    extraction_case(detector, key, NULL);
    const char *bad[] = {"bscscan _%s", "bscscan %s_", "bscscan X%s", "bscscan %sA", "bscscan %.33s"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        snprintf(input, sizeof(input), bad[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[20] = 'a';
    snprintf(input, sizeof(input), "BSCSCAN %s", changed);
    extraction_case(detector, input, NULL); /* CI keyword MUST NOT widen uppercase-only capture. */
    changed[20] = '-'; snprintf(input, sizeof(input), "bscscan %s", changed);
    extraction_case(detector, input, NULL);
    memset(changed, 'A', 34); changed[34] = '\0';
    snprintf(input, sizeof(input), "bscscan %s", changed);
    extraction_case(detector, input, changed); /* No entropy filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "bscscan", 7); memset(input + 7, '.', gap);
        snprintf(input + 7 + gap, sizeof(input) - 7 - gap, "%s", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "bscscan %s %s", key, key);
    extraction_case(detector, input, key); /* FindAll consumes the shared keyword with the first match. */
}

typedef struct { const char *keys[3]; size_t len; uint32_t timeout_limit; bool second_503; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    char url[192]; snprintf(url, sizeof(url), "%s%s", url_prefix, expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 910);
    if (expected->timeout_limit) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->timeout_limit);
    else CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1); /* Default UA only: no provider, Authorization, Accept or Content-Type headers. */
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog"));
    if (expected->second_503) http->response.status = http->calls == 1 ? 200 : 503;
}

static void occurrences(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "bscscan %s\nBSCSCAN %s\nbscscan %s", key, other_key, key);
    expected_requests expected = {.keys = {key, other_key, key}, .len = 3};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], verify, NULL);
        br_results_clear(&results);
    }
    http = (test_http){.send_rc = 1, .send_error = "no such host", .inspect = inspect_request, .user = &expected};
    for (int retry = 0; retry < 2; ++retry) {
        http.calls = http.releases = 0;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], false, "no such host");
        br_results_clear(&results);
    }
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    char input[64]; snprintf(input, sizeof(input), "bscscan %s", key);
    expected_requests expected = {.keys = {key}, .len = 1};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_result(&results.items[0], key, verified, error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const struct { br_slice body; bool verified; } bodies[] = {
        {{NULL, 0}, true}, {SLICE("arbitrary non-JSON error text"), true},
        {SLICE("NOTOK"), false}, {SLICE("prefixNOTOKsuffix"), false}, {SLICE("notok NoToK"), true},
        {SLICE("\xff\0NOTOK"), false}, {SLICE("\xff\0arbitrary\x80"), true}, {SLICE("N\0OTOK"), true},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = bodies[i].body}};
        verify_case(detector, &http, bodies[i].verified, NULL);
    }
    const int statuses[] = {401, 201, 204, 302, 403, 404, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80]; snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = SLICE("NOTOK"), .body_error = "ignored outside 200"}};
        verify_case(detector, &http, false, statuses[i] == 401 ? NULL : error);
    }
    char echoed[256]; snprintf(echoed, sizeof(echoed), "key=%s url=%s%s", key, url_prefix, key);
    test_http http = {.response = {.status = 200, .body = SLICE("NOTOK"), .body_error = echoed}};
    verify_case(detector, &http, false, echoed); /* Read error precedes marker test; ZERO secret arguments. */
    http.response.body = (br_slice){NULL, 0};
    verify_case(detector, &http, false, echoed); /* Also precedes empty-body success. */
    http = (test_http){.response = {.status = 200}, .send_rc = -1, .send_error = echoed};
    verify_case(detector, &http, false, echoed); /* Echoed key AND query URL remain unredacted. */
    const char *errors[] = {"no such host", "context canceled", "context deadline exceeded", "unsupported: SANE redirect policy", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        http = (test_http){.response = {.status = 200}, .send_rc = 1, .send_error = errors[i]};
        verify_case(detector, &http, false, errors[i] ? errors[i] : "HTTP transport failed");
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "bscscan %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, "net/http: nil Context"); br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, "HTTP transport not installed"); br_results_clear(&results);
    test_http http = {.response = {.status = 200}}; br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1);
        check_result(&results.items[0], key, false, deadline ? "context deadline exceeded" : "context canceled");
        br_results_clear(&results);
    }
    expected_requests expected = {.keys = {key}, .len = 1, .timeout_limit = 2000};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    check_result(&results.items[0], key, true, NULL); br_results_clear(&results);

    snprintf(input, sizeof(input), "bscscan %s\nbscscan %s", key, other_key);
    expected = (expected_requests){.keys = {key, other_key}, .len = 2, .second_503 = true};
    http = (test_http){.inspect = inspect_request, .user = &expected}; ctx.deadline_monotonic_ms = 0;
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data;
    fail_503_dup = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_503_dup && rc == -1 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].detector_type == 777 && results.items[0].raw.data == saved);
    CHECK(results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], key, true, NULL);
    check_result(&results.items[1], other_key, false, status_503);
    br_results_clear(&results);
}

int main(void)
{
    const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (size_t i = 0; i < 34; ++i) { key[i] = alphabet[i]; other_key[i] = alphabet[(i + 11) % 36]; }
    key[34] = other_key[34] = '\0';
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences(detector);
    verification(detector);
    context_and_resource(detector);
    return test_finish("BscScan");
}
