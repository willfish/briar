/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char first_key[40], dash_key[40];
typedef struct { const char *const *keys; size_t len; } expected_requests;

/* Target only the 401 verification-error copy to exercise the real setter's
 * positive +1 allocation failure without changing shared code or transport. */
static bool fail_status_copy;
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, "unexpected status code: 401")) {
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
    CHECK(br_blogger_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_blogger_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 302 && detector->version == 0 && !strcmp(detector->name, "Blogger"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Blogger API keys can be used to access and manage blogs on the Blogger platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "blogger"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_blogger_init(NULL, &error) != 0 && error);
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
        test_key_result(&results.items[i], 302, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192];
    const struct { const char *format; size_t count; } cases[] = {
        {"blogger '%s'", 1},
        {"BLOGGER=%s", 1},
        {"prefixbloggersuffix %s", 1},
        {"blogger\r\n%s\t", 1},
        {"%s", 0},
        {"blog ger %s", 0},
        {"blogger %.38s", 0},
        {"blogger _%s", 0},
        {"blogger a%s", 0},
        {"blogger +%s/", 1},
        {"blogger %s_", 1},
        {"blogger %sABCDEFGHIJKLMNOPQRSTUVWXYZ_more", 1},
        {"blogger %s-", 1},
        {"blogger %s=ignored", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, first_key);
        expect_extraction(detector, input, strlen(input), first_key, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "blogger", 7); memset(input + 7, '.', gap);
        snprintf(input + 7 + gap, sizeof(input) - 7 - gap, "%s", first_key);
        expect_extraction(detector, input, strlen(input), first_key, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "blogger %s", dash_key);
    expect_extraction(detector, input, strlen(input), dash_key, 1); /* No ending boundary after '-'. */
    const size_t positions[] = {0, 1, 4};
    const char lower[] = {'a', 'i', 's'};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        char changed[40]; memcpy(changed, first_key, sizeof(changed)); changed[positions[i]] = lower[i];
        snprintf(input, sizeof(input), "BLOGGER %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0); /* AIzaSy stays case-sensitive. */
    }
    char changed[40]; memcpy(changed, first_key, sizeof(changed)); changed[12] = '+';
    snprintf(input, sizeof(input), "blogger %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, first_key, sizeof(changed)); memset(changed + 6, 'A', 33);
    snprintf(input, sizeof(input), "blogger %s", changed);
    expect_extraction(detector, input, strlen(input), changed, 1); /* No local entropy/FP filtering. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    char url[160];
    snprintf(url, sizeof(url), "https://www.googleapis.com/blogger/v3/blogs/2399953?key=%s", expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 302);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, ctx->user_agent ? "TruffleHog blogger-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1);
}

static void occurrences(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "blogger %s_CONTINUED\nBLOGGER %s\nblogger %s", first_key, dash_key, first_key);
    const char *keys[] = {first_key, dash_key, first_key};
    expected_requests expected = {keys, sizeof(keys) / sizeof(keys[0])};
    for (int mode = 0; mode < 3; ++mode) {
        bool verify = mode != 0;
        const char *dns_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL;
        test_http http = {.response = {.status = 200}, .send_rc = mode == 2 ? 1 : 0, .send_error = dns_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 302, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1));
            if (dns_error) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, dns_error));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 302, keys[i], "key");
        CHECK(!results.items[i].verified && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
    }
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 302, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[96], unredacted[256];
    snprintf(input, sizeof(input), "blogger %s", dash_key);
    snprintf(unredacted, sizeof(unredacted), "GET https://www.googleapis.com/blogger/v3/blogs/2399953?key=%s failed again=%s", dash_key, dash_key);
    const char *keys[] = {dash_key}; expected_requests expected = {keys, 1};
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {400, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {401, 0, NULL, false, "unexpected status code: 401"},
        {201, 0, NULL, false, "unexpected status code: 201"},
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
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "blogger-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0]; test_key_result(result, 302, dash_key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) CHECK(result->verification_error && !strcmp(result->verification_error, cases[i].error));
        else CHECK(!result->verification_error);
        if (cases[i].send_error == unredacted) {
            CHECK(strstr(result->verification_error, dash_key));
            CHECK(!strstr(result->verification_error, "[REDACTED]"));
        }
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "blogger %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        test_key_result(&results.items[0], 302, first_key, "key");
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

static void resource_returns(const br_detector *detector)
{
    br_result probe = {0};
    fail_status_copy = true;
    CHECK(br_result_set_verification_error(&probe, "unexpected status code: 401", NULL, 0) == 1);
    CHECK(!fail_status_copy && !probe.verification_error);
    br_result_clear(&probe);

    char input[96]; snprintf(input, sizeof(input), "blogger %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1};
    test_http http = {.response = {.status = 401}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; char *error = NULL;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!fail_status_copy && !results.len && http.calls == 1 && http.releases == 1);
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], 302, first_key, "key");
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "unexpected status code: 401"));
    br_results_clear(&results);
}

int main(void)
{
    memcpy(first_key, "AIzaSy", 6); test_secret(first_key + 6, 33, 0);
    first_key[14] = '_'; first_key[25] = '-'; first_key[30] = 'Z';
    memcpy(dash_key, first_key, sizeof(dash_key)); dash_key[6] = 'Q'; dash_key[38] = '-';
    CHECK(strlen(first_key) == 39 && strlen(dash_key) == 39);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification(detector); context_errors(detector); resource_returns(detector);
    return test_finish("Blogger");
}
