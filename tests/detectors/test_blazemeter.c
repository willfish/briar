/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char first_key[] = "g7h8ijkl-m9n0-opqr-stuv-wxyz1234abcd";
static const char second_key[] = "12345678-90ab-cdef-ghij-klmnopqrstuv";
typedef struct { const char *const *keys; size_t len; } expected_requests;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_blazemeter_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_blazemeter_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 603 && detector->version == 0 && !strcmp(detector->name, "Blazemeter"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Blazemeter is a continuous testing platform for DevOps. "
        "The keys can be used to access and manage performance tests and other resources."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "blazemeter") && !strcmp(detector->keywords[1], "runscope"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_blazemeter_init(NULL, &error) != 0 && error);
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
        test_key_result(&results.items[i], 603, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192];
    const struct { const char *format; size_t count; } cases[] = {
        {"blazemeter '%s'", 1},
        {"BLAZEMETER: %s", 1},
        {"RUNSCOPE=%s", 1},
        {"RuNsCoPe\t%s", 1},
        {"prefixrunscopepostfix %s", 1},
        {"blazemeter\r\n%s\t", 1},
        {"%s", 0},
        {"blaze meter %s", 0},
        {"run scope %s", 0},
        {"blazemeter %.35s", 0},
        {"blazemeter a%s", 0},
        {"blazemeter %sa", 0},
        {"blazemeter _%s", 0},
        {"blazemeter %s_", 0},
        {"runscope +%s/", 1},
        {"blazemeter %s=", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, first_key);
        expect_extraction(detector, input, strlen(input), first_key, cases[i].count);
    }
    size_t prefix = strlen("blazemeter");
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "blazemeter", prefix); memset(input + prefix, '-', gap);
        snprintf(input + prefix + gap, sizeof(input) - prefix - gap, "%s", first_key);
        expect_extraction(detector, input, strlen(input), first_key, gap == 40 ? 1 : 0);
    }
    char changed[37]; memcpy(changed, first_key, sizeof(changed));
    for (size_t i = 0; i < 36; ++i)
        if (changed[i] >= 'a' && changed[i] <= 'z') changed[i] += 'A' - 'a';
    snprintf(input, sizeof(input), "BLAZEMETER %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0); /* CI is scoped to keywords, not keys. */
    memcpy(changed, first_key, sizeof(changed)); changed[9] = 'M';
    snprintf(input, sizeof(input), "RUNSCOPE %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, first_key, sizeof(changed)); changed[8] = '_';
    snprintf(input, sizeof(input), "blazemeter %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    const char *nil_uuid = "00000000-0000-0000-0000-000000000000";
    snprintf(input, sizeof(input), "runscope %s", nil_uuid);
    expect_extraction(detector, input, strlen(input), nil_uuid, 1); /* Shape only: no version/variant/FP/entropy validation. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.runscope.com/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 603);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    char authorization[96];
    snprintf(authorization, sizeof(authorization), "Bearer %s", expected->keys[http->calls - 1]);
    CHECK(!strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog blazemeter-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1);
}

static void occurrences(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "blazemeter %s\nrunscope %s\nBLAZEMETER %s", first_key, second_key, first_key);
    const char *keys[] = {first_key, second_key, first_key};
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
            test_key_result(&results.items[i], 603, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1));
            if (dns_error) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, dns_error));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 603, keys[i], "key");
        CHECK(!results.items[i].verified && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
    }
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 603, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[96], unredacted[256];
    snprintf(input, sizeof(input), "runscope %s", second_key);
    snprintf(unredacted, sizeof(unredacted), "url=https://api.runscope.com/account Bearer %s again=%s", second_key, second_key);
    const char *keys[] = {second_key}; expected_requests expected = {keys, 1};
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
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
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "blazemeter-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0]; test_key_result(result, 603, second_key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) CHECK(result->verification_error && !strcmp(result->verification_error, cases[i].error));
        else CHECK(!result->verification_error);
        if (cases[i].send_error == unredacted) {
            CHECK(strstr(result->verification_error, second_key));
            CHECK(!strstr(result->verification_error, "[REDACTED]"));
        }
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "blazemeter %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        test_key_result(&results.items[0], 603, first_key, "key");
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

int main(void)
{
    CHECK(strlen(first_key) == 36 && strlen(second_key) == 36);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification(detector); context_errors(detector);
    return test_finish("Blazemeter");
}
