/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *const *keys; size_t len; } expected_requests;
static char first_key[47], symbols_key[47];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_beamer_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_beamer_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 166 && detector->version == 0 && !strcmp(detector->name, "Beamer"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Beamer is a user engagement platform that helps you communicate product updates and other important "
        "information to your users. Beamer API keys can be used to access and manage this information."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "beamer"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_beamer_init(NULL, &error) != 0 && error);
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
        test_key_result(&results.items[i], 166, key, "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[160];
    const struct { const char *format; size_t count; } cases[] = {
        {"beamer '%s'", 1},
        {"BEAMER: %s", 1},
        {"prefixbeamersuffix %s", 1},
        {"beamer\r\n%s", 1},
        {"%s", 0},
        {"bea mer %s", 0},
        {"beamer _%s", 0},
        {"beamer X%s", 0}, /* 46 word characters before '=' cannot match. */
        {"beamer %.44s=", 0},
        {"beamer %.45s", 0},
        {"beamer %s_suffix", 1}, /* No ending boundary after the literal '='. */
        {"beamer %s=", 1},
        {"beamer +%s", 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, first_key);
        expect_extraction(detector, input, strlen(input), first_key, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "beamer", 6); memset(input + 6, '-', gap);
        snprintf(input + 6 + gap, sizeof(input) - 6 - gap, "%s", first_key);
        expect_extraction(detector, input, strlen(input), first_key, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "beamer %s", symbols_key);
    expect_extraction(detector, input, strlen(input), symbols_key, 1); /* '_', '+' and '/' are not decoded. */
    char changed[47]; memcpy(changed, first_key, sizeof(changed)); changed[0] = '_';
    snprintf(input, sizeof(input), "beamer %s", changed);
    expect_extraction(detector, input, strlen(input), changed, 1);
    const char nonword[] = {'+', '/'};
    for (size_t i = 0; i < sizeof(nonword); ++i) {
        memcpy(changed, first_key, sizeof(changed)); changed[0] = nonword[i];
        snprintf(input, sizeof(input), "beamer %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
        /* A leading nonword key byte is legal when the PREVIOUS byte is word. */
        snprintf(input, sizeof(input), "beamer W%s", changed);
        expect_extraction(detector, input, strlen(input), changed, 1);
    }
    memcpy(changed, first_key, sizeof(changed)); changed[20] = '-';
    snprintf(input, sizeof(input), "beamer %s", changed);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    memset(changed, 'A', 45); changed[45] = '='; changed[46] = 0;
    snprintf(input, sizeof(input), "beamer %s", changed);
    expect_extraction(detector, input, strlen(input), changed, 1); /* No detector-local entropy/FP filtering. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->len);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.getbeamer.com/v0/url"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 166);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Beamer-Api-Key"));
    CHECK(!strcmp(request->headers[0].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog beamer-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1);
}

static void occurrences(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "beamer %s\nbeamer %s\nbeamer %s", first_key, symbols_key, first_key);
    const char *keys[] = {first_key, symbols_key, first_key};
    expected_requests expected = {keys, sizeof(keys) / sizeof(keys[0])};
    for (int verify = 0; verify <= 1; ++verify) {
        test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 166, keys[i], "key");
            CHECK(results.items[i].verified == (bool)verify && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    /* Creation failure is retained for EVERY occurrence, unlike skip-on-error providers. */
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) {
        test_key_result(&results.items[i], 166, keys[i], "key");
        CHECK(!results.items[i].verified && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[128], sensitive[256], redacted[160];
    snprintf(input, sizeof(input), "beamer %s", symbols_key);
    snprintf(sensitive, sizeof(sensitive), "url=https://api.getbeamer.com/v0/url key=%s again=%s", symbols_key, symbols_key);
    snprintf(redacted, sizeof(redacted), "url=https://api.getbeamer.com/v0/url key=[REDACTED] again=[REDACTED]");
    const char *keys[] = {symbols_key}; expected_requests expected = {keys, 1};
    const struct {
        int status, send_rc;
        const char *send_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {403, 0, NULL, false, "unexpected status code: 403"},
        {429, 0, NULL, false, "unexpected status code: 429"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "lookup synthetic: no such host", false, "lookup synthetic: no such host"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, 1, sensitive, false, redacted},
        {200, 1, NULL, false, "HTTP transport failed"},
        {200, 0, NULL, true, NULL}, /* No DNS suppression/cache survives a prior error. */
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "beamer-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        const br_result *result = &results.items[0]; test_key_result(result, 166, symbols_key, "key");
        CHECK(result->verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(result->verification_error && !strcmp(result->verification_error, cases[i].error));
            CHECK(!strstr(result->verification_error, symbols_key));
        } else CHECK(!result->verification_error);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_errors(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "beamer %s", first_key);
    const char *keys[] = {first_key}; expected_requests expected = {keys, 1};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 0 && http.releases == 1);
        test_key_result(&results.items[0], 166, first_key, "key");
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(first_key, 45, 0); first_key[45] = '='; first_key[46] = 0;
    test_secret(symbols_key, 45, 7);
    for (size_t i = 0; i < 45; ++i)
        if (symbols_key[i] >= 'a' && symbols_key[i] <= 'z') symbols_key[i] += 'A' - 'a';
    symbols_key[5] = '_'; symbols_key[13] = '+'; symbols_key[27] = '/'; symbols_key[45] = '='; symbols_key[46] = 0;
    const br_detector *detector = descriptor();
    extraction(detector); occurrences(detector); verification(detector); context_errors(detector);
    return test_finish("Beamer");
}
