/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char key[33], other[33];

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apilayer_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_apilayer_init(&detector, &error) == 0 && !error && detector);
    const void *compiled = detector->state;
    CHECK(br_apilayer_init(&again, &error) == 0 && !error && again == detector);
    CHECK(compiled && again->state == compiled);
    CHECK(detector->type == 788 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Apilayer") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Apilayer is a service providing various APIs for data verification and other utilities. "
        "Apilayer API keys can be used to access these services and perform operations such as number verification."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apilayer"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const char *input,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, input ? strlen(input) : 0);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        CHECK(results.items[i].raw.len == 32);
        size_t k = 0;
        for (; k < count; ++k)
            if (!memcmp(results.items[i].raw.data, keys[k], 32)) break;
        CHECK(k < count);
        test_key_result(&results.items[i], 788, keys[k], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        /* Upstream iterates a map, so compare unique values rather than order. */
        for (size_t j = 0; j < i; ++j) CHECK(memcmp(results.items[i].raw.data, results.items[j].raw.data, 32) != 0);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[33];
    const char *one[] = {key};
    snprintf(input, sizeof(input), "apilayer = '%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, NULL, NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s apilayer", key);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "preAPILAYERsuffix:%s", key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "apilayer\r\n%s", key);
    expect_extraction(detector, input, one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "apilayer");
        memset(input + at, '-', gap);
        memcpy(input + at + gap, key, 33);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const struct { const char *before, *after; } edges[] = {{"_", ""}, {"x", ""}, {"", "_"}, {"", "q"}};
    for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        snprintf(input, sizeof(input), "apilayer %s%s%s", edges[i].before, key, edges[i].after);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "apilayer %.31s", key);
    expect_extraction(detector, input, NULL, 0);
    const char invalid[] = {'-', '_', '/', '='};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[16] = invalid[i];
        snprintf(input, sizeof(input), "apilayer %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    /* Folding belongs only to the prefix, not the ASCII capture class. */
    snprintf(input, sizeof(input), "apilayer %.16s\xe2\x84\xaa%s", key, key + 17);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "apilayer %s\napilayer %s", key, key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "apilayer %s\napilayer %s\napilayer %s", other, key, other);
    const char *unique[] = {key, other};
    expect_extraction(detector, input, unique, 2); /* Case-distinct keys stay distinct. */
    memset(changed, 'a', 32);
    changed[32] = '\0';
    const char *unfiltered[] = {changed};
    snprintf(input, sizeof(input), "apilayer %s", changed);
    expect_extraction(detector, input, unfiltered, 1);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "apilayer %s", changed);
    expect_extraction(detector, input, unfiltered, 1);
}

typedef struct {
    const char *key, *other;
    size_t key_calls, other_calls;
} requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.apilayer.com/number_verification/countries"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 788);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2); /* Only apikey plus the shared User-Agent. */
    CHECK(!strcmp(request->headers[0].name, "apikey"));
    if (!strcmp(request->headers[0].value, expected->key)) ++expected->key_calls;
    else { CHECK(expected->other && !strcmp(request->headers[0].value, expected->other)); ++expected->other_calls; }
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog apilayer-test"));
}

static void verification(const br_detector *detector)
{
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL},
        {401, 0, NULL, false, NULL},
        {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"},
        {500, 0, NULL, false, "unexpected status code: 500"},
        {200, -1, "context deadline exceeded", false, "context deadline exceeded"},
        {200, -1, "context canceled", false, "context canceled"},
        {200, -1, NULL, false, "HTTP transport failed"},
    };
    char input[256];
    snprintf(input, sizeof(input), "apilayer %s\napilayer %s", key, key);
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        requests expected = {.key = key};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "ignored body-read/drain error"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "apilayer-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(expected.key_calls == 1 && !expected.other_calls);
        test_key_result(&results.items[0], 788, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char cause[160];
    snprintf(cause, sizeof(cause), "key=%s repeated=%s", key, key);
    snprintf(input, sizeof(input), "apilayer %s\napilayer %s\napilayer %s", other, key, other);
    requests expected = {.key = key, .other = other};
    test_http http = {.send_rc = -1, .send_error = cause, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apilayer-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    CHECK(expected.key_calls == 1 && expected.other_calls == 1);
    CHECK(results.items[0].raw.len == 32 && results.items[1].raw.len == 32);
    CHECK(memcmp(results.items[0].raw.data, results.items[1].raw.data, 32) != 0);
    for (size_t i = 0; i < results.len; ++i) {
        const char *matched = !memcmp(results.items[i].raw.data, key, 32) ? key : other;
        test_key_result(&results.items[i], 788, matched, "key");
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, cause)); /* No redaction arguments upstream. */
    }
    br_results_clear(&results);
    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "apilayer", 8);
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "apilayer %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    test_key_result(&results.items[0], 788, key, "key");
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0);
    key[0] = 'B';
    key[16] = 'K';
    memcpy(other, key, sizeof(other));
    other[0] = 'b';
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    return test_finish("Apilayer");
}
