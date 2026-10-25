/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aiven_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_aiven_init(&detector, &error) == 0 && !error && detector);
    const void *compiled = detector->state;
    CHECK(br_aiven_init(&again, &error) == 0 && !error && again == detector);
    CHECK(compiled && again->state == compiled);
    CHECK(detector->type == 917 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Aiven") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Aiven is a managed cloud service that provides various open-source data infrastructure services. "
        "Aiven API keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "aiven"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < results.len; ++i) {
        size_t k = 0;
        for (; k < count; ++k)
            if (results.items[i].raw.len == strlen(keys[k]) &&
                !memcmp(results.items[i].raw.data, keys[k], strlen(keys[k]))) break;
        CHECK(k < count);
        test_key_result(&results.items[i], 917, keys[k], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
        /* Source uses a map: require set membership and uniqueness, not order. */
        for (size_t j = 0; j < i; ++j)
            CHECK(memcmp(results.items[i].raw.data, results.items[j].raw.data, 372) != 0);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[2048], changed[373];
    const char *one[] = {key};
    snprintf(input, sizeof(input), "aiven = '%s'", key);
    expect_extraction(detector, input, strlen(input), one, 1);
    expect_extraction(detector, NULL, 0, NULL, 0);
    expect_extraction(detector, key, 372, NULL, 0);
    snprintf(input, sizeof(input), "%s aiven", key);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "preAIVENsuffix:%s", key);
    expect_extraction(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "aiven\r\n%s", key);
    expect_extraction(detector, input, strlen(input), one, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        size_t at = (size_t)snprintf(input, sizeof(input), "aiven");
        memset(input + at, '_', gap);
        memcpy(input + at + gap, key, 373);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
        at = (size_t)snprintf(input, sizeof(input), "aiven");
        for (size_t i = 0; i < gap; ++i) {
            input[at++] = (char)0xc3;
            input[at++] = (char)0xa9;
        }
        memcpy(input + at, key, 373);
        expect_extraction(detector, input, strlen(input), one, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "aiven%s", key);
    expect_extraction(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "aiven _%s_", key);
    expect_extraction(detector, input, strlen(input), one, 1);
    snprintf(input, sizeof(input), "aiven %.371s", key);
    expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "aiven %sR", key);
    expect_extraction(detector, input, strlen(input), one, 1);
    changed[0] = 'R';
    memcpy(changed + 1, key, 371);
    changed[372] = '\0';
    const char *shifted[] = {changed};
    snprintf(input, sizeof(input), "aiven R%s", key);
    expect_extraction(detector, input, strlen(input), shifted, 1);
    snprintf(input, sizeof(input), "aiven %s%s", key, other);
    expect_extraction(detector, input, strlen(input), one, 1);

    const char invalid[] = {'_', '-', ' ', '\n', ':'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[180] = invalid[i];
        snprintf(input, sizeof(input), "aiven %s", changed);
        expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    snprintf(input, sizeof(input), "aiven %s\naiven %s\naiven %s", other, key, other);
    const char *unique[] = {key, other};
    expect_extraction(detector, input, strlen(input), unique, 2);
    snprintf(input, sizeof(input), "aiven %s\naiven %s", key, key);
    expect_extraction(detector, input, strlen(input), one, 1);
    memset(changed, '=', 372); /* No Base64 validity or entropy checks upstream. */
    changed[372] = '\0';
    const char *unfiltered[] = {changed};
    snprintf(input, sizeof(input), "aiven %s", changed);
    expect_extraction(detector, input, strlen(input), unfiltered, 1);
    memset(changed, 'a', 372);
    memcpy(changed, "example", 7);
    snprintf(input, sizeof(input), "aiven %s", changed);
    expect_extraction(detector, input, strlen(input), unfiltered, 1);
    size_t at = (size_t)snprintf(input, sizeof(input), "aiven");
    input[at++] = '\0';
    memcpy(input + at, key, 372);
    expect_extraction(detector, input, at + 372, one, 1);
}

typedef struct {
    const char *key, *other, *agent;
    size_t key_calls, other_calls;
} expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user;
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.aiven.io/v1/project"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 917);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 8 + 372 && !memcmp(auth, "aivenv1 ", 8));
    if (!strcmp(auth + 8, expected->key)) {
        ++expected->key_calls;
    } else {
        CHECK(expected->other && !strcmp(auth + 8, expected->other));
        ++expected->other_calls;
    }
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, expected->agent));
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    char input[2048];
    snprintf(input, sizeof(input), "aiven %s\naiven %s", key, key);
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
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.key = key, .agent = "TruffleHog detector-test"};
        test_http http = {
            .response = {.status = cases[i].status, .body = {body, sizeof(body)},
                         .body_error = "ignored body-read failure"},
            .send_rc = cases[i].send_rc, .send_error = cases[i].send_error,
            .inspect = inspect_request, .user = &expected,
        };
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "detector-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(expected.key_calls == 1 && !expected.other_calls);
        test_key_result(&results.items[0], 917, key, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) {
            CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    char transport_error[900];
    snprintf(transport_error, sizeof(transport_error), "key=%s repeated=%s", key, key);
    snprintf(input, sizeof(input), "aiven %s\naiven %s\naiven %s", other, key, other);
    expected_requests expected = {.key = key, .other = other, .agent = "TruffleHog"};
    test_http http = {.send_rc = -1, .send_error = transport_error,
                      .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    CHECK(expected.key_calls == 1 && expected.other_calls == 1);
    CHECK(results.items[0].raw.len == 372 && results.items[1].raw.len == 372);
    CHECK(memcmp(results.items[0].raw.data, results.items[1].raw.data, 372) != 0);
    for (size_t i = 0; i < results.len; ++i) {
        bool first = !memcmp(results.items[i].raw.data, key, 372);
        test_key_result(&results.items[i], 917, first ? key : other, "key");
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, transport_error));
    }
    br_results_clear(&results);

    http = (test_http){0};
    results = test_scan(detector, &ctx, true, "aiven", 5);
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "aiven %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    test_key_result(&results.items[0], 917, key, "key");
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[373], other[373];
    test_secret(key, 372, 0);
    key[0] = '/';
    key[1] = 'B';
    key[17] = '+';
    key[200] = '=';
    key[371] = '=';
    memcpy(other, key, sizeof(other));
    other[1] = 'b';
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("Aiven");
}
