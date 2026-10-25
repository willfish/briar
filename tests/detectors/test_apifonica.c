/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *key, *token; } credential;

static void make_key(char out[40], size_t shift)
{
    test_secret(out, 39, shift);
    out[11] = out[16] = out[21] = out[26] = '-';
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_apifonica_init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(br_apifonica_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 484 && detector->version == 0);
    CHECK(!strcmp(detector->name, "ApiFonica") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Apifonica is a cloud communication platform that provides APIs for messaging, voice, and other communication services. Apifonica keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "apifonica"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1); /* No multipart provider upstream. */
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_extraction(const br_detector *detector, const char *input,
                              const char *const *keys, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        /* Shared assertions require exactly one key part and no RawV2. */
        test_key_result(&results.items[i], 484, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key,
                        const char *other, const char *third)
{
    char input[256], changed[40], padding[42];
    const char *one[] = {key};
    CHECK(strlen(key) == 39 && strchr(key, 'g')); /* Lowercase alphanumeric, not hex UUID. */
    snprintf(input, sizeof(input), "preAPIFONICAsuffix:'%s'", key);
    expect_extraction(detector, input, one, 1); /* Includes the key == token pair. */
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s apifonica", key);
    expect_extraction(detector, input, NULL, 0);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "apifonica%.*s%s", gap, padding, key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *separators[] = {"\r", "\n", "\r\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        snprintf(input, sizeof(input), "apifonica%s%s", separators[i], key);
        expect_extraction(detector, input, one, 1);
    }
    const char *invalid_forms[] = {
        "apifonica%s", "apifonica _%s", "apifonica %s_", "apifonica %.38s", "apifonica %sz",
    };
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    const struct { size_t at; char value; } mutations[] = {{0, 'A'}, {12, '_'}, {11, 'x'}, {16, '_'}};
    for (size_t i = 0; i < sizeof(mutations) / sizeof(mutations[0]); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[mutations[i].at] = mutations[i].value;
        snprintf(input, sizeof(input), "APIFONICA %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    expect_extraction(detector, "apifonica 01234567-89ab-cdef-0123-456789abcdef", NULL, 0);
    snprintf(input, sizeof(input), "apifonica %s %s", key, other);
    expect_extraction(detector, input, one, 1); /* One prefix yields one capture, hence one self-pair. */
    snprintf(input, sizeof(input), "apifonica %s\napifonica %s", key, key);
    expect_extraction(detector, input, one, 1); /* Uniqueness is before Cartesian pairing. */

    snprintf(input, sizeof(input), "apifonica %s\napifonica %s\napifonica %s", other, key, other);
    const char *four[] = {other, other, key, key};
    expect_extraction(detector, input, four, 4); /* Repeated same-key findings are NOT cleaned. */
    snprintf(input, sizeof(input), "apifonica %s\napifonica %s\napifonica %s\napifonica %s",
             other, key, third, other);
    const char *nine[] = {other, other, other, key, key, key, third, third, third};
    expect_extraction(detector, input, nine, 9);
}

typedef struct { const credential *pairs; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    credential pair = expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.apifonica.com/v2/accounts"));
    CHECK(request->detector_type == 484 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    char *auth = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)pair.key, 39},
                             (br_slice){(const unsigned char *)pair.token, 39}, &auth, NULL) == 0 && auth);
    CHECK(!strcmp(request->headers[1].value, auth));
    free(auth);
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog apifonica-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                const char *input, const credential *pairs, size_t count,
                                bool verified, const char *error)
{
    expected_requests expected = {pairs, count};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "apifonica-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == count && http->calls == count && http->releases == count);
    for (size_t i = 0; i < count; ++i) {
        test_key_result(&results.items[i], 484, pairs[i].key, "key");
        CHECK(results.items[i].verified == verified);
        if (error) {
            CHECK(results.items[i].verification_error);
            CHECK(!strcmp(results.items[i].verification_error, error));
        } else CHECK(!results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key,
                          const char *other, const char *third)
{
    char input[256];
    snprintf(input, sizeof(input), "apifonica %s", key);
    const credential self[] = {{key, key}};
    test_http http = {.response = {.status = 200}};
    expect_verification(detector, &http, input, self, 1, true, NULL);
    snprintf(input, sizeof(input), "apifonica %s\napifonica %s\napifonica %s", other, key, other);
    const credential four[] = {{other, other}, {other, key}, {key, other}, {key, key}};
    const struct {
        int status;
        const char *body_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, NULL, true, NULL}, {200, "ignored drain failure", true, NULL},
        {401, "ignored drain failure", false, NULL}, {403, "ignored drain failure", false, NULL},
        {201, "ignored drain failure", false, "unexpected status code: 201"},
        {404, "ignored drain failure", false, "unexpected status code: 404"},
        {500, "ignored drain failure", false, "unexpected status code: 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http = (test_http){.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = cases[i].body_error}};
        expect_verification(detector, &http, input, four, 4, cases[i].verified, cases[i].error);
    }
    http = (test_http){.response = {.status = 200}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, input, four, 4, false, send_errors[i]);
    }
    /* Synthetic only: upstream omits BOTH credentials from error redaction. */
    char sensitive_error[192];
    snprintf(sensitive_error, sizeof(sensitive_error), "key %s token %s failed for %s", key, other, key);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, input, four, 4, false, sensitive_error);
    http.send_error = NULL;
    expect_verification(detector, &http, input, four, 4, false, "HTTP transport failed");

    snprintf(input, sizeof(input), "apifonica %s\napifonica %s\napifonica %s\napifonica %s",
             other, key, third, other);
    const credential nine[] = {
        {other, other}, {other, key}, {other, third},
        {key, other}, {key, key}, {key, third},
        {third, other}, {third, key}, {third, third},
    };
    http = (test_http){.response = {.status = 200}};
    expect_verification(detector, &http, input, nine, 9, true, NULL);

    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 9);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 484, nine[i].key, "key");
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, "HTTP transport not installed"));
    }
    br_results_clear(&results);

    http = (test_http){0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[40], other[40];
    make_key(key, 0);
    make_key(other, 11);
    const char *third = "zzzzzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
    CHECK(strlen(third) == 39);
    extraction(detector, key, other, third);
    verification(detector, key, other, third);
    return test_finish("ApiFonica");
}
