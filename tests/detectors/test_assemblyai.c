/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_assemblyai_init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(br_assemblyai_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 389 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AssemblyAI") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AssemblyAI is a service that provides speech-to-text transcription. "
        "AssemblyAI keys can be used to access and utilize the transcription services provided by AssemblyAI."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "assemblyai"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
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
        test_key_result(&results.items[i], 389, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[192], changed[33], padding[42];
    const char *one[] = {key};
    CHECK(strlen(key) == 32 && strpbrk(key, "ghjkmnpqrstuvwxyz")); /* Not hex-only. */
    snprintf(input, sizeof(input), "preASSEMBLYAIsuffix:'%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s assemblyai", key);
    expect_extraction(detector, input, NULL, 0);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "assemblyai%.*s%s", gap, padding, key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *separators[] = {"\r", "\n", "\r\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        snprintf(input, sizeof(input), "assemblyai%s%s", separators[i], key);
        expect_extraction(detector, input, one, 1);
    }
    const char *invalid_forms[] = {
        "assemblyai%s", "assemblyai x%s", "assemblyai _%s", "assemblyai %s_",
        "assemblyai %.31s", "assemblyai %sz",
    };
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    const char invalid_chars[] = {'G', '_', '-'};
    for (size_t i = 0; i < sizeof(invalid_chars); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[16] = invalid_chars[i];
        snprintf(input, sizeof(input), "ASSEMBLYAI %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    memset(changed, 'z', 32);
    changed[32] = '\0';
    const char *altered[] = {changed};
    snprintf(input, sizeof(input), "assemblyai %s", changed);
    expect_extraction(detector, input, altered, 1);
    memset(changed, '7', 32);
    snprintf(input, sizeof(input), "assemblyai %s", changed);
    expect_extraction(detector, input, altered, 1);
    snprintf(input, sizeof(input), "assemblyai -%s-", key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "assemblyai \xc3\xa9%s\xc3\xa9", key); /* ASCII word boundaries. */
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "assemblyai %s\nassemblyai %s\nassemblyai %s", other, key, other);
    const char *occurrences[] = {other, key, other};
    expect_extraction(detector, input, occurrences, 3);
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.assemblyai.com/v2/transcript"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 389);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, expected->keys[http->calls - 1])); /* No Bearer prefix. */
    CHECK(!strcmp(request->headers[1].name, "User-Agent") &&
          !strcmp(request->headers[1].value, "TruffleHog assemblyai-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                const char *key, bool verified, const char *error)
{
    char input[64];
    snprintf(input, sizeof(input), "assemblyai %s", key);
    const char *keys[] = {key};
    expected_requests expected = {keys, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "assemblyai-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 389, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    const struct { int status; const char *body_error; bool verified; const char *error; } cases[] = {
        {200, NULL, true, NULL}, {200, "ignored drain failure", true, NULL},
        {401, "ignored drain failure", false, NULL},
        {403, "ignored drain failure", false, "unexpected status code 403"},
        {201, "ignored drain failure", false, "unexpected status code 201"},
        {302, "ignored drain failure", false, "unexpected status code 302"},
        {500, "ignored drain failure", false, "unexpected status code 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = cases[i].body_error}};
        expect_verification(detector, &http, key, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200, .body = {body, sizeof(body)}}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded", "lookup synthetic: no such host"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, key, false, send_errors[i]);
    }
    char cause[160], redacted[160];
    snprintf(cause, sizeof(cause), "key=%s repeated=%s other=%s", key, key, other);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] repeated=[REDACTED] other=%s", other);
    http.send_error = cause;
    expect_verification(detector, &http, key, false, redacted);
    http.send_error = NULL;
    expect_verification(detector, &http, key, false, "HTTP transport failed");
    http = (test_http){.response = {.status = 200, .body_error = cause}};
    expect_verification(detector, &http, key, true, NULL); /* Ignored body errors do not become candidate errors. */

    char input[192];
    snprintf(input, sizeof(input), "assemblyai %s\nassemblyai %s\nassemblyai %s", other, key, other);
    const char *keys[] = {other, key, other};
    expected_requests expected = {keys, 3};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "assemblyai-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 389, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "assemblyai %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 389, key, "key");
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

int main(void)
{
    char key[33], other[33];
    test_secret(key, 32, 0);
    test_secret(other, 32, 9);
    const br_detector *detector = detector_init();
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("AssemblyAI");
}
