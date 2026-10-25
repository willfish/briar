/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

typedef struct { const char *key, *secret; } credential;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_amplitudeapikey_init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(br_amplitudeapikey_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 42 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AmplitudeApiKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Amplitude is a product analytics service that helps companies track and analyze user behavior within web and mobile applications. Amplitude API keys can be used to access and modify this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "amplitude"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_pair(const br_result *result, credential expected)
{
    CHECK(strlen(expected.key) == 32 && strlen(expected.secret) == 32);
    CHECK(strcmp(expected.key, expected.secret) != 0);
    CHECK(result->detector_type == 42 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, expected.key, 32));
    CHECK(result->raw_v2.len == 64);
    CHECK(!memcmp(result->raw_v2.data, expected.key, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, expected.secret, 32));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !strcmp(json_object_get_string(part), expected.key));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 32 && !strcmp(json_object_get_string(part), expected.secret));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_extraction(const br_detector *detector, const char *input,
                              const credential *pairs, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *first,
                        const char *second, const char *third)
{
    char input[1536], changed[33];
    const credential both[] = {{first, second}, {second, first}};
    snprintf(input, sizeof(input), "preAMPLITUDEsuffix:'%s'\ramplitude\n%s", first, second);
    expect_extraction(detector, input, both, 2);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "amplitude%.*s%s\namplitude %s", gap,
                 "-----------------------------------------", first, second);
        expect_extraction(detector, input, both, gap == 40 ? 2 : 0);
    }
    const char *invalid_forms[] = {
        "_%s", "%s_", "%.31s", "%sf",
    };
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        char invalid[35];
        snprintf(invalid, sizeof(invalid), invalid_forms[i], first);
        snprintf(input, sizeof(input), "amplitude %s\namplitude %s", invalid, second);
        expect_extraction(detector, input, NULL, 0);
    }
    const char invalid_chars[] = {'A', 'g', '-'};
    for (size_t i = 0; i < sizeof(invalid_chars); ++i) {
        memcpy(changed, first, sizeof(changed));
        changed[16] = invalid_chars[i];
        snprintf(input, sizeof(input), "AMPLITUDE %s\namplitude %s", changed, second);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "amplitude %s\n%1100s\namplitude %s", first, "", second);
    expect_extraction(detector, input, both, 2); /* No scanner-local credential span limit. */

    snprintf(input, sizeof(input), "amplitude %s\namplitude %s\namplitude %s\namplitude %s",
             second, first, third, second);
    const credential product[] = {
        {second, first}, {second, third}, {first, second},
        {first, third}, {third, second}, {third, first},
    };
    expect_extraction(detector, input, product, 6);

    /* Both regexes see the same set. A lone value, even repeated, cannot form
     * an unequal pair. One provider prefix is not reused for a second capture. */
    char repeated[256], one_prefix[96], bare[80], single[64];
    snprintf(repeated, sizeof(repeated), "amplitude %s\namplitude %s", first, first);
    snprintf(one_prefix, sizeof(one_prefix), "amplitude %s %s", first, second);
    snprintf(bare, sizeof(bare), "%s %s", first, second);
    snprintf(single, sizeof(single), "amplitude %s", first);
    const char *no_pairs[] = {"", "amplitude", bare, single, repeated, one_prefix};
    for (size_t i = 0; i < sizeof(no_pairs) / sizeof(no_pairs[0]); ++i) {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, no_pairs[i], strlen(no_pairs[i]));
        CHECK(!results.len && !http.calls && !http.releases);
        br_results_clear(&results);
    }
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
    CHECK(!strcmp(request->url, "https://amplitude.com/api/2/taxonomy/category"));
    CHECK(request->detector_type == 42 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    char *auth = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)pair.key, 32},
                             (br_slice){(const unsigned char *)pair.secret, 32}, &auth, NULL) == 0 && auth);
    CHECK(!strcmp(request->headers[0].value, auth));
    free(auth);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog amplitudeapikey-test"));
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
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "amplitudeapikey-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == count && http->calls == count && http->releases == count);
    for (size_t i = 0; i < count; ++i) {
        check_pair(&results.items[i], pairs[i]);
        CHECK(results.items[i].verified == verified);
        if (error) {
            CHECK(results.items[i].verification_error);
            CHECK(!strcmp(results.items[i].verification_error, error));
        } else CHECK(!results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *first,
                          const char *second, const char *third)
{
    char input[256];
    snprintf(input, sizeof(input), "amplitude %s\namplitude %s", first, second);
    const credential both[] = {{first, second}, {second, first}};
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
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = cases[i].body_error}};
        expect_verification(detector, &http, input, both, 2, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 200}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, input, both, 2, false, send_errors[i]);
    }
    /* Synthetic only: upstream omits BOTH credentials from error redaction. */
    char sensitive_error[192];
    snprintf(sensitive_error, sizeof(sensitive_error), "key %s secret %s failed for %s", first, second, first);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, input, both, 2, false, sensitive_error);
    http.send_error = NULL;
    expect_verification(detector, &http, input, both, 2, false, "HTTP transport failed");

    snprintf(input, sizeof(input), "amplitude %s\namplitude %s\namplitude %s\namplitude %s",
             second, first, third, second);
    const credential product[] = {
        {second, first}, {second, third}, {first, second},
        {first, third}, {third, second}, {third, first},
    };
    http = (test_http){.response = {.status = 200}};
    expect_verification(detector, &http, input, product, 6, true, NULL);

    br_scan_ctx offline = {0};
    br_results results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 6);
    for (size_t i = 0; i < results.len; ++i) {
        check_pair(&results.items[i], product[i]);
        CHECK(!results.items[i].verified && results.items[i].verification_error);
        CHECK(!strcmp(results.items[i].verification_error, "HTTP transport not installed"));
    }
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    const char *first = "0123456789abcdef0123456789abcdef";
    const char *second = "fedcba9876543210fedcba9876543210";
    const char *third = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    extraction(detector, first, second, third);
    verification(detector, first, second, third);
    return test_finish("AmplitudeApiKey");
}
