/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char jwt_header[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
enum { PAYLOAD_AT = sizeof(jwt_header), SIGNATURE_AT = PAYLOAD_AT + 74 + 1,
       TOKEN_LEN = SIGNATURE_AT + 43 };

static void make_token(char out[TOKEN_LEN + 1], char payload, char signature)
{
    memcpy(out, jwt_header, sizeof(jwt_header) - 1);
    out[PAYLOAD_AT - 1] = '.';
    /* These payloads are not JWT JSON: upstream only matches the byte pattern. */
    memset(out + PAYLOAD_AT, payload, 74);
    out[SIGNATURE_AT - 1] = '.';
    memset(out + SIGNATURE_AT, signature, 43);
    out[TOKEN_LEN] = '\0';
}

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_appfollow_init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(br_appfollow_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 588 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Appfollow") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Appfollow is a service used for app monitoring and analytics. Appfollow API tokens can be used to access and manage app data and analytics."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "appfollow"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
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
        test_key_result(&results.items[i], 588, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector, const char *key, const char *other)
{
    char input[3 * TOKEN_LEN + 128], changed[TOKEN_LEN + 1], padding[42];
    const char *one[] = {key}, *altered[] = {changed};
    CHECK(strlen(key) == TOKEN_LEN);
    snprintf(input, sizeof(input), "preAPPFOLLOWsuffix:'%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s appfollow", key);
    expect_extraction(detector, input, NULL, 0);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "appfollow%.*s%s", gap, padding, key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    snprintf(input, sizeof(input), "appfollow\r\n%s", key);
    expect_extraction(detector, input, one, 1);
    const char *invalid_forms[] = {"appfollow%s", "appfollow _%s", "appfollow %s_", "appfollow %sz"};
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[0] = 'E';
    snprintf(input, sizeof(input), "APPFOLLOW %s", changed);
    expect_extraction(detector, input, NULL, 0); /* The fixed header remains case-sensitive. */
    const char invalid_payload[] = {'-', '_', '='};
    for (size_t i = 0; i < sizeof(invalid_payload); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[PAYLOAD_AT + 4] = invalid_payload[i];
        snprintf(input, sizeof(input), "appfollow %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[PAYLOAD_AT] = 'z';
    changed[PAYLOAD_AT + 1] = '7';
    snprintf(input, sizeof(input), "appfollow %s", changed);
    expect_extraction(detector, input, altered, 1);
    snprintf(input, sizeof(input), "appfollow %s.%.*s.%s", jwt_header, 73,
             key + PAYLOAD_AT, key + SIGNATURE_AT);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "appfollow %s.%.*sA.%s", jwt_header, 74,
             key + PAYLOAD_AT, key + SIGNATURE_AT);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "appfollow %.*s", TOKEN_LEN - 1, key);
    expect_extraction(detector, input, NULL, 0);

    memcpy(changed, key, sizeof(changed));
    changed[SIGNATURE_AT] = '-';
    changed[SIGNATURE_AT + 5] = '_';
    snprintf(input, sizeof(input), "appfollow %s", changed);
    expect_extraction(detector, input, altered, 1);
    /* A-Z-a-z does not broaden this class to the ASCII punctuation between Z and a. */
    const char invalid_signature[] = {'[', ']', '\\', '^', '`', '='};
    for (size_t i = 0; i < sizeof(invalid_signature); ++i) {
        memcpy(changed, key, sizeof(changed));
        changed[SIGNATURE_AT + 5] = invalid_signature[i];
        snprintf(input, sizeof(input), "appfollow %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(changed));
    changed[TOKEN_LEN - 1] = '-';
    snprintf(input, sizeof(input), "appfollow %s", changed);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "appfollow %sZ", changed);
    expect_extraction(detector, input, altered, 1); /* Nonword '-' before word 'Z' satisfies the boundary. */
    changed[TOKEN_LEN - 1] = '_';
    snprintf(input, sizeof(input), "appfollow %s", changed);
    expect_extraction(detector, input, altered, 1);
    snprintf(input, sizeof(input), "appfollow %sZ", changed);
    expect_extraction(detector, input, NULL, 0); /* '_' and 'Z' are both word characters. */
    snprintf(input, sizeof(input), "appfollow %s-", key);
    expect_extraction(detector, input, one, 1); /* A nonword suffix need not be part of the capture. */
    snprintf(input, sizeof(input), "appfollow \xc3\xa9%s\xc3\xa9", key);
    expect_extraction(detector, input, one, 1); /* Word boundaries stay ASCII. */

    snprintf(input, sizeof(input), "appfollow %s\nappfollow %s\nappfollow %s", other, key, other);
    const char *ordered[] = {other, key, other};
    expect_extraction(detector, input, ordered, 3);
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                             const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.appfollow.io/api/v2/account/users"));
    CHECK(request->detector_type == 588 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-AppFollow-API-Token"));
    CHECK(!strcmp(request->headers[0].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog appfollow-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                const char *key, bool verified, const char *error)
{
    char input[TOKEN_LEN + 16];
    snprintf(input, sizeof(input), "appfollow %s", key);
    const char *keys[] = {key};
    expected_requests expected = {keys, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "appfollow-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 588, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
        CHECK(!strstr(results.items[0].verification_error, key));
    } else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector, const char *key, const char *other)
{
    const struct {
        int status;
        const char *body_error;
        bool verified;
        const char *error;
    } cases[] = {
        {200, NULL, true, NULL}, {200, "ignored drain failure", true, NULL},
        {402, "ignored drain failure", true, NULL}, {422, "ignored drain failure", true, NULL},
        {401, "ignored drain failure", false, NULL},
        {403, "ignored drain failure", false, "unexpected status code: 403"},
        {201, "ignored drain failure", false, "unexpected status code: 201"},
        {500, "ignored drain failure", false, "unexpected status code: 500"},
    };
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {body, sizeof(body)}, .body_error = cases[i].body_error}};
        expect_verification(detector, &http, key, cases[i].verified, cases[i].error);
    }
    test_http http = {.response = {.status = 422}, .send_rc = -1};
    const char *send_errors[] = {"context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, key, false, send_errors[i]);
    }
    char sensitive_error[2 * TOKEN_LEN + 80];
    snprintf(sensitive_error, sizeof(sensitive_error), "token %s failed: %s; keep synthetic-marker", key, key);
    http.send_error = sensitive_error;
    expect_verification(detector, &http, key, false,
                        "token [REDACTED] failed: [REDACTED]; keep synthetic-marker");
    http.send_error = NULL;
    expect_verification(detector, &http, key, false, "HTTP transport failed");

    char input[3 * TOKEN_LEN + 64];
    snprintf(input, sizeof(input), "appfollow %s\nappfollow %s\nappfollow %s", other, key, other);
    const char *keys[] = {other, key, other};
    expected_requests expected = {keys, 3};
    http = (test_http){.response = {.status = 402}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "appfollow-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 588, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);

    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "appfollow %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 588, key, "key");
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = detector_init();
    char key[TOKEN_LEN + 1], other[TOKEN_LEN + 1];
    make_token(key, 'A', 'b');
    make_token(other, 'C', 'd');
    extraction(detector, key, other);
    verification(detector, key, other);
    return test_finish("Appfollow");
}
