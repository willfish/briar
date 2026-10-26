/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char hex[] = "0123456789abcdef0123456789abcdef01234567";
static char key[58], other_key[58];

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_avazapersonalaccesstoken_init(&detector, &error) == 0 && !error && detector);
    const void *state = detector->state;
    CHECK(br_avazapersonalaccesstoken_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->state == state);
    CHECK(detector->type == 733 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AvazaPersonalAccessToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Avaza is a business management tool that offers project management, time tracking, and financial management. "
        "Avaza Personal Access Tokens can be used to access and interact with Avaza's API."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "avaza"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
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
        test_key_result(&results.items[i], 733, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[80], padding[42];
    const char *one[] = {key};
    CHECK(strlen(key) == 57 && !strncmp(key, "0000000000000123-", 17));
    snprintf(input, sizeof(input), "preAvAzAsuffix:'%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s avaza", key);
    expect_extraction(detector, input, NULL, 0);
    memset(padding, ' ', 41);
    padding[41] = '\0';
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "avaza%.*s%s", gap, padding, key);
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *separators[] = {"\r", "\n", "\r\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        snprintf(input, sizeof(input), "avaza%s%s", separators[i], key);
        expect_extraction(detector, input, one, 1);
    }
    const char *invalid_forms[] = {
        "avaza%s", "avaza x%s", "avaza _%s", "avaza %s_", "avaza %.56s", "avaza %sa", "avaza %sg",
    };
    for (size_t i = 0; i < sizeof(invalid_forms) / sizeof(invalid_forms[0]); ++i) {
        snprintf(input, sizeof(input), invalid_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    const char invalid_hex[] = {'A', 'g', '_', '-'};
    for (size_t i = 0; i < sizeof(invalid_hex); ++i) {
        memcpy(changed, key, sizeof(key));
        changed[27] = invalid_hex[i];
        snprintf(input, sizeof(input), "avaza %s", changed);
        expect_extraction(detector, input, NULL, 0);
    }
    memcpy(changed, key, sizeof(key));
    changed[4] = 'x';
    snprintf(input, sizeof(input), "avaza %s", changed);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "avaza -%s", hex); /* At least one numeric prefix byte is required. */
    expect_extraction(detector, input, NULL, 0);
    snprintf(changed, sizeof(changed), "0-%s", hex);
    snprintf(input, sizeof(input), "avaza %s", changed);
    const char *zero[] = {changed};
    expect_extraction(detector, input, zero, 1);
    snprintf(input, sizeof(input), "avaza -%s-", key);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "avaza \xc3\xa9%s\xc3\xa9", key);
    expect_extraction(detector, input, one, 1);
    char padded[46], plain[43];
    snprintf(padded, sizeof(padded), "0001-%s", hex);
    snprintf(plain, sizeof(plain), "1-%s", hex);
    snprintf(input, sizeof(input), "avaza %s\navaza %s", padded, plain);
    const char *distinct[] = {padded, plain};
    expect_extraction(detector, input, distinct, 2); /* No integer normalization. */
    snprintf(input, sizeof(input), "avaza %s\navaza %s\navaza %s", other_key, key, other_key);
    const char *occurrences[] = {other_key, key, other_key};
    expect_extraction(detector, input, occurrences, 3);
}

typedef struct { const char *const *keys; size_t count; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.avaza.com/api/Account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 733);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog avaza-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                                const char *credential, bool verified, const char *error)
{
    size_t len = strlen(credential);
    char *input = malloc(len + sizeof("avaza "));
    CHECK(input);
    memcpy(input, "avaza ", sizeof("avaza ") - 1);
    memcpy(input + sizeof("avaza ") - 1, credential, len + 1);
    const char *keys[] = {credential};
    expected_requests expected = {keys, 1};
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "avaza-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 733, credential, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
    free(input);
}

static void verification(const br_detector *detector)
{
    const struct { int status; const char *body_error; bool verified; const char *error; } cases[] = {
        {200, NULL, true, NULL}, {200, "ignored drain failure", true, NULL},
        {401, "ignored drain failure", false, NULL},
        {403, "ignored drain failure", false, "unexpected status code: 403"},
        {404, "ignored drain failure", false, "unexpected status code: 404"},
        {500, "ignored drain failure", false, "unexpected status code: 500"},
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
    char cause[384], redacted[384];
    snprintf(cause, sizeof(cause), "key=%s repeated=%s other=%s hash=%s", key, key, other_key, hex);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] repeated=[REDACTED] other=%s hash=%s", other_key, hex);
    http.send_error = cause;
    expect_verification(detector, &http, key, false, redacted);
    http.send_error = NULL;
    expect_verification(detector, &http, key, false, "HTTP transport failed");
    http = (test_http){.response = {.status = 200, .body_error = cause}};
    expect_verification(detector, &http, key, true, NULL);

    char input[256];
    snprintf(input, sizeof(input), "avaza %s\navaza %s\navaza %s", other_key, key, other_key);
    const char *keys[] = {other_key, key, other_key};
    expected_requests expected = {keys, 3};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "avaza-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 733, keys[i], "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    br_scan_ctx offline = {0};
    snprintf(input, sizeof(input), "avaza %s", key);
    results = test_scan(detector, &offline, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 733, key, "key");
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
}

static void long_prefix(const br_detector *detector)
{
    size_t digits = 8192, len = digits + 1 + 40;
    char *credential = malloc(len + 1), *input = malloc(len + sizeof("avaza "));
    CHECK(credential && input);
    memset(credential, '0', digits);
    memcpy(credential + digits - 5, "12345", 5);
    credential[digits] = '-';
    memcpy(credential + digits + 1, hex, sizeof(hex));
    memcpy(input, "avaza ", sizeof("avaza ") - 1);
    memcpy(input + sizeof("avaza ") - 1, credential, len + 1);
    const char *keys[] = {credential};
    expect_extraction(detector, input, keys, 1);
    test_http http = {.response = {.status = 200, .body_error = "ignored"}};
    expect_verification(detector, &http, credential, true, NULL);
    free(input);
    free(credential);
}

int main(void)
{
    CHECK(strlen(hex) == 40);
    snprintf(key, sizeof(key), "0000000000000123-%s", hex);
    snprintf(other_key, sizeof(other_key), "0000000000000124-%s", hex);
    const br_detector *detector = detector_init();
    extraction(detector);
    verification(detector);
    long_prefix(detector);
    return test_finish("AvazaPersonalAccessToken");
}
