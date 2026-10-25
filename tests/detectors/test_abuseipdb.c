/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static void test_descriptor(const br_detector *detector)
{
    CHECK(BR_ABI_REVISION == 1);
    CHECK(detector->type == 521 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AbuseIPDB") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. AbuseIPDB API keys can be used to report and check IP addresses for abusive activities."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "abuseipdb"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);

    const br_detector *again = NULL;
    char *error = NULL;
    CHECK(br_abuseipdb_init(&again, &error) == 0 && error == NULL);
    CHECK(again == detector);
}

static void expect_extraction(const br_detector *detector, const char *input,
                              const char *const *keys, size_t nkeys)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == nkeys);
    CHECK(http.calls == 0 && http.releases == 0);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 521, keys[i], "key");
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void test_extraction(const br_detector *detector)
{
    char key[81], second[81], changed[81], input[256];
    test_secret(key, 80, 0);
    test_secret(second, 80, 9);
    const char *one[] = {key};
    const char *two[] = {key, second};
    const char *twice[] = {key, key};

    snprintf(input, sizeof(input), "AbUsEiPdB = '%s'", key);
    expect_extraction(detector, input, one, 1);
    expect_extraction(detector, "", NULL, 0);
    expect_extraction(detector, key, NULL, 0);
    snprintf(input, sizeof(input), "%s abuseipdb", key);
    expect_extraction(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "preabuseipdbsuffix:%s", key);
    expect_extraction(detector, input, one, 1);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "abuseipdb", 9);
        memset(input + 9, '-', gap);
        memcpy(input + 9 + gap, key, sizeof(key));
        expect_extraction(detector, input, one, gap == 40 ? 1 : 0);
    }
    const char *separators[] = {"\r", "\n", "\r\n"};
    for (size_t i = 0; i < sizeof(separators) / sizeof(separators[0]); ++i) {
        snprintf(input, sizeof(input), "abuseipdb%s%s", separators[i], key);
        expect_extraction(detector, input, one, 1);
    }

    const char *rejected_forms[] = {
        "abuseipdb%s", "abuseipdb _%s", "abuseipdb %s_", "abuseipdb %sq",
    };
    for (size_t i = 0; i < sizeof(rejected_forms) / sizeof(rejected_forms[0]); ++i) {
        snprintf(input, sizeof(input), rejected_forms[i], key);
        expect_extraction(detector, input, NULL, 0);
    }
    snprintf(input, sizeof(input), "abuseipdb %.*s", 79, key);
    expect_extraction(detector, input, NULL, 0);
    memcpy(changed, key, sizeof(key));
    changed[40] = 'A';
    snprintf(input, sizeof(input), "abuseipdb %s", changed);
    expect_extraction(detector, input, NULL, 0);
    changed[40] = '_';
    snprintf(input, sizeof(input), "abuseipdb %s", changed);
    expect_extraction(detector, input, NULL, 0);

    snprintf(input, sizeof(input), "abuseipdb %s\nabuseipdb %s", key, second);
    expect_extraction(detector, input, two, 2);
    snprintf(input, sizeof(input), "abuseipdb %s %s", key, second);
    expect_extraction(detector, input, one, 1);
    snprintf(input, sizeof(input), "abuseipdb %s\nabuseipdb %s", key, key);
    expect_extraction(detector, input, twice, 2);
    memset(changed, 'a', 80);
    changed[80] = '\0';
    const char *low_entropy[] = {changed};
    snprintf(input, sizeof(input), "abuseipdb %s", changed);
    expect_extraction(detector, input, low_entropy, 1);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx,
                            const br_http_request *request)
{
    const char *key = http->user;
    CHECK(ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8"));
    CHECK(request->detector_type == 521 && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Key"));
    CHECK(!strcmp(request->headers[0].value, key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog abuseipdb-test"));
}

static void expect_verification(const br_detector *detector, test_http *http,
                               const char *key, bool verified, const char *error)
{
    char input[96];
    snprintf(input, sizeof(input), "abuseipdb %s", key);
    http->calls = http->releases = 0;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "abuseipdb-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 521, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) {
        CHECK(results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, error));
        CHECK(!strstr(results.items[0].verification_error, key));
    } else {
        CHECK(!results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void test_verification(const br_detector *detector)
{
    char key[81], sensitive_error[192];
    test_secret(key, 80, 0);
    test_http http = {.inspect = inspect_request, .user = key};
    http.response.status = 200;

    const char *bodies[] = {
        "{\"data\":{\"ipAddress\":\"8.8.8.8\"}}",
        "ipAddress", "not JSON: ipAddress!",
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        http.response.body = (br_slice){(const unsigned char *)bodies[i], strlen(bodies[i])};
        expect_verification(detector, &http, key, true, NULL);
    }
    static const unsigned char binary[] = "\0ipAddress\0\xff";
    http.response.body = (br_slice){binary, sizeof(binary) - 1};
    expect_verification(detector, &http, key, true, NULL);

    const char *missing_marker[] = {"", "{\"data\":{\"address\":\"8.8.8.8\"}}", "ipaddress IPADDRESS ipAddres"};
    for (size_t i = 0; i < sizeof(missing_marker) / sizeof(missing_marker[0]); ++i) {
        http.response.body = (br_slice){(const unsigned char *)missing_marker[i], strlen(missing_marker[i])};
        expect_verification(detector, &http, key, false, NULL);
    }
    http.response.body = (br_slice){0};
    expect_verification(detector, &http, key, false, NULL);

    snprintf(sensitive_error, sizeof(sensitive_error), "read %s failed: %s", key, key);
    http.response.body = (br_slice){binary, sizeof(binary) - 1};
    http.response.body_error = sensitive_error;
    expect_verification(detector, &http, key, false, "read [REDACTED] failed: [REDACTED]");
    http.response.status = 401;
    expect_verification(detector, &http, key, false, NULL);

    const int statuses[] = {201, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80];
        http.response.status = statuses[i];
        snprintf(error, sizeof(error), "unexpected HTTP response status %d", statuses[i]);
        expect_verification(detector, &http, key, false, error);
    }

    http.response.status = 200;
    http.response.body_error = NULL;
    http.send_rc = -1;
    const char *send_errors[] = {"context deadline exceeded", "context canceled"};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        http.send_error = send_errors[i];
        expect_verification(detector, &http, key, false, send_errors[i]);
    }
    http.send_error = sensitive_error;
    expect_verification(detector, &http, key, false, "read [REDACTED] failed: [REDACTED]");
    http.send_error = NULL;
    expect_verification(detector, &http, key, false, "HTTP transport failed");

    http.send_rc = 0;
    http.calls = http.releases = 0;
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "abuseipdb-test"};
    br_results results = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(results.len == 0 && http.calls == 0 && http.releases == 0);
    br_results_clear(&results);

    char input[192];
    snprintf(input, sizeof(input), "abuseipdb %s\nabuseipdb %s", key, key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < results.len; ++i) {
        test_key_result(&results.items[i], 521, key, "key");
        CHECK(results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_abuseipdb_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector != NULL);
    test_descriptor(detector);
    test_extraction(detector);
    test_verification(detector);
    return test_finish("AbuseIPDB");
}
