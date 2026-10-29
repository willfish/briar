/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

int br_ipquality_init(const br_detector **out, char **error);

static int force_null_send_cause, force_each_positive;
static int release_saw_clean, release_before_setter, setter_after_clean_release, setter_calls;

static int (*real_send)(const br_scan_ctx *, const br_http_request *, br_http_response *, char **) = br_http_send;
static void (*real_release)(const br_scan_ctx *, br_http_response *) = br_http_release;
static int (*real_set_error)(br_result *, const char *, const br_slice *, size_t) = br_result_set_verification_error;
static int (*real_each_member)(br_slice, br_json_member_fn, void *) = br_json_each_member;

static int injected_send(const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    if (force_null_send_cause) {
        force_null_send_cause = 0;
        if (response) memset(response, 0, sizeof(*response));
        if (error) *error = NULL;
        return 1;
    }
    return real_send(ctx, request, response, error);
}

/* The included verifier names its result `result`. Capture it only in this test. */
static void observe_release(const br_scan_ctx *ctx, br_http_response *response, br_result *result)
{
    release_saw_clean = result && !result->verified && !result->verification_error;
    CHECK(release_saw_clean);
    release_before_setter = 1;
    real_release(ctx, response);
}

static int observe_set(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    if (release_before_setter) {
        ++setter_after_clean_release;
        release_before_setter = 0;
    }
    return real_set_error(result, cause, secrets, nsecrets);
}

static int injected_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    if (force_each_positive) {
        force_each_positive = 0;
        return 1;
    }
    return real_each_member(object, callback, user);
}

#define br_http_send injected_send
#define br_http_release(ctx, response) observe_release(ctx, response, result)
#define br_result_set_verification_error observe_set
#define br_json_each_member injected_each_member
#include "../../src/detectors/ipquality.c"
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_json_each_member

static char key[33], other[33];
static const char *fail_cause;
static int fail_cause_dup;

char *strdup(const char *value)
{
    if (fail_cause_dup && fail_cause && !strcmp(value, fail_cause)) {
        fail_cause_dup = 0;
        return NULL;
    }
    size_t size = strlen(value) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_ipquality_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid IPQuality detector output"));
    free(error);
    error = NULL;
    CHECK(!br_ipquality_init(&detector, &error) && detector && !error);
    CHECK(!br_ipquality_init(&again, NULL) && again == detector);
    CHECK(detector->type == 478 && detector->version == 0 && !strcmp(detector->name, "IPQuality"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "IPQualityScore provides tools to detect and prevent fraudulent activity. "
                  "IPQualityScore API keys can be used to access their fraud prevention services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ipquality"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_raw(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1 : 0) && !http.calls && !http.releases);
    if (expected) {
        test_key_result(&results.items[0], 478, expected, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    const char *formats[] = {"ipquality %s", "IPQUALITY '%s'", "prefixipqualitysuffix=%s", "ipquality\r\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        expect_raw(detector, input, strlen(input), key);
    }
    snprintf(input, sizeof(input), "ipquality token = '%s'", key);
    expect_raw(detector, input, strlen(input), key);
    snprintf(input, sizeof(input), "ipquality token = '%s' | '%s'", key, key);
    expect_raw(detector, input, strlen(input), key); /* One keyword is consumed by the first match. */
    snprintf(input, sizeof(input), "ipquality keyword is not close to the real key in the data\n = '%s'", key);
    expect_raw(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "ipquality = '%s'", "p1b3ref1b3gzpn15gduecwvhaat0du5");
    expect_raw(detector, input, strlen(input), NULL);
    expect_raw(detector, key, 32, NULL);
    expect_raw(detector, "", 0, NULL);

    char upper[33];
    memset(upper, 'A', 32);
    upper[32] = '\0';
    snprintf(input, sizeof(input), "IpQuAlItY %s", upper);
    expect_raw(detector, input, strlen(input), upper);

    char changed[33];
    memcpy(changed, key, sizeof(changed));
    changed[8] = '-';
    snprintf(input, sizeof(input), "ipquality %s", changed);
    expect_raw(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "ipquality %sx", key);
    expect_raw(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "ipquality x%s", key);
    expect_raw(detector, input, strlen(input), NULL); /* Word character removes the leading boundary. */
    snprintf(input, sizeof(input), "ipquality.%s", key);
    expect_raw(detector, input, strlen(input), key);

    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ipquality", 9);
        memset(input + 9, '.', gap);
        memcpy(input + 9 + gap, key, 32);
        input[9 + gap + 32] = '\0';
        expect_raw(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    unsigned char binary[48];
    memcpy(binary, "\xffipquality ", 12);
    memcpy(binary + 12, key, 32);
    expect_raw(detector, binary, 44, key);
    unsigned char vt[44];
    memcpy(vt, "ipquality", 9);
    vt[9] = 0x0b;
    memcpy(vt + 10, key, 32);
    expect_raw(detector, vt, 42, key);

    snprintf(input, sizeof(input), "ipquality %s ipquality %s", key, other);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2 && !http.calls && !http.releases);
    test_key_result(&results.items[0], 478, key, "key");
    test_key_result(&results.items[1], 478, other, "key");
    CHECK(!results.items[0].verified && !results.items[1].verified);
    br_results_clear(&results);
}

typedef struct { const char *keys[2]; size_t len; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    const char *secret = expected->keys[http->calls - 1];
    char url[96];
    snprintf(url, sizeof(url), "https://www.ipqualityscore.com/api/json/account/%s", secret);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 478);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog ipquality-test"));
}

static void expect_verified(const br_detector *detector, test_http *http, const char *input,
                            bool verified, const char *error, size_t calls)
{
    expected_requests expected = {{key, other}, calls, };
    int setter_before = setter_after_clean_release;
    release_saw_clean = 0;
    http->calls = http->releases = 0;
    http->inspect = inspect_request;
    http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "ipquality-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == calls && http->releases == calls);
    CHECK(release_saw_clean && setter_after_clean_release == setter_before + 1);
    test_key_result(&results.items[0], 478, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "ipquality %s", key);
    const char *verified_bodies[] = {
        "{\"success\":true}",
        "{\"success\":true,\"message\":\"\"}",
        "{\"success\":true,\"message\":\"insufficient credits\"}",
        "{\"SUCCESS\":true,\"Message\":\"ignored\"}",
        "{\"success\":false,\"success\":true}",
        "{\"success\":true,\"success\":null}",
        "{\"succe\xC5\xBFs\":true}",
    };
    for (size_t i = 0; i < sizeof(verified_bodies) / sizeof(verified_bodies[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {(const unsigned char *)verified_bodies[i], strlen(verified_bodies[i])}}};
        expect_verified(detector, &http, input, true, NULL, 1);
    }

    const char *silent[] = {
        "{}",
        "null",
        "{\"success\":false}",
        "{\"success\":false,\"message\":\"\"}",
        "{\"success\":false,\"message\":\"Invalid or unauthorized key\"}",
        "{\"message\":\"invalid or unauthorized key\"}",
        "{\"message\":\"ok Invalid or unauthorized key!\"}",
    };
    for (size_t i = 0; i < sizeof(silent) / sizeof(silent[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {(const unsigned char *)silent[i], strlen(silent[i])}}};
        expect_verified(detector, &http, input, false, NULL, 1);
    }

    const char *credits[] = {
        "{\"success\":false,\"message\":\"insufficient credits\"}",
        "{\"message\":\"prefix insufficient credits suffix\"}",
        "{\"message\":\"Invalid or unauthorized key insufficient credits\"}",
        "{\"message\":\"insufficient credits\",\"message\":null}",
    };
    for (size_t i = 0; i < sizeof(credits) / sizeof(credits[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {(const unsigned char *)credits[i], strlen(credits[i])}}};
        expect_verified(detector, &http, input, false, "couldn't verify; API Key has insufficient credits", 1);
    }
    static const unsigned char nul_message[] = "{\"message\":\"a\\u0000insufficient credits\"}";
    test_http nul = {.response = {.status = 200, .body = {nul_message, sizeof(nul_message) - 1}}};
    expect_verified(detector, &nul, input, false, "couldn't verify; API Key has insufficient credits", 1);

    const int statuses[] = {201, 204, 401, 403, 429, 500};
    static const unsigned char ignored[] = "{\"success\":true}";
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[48];
        snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {ignored, sizeof(ignored) - 1}, .body_error = "ignored read"}};
        expect_verified(detector, &http, input, false, error, 1);
    }
    test_http read = {.response = {.status = 200, .body = {ignored, sizeof(ignored) - 1}, .body_error = "synthetic read failure"}};
    expect_verified(detector, &read, input, false, "synthetic read failure", 1);

    const char *decode_bodies[] = {"", "s", "{\"success\":true} s", "[]", "{\"success\":1}", "{\"message\":[]}",
                                   "{\"success\":1,\"message\":\"insufficient credits\"}",
                                   "{\"success\":true,\"success\":1}"};
    const char *decode_errors[] = {
        "unexpected end of JSON input",
        "invalid character 's' looking for beginning of value",
        "invalid character 's' after top-level value",
        "json: cannot unmarshal array into Go value of type ipquality.apiResponse",
        "json: cannot unmarshal number into Go struct field apiResponse.success of type bool",
        "json: cannot unmarshal array into Go struct field apiResponse.message of type string",
        "json: cannot unmarshal number into Go struct field apiResponse.success of type bool",
        "json: cannot unmarshal number into Go struct field apiResponse.success of type bool",
    };
    for (size_t i = 0; i < sizeof(decode_bodies) / sizeof(decode_bodies[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {(const unsigned char *)decode_bodies[i], strlen(decode_bodies[i])}}};
        expect_verified(detector, &http, input, false, decode_errors[i], 1);
    }

    char leaked[128];
    snprintf(leaked, sizeof(leaked), "dial tcp %s: no such host", key);
    const char *send_errors[] = {leaked, "context canceled", "out of memory constructing HTTP headers", NULL};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = send_errors[i]};
        expect_verified(detector, &http, input, false, send_errors[i] ? send_errors[i] : "HTTP transport failed", 1);
    }
}

static bool cancelled(void *user)
{
    (void)user;
    return true;
}

static void context_and_resource(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "ipquality %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    test_key_result(&results.items[0], 478, key, "key");
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
                           .deadline_monotonic_ms = deadline ? 1 : 0, .user_agent = "ipquality-test"};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1 && !results.items[0].verified);
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }

    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);

    br_result prior = {0};
    CHECK(!br_finding_key_bytes(&prior, 1, (br_slice){(const unsigned char *)"kept", 4}, "kept"));
    CHECK(!br_results_push(&results, &prior));
    const char *causes[] = {"net/http: nil Context", "unexpected status code: 503",
                            "couldn't verify; API Key has insufficient credits"};
    for (size_t i = 0; i < 3; ++i) {
        http = (test_http){.response = {.status = i == 1 ? 503 : 200,
            .body = {(const unsigned char *)"{\"message\":\"insufficient credits\"}", 34}}};
        transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "ipquality-test"};
        char *error = NULL;
        int setters_before = setter_calls, after_before = setter_after_clean_release;
        release_saw_clean = 0;
        fail_cause = causes[i];
        fail_cause_dup = 1;
        int rc = detector->scan(detector, i ? &ctx : NULL, true,
                                (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
        CHECK(!fail_cause_dup && results.len == 1 && results.items[0].detector_type == 1);
        CHECK(http.calls == (i ? 1 : 0) && http.releases == (i ? 1 : 0));
        CHECK(setter_calls == setters_before + 1);
        CHECK(setter_after_clean_release == after_before + (i ? 1 : 0));
        CHECK(!i || release_saw_clean);
        free(error);
    }
    br_results_clear(&results);
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)"{\"success\":true}", 16}}};
    expect_verified(detector, &http, input, true, NULL, 1);
}

static char mutable_read_error[] = "synthetic read failure";

static void invalidate_release(void *user, br_http_response *response)
{
    test_http_release(user, response);
    memset(mutable_read_error, 'X', sizeof(mutable_read_error) - 1);
}

static void keep_prior(br_results *results)
{
    br_result prior = {0};
    CHECK(!br_finding_key_bytes(&prior, 1, (br_slice){(const unsigned char *)"kept", 4}, "kept"));
    CHECK(!br_results_push(results, &prior));
}

static void order_and_faults(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "ipquality %s", key);
    test_http http = {.response = {.status = 200, .body_error = mutable_read_error}};
    br_transport transport = test_transport(&http);
    transport.release = invalidate_release;
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "ipquality-test"};
    int setters_before = setter_after_clean_release;
    release_saw_clean = 0;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && release_saw_clean);
    CHECK(setter_after_clean_release == setters_before + 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "synthetic read failure"));
    CHECK(mutable_read_error[0] == 'X');
    br_results_clear(&results);

    memcpy(mutable_read_error, "synthetic read failure", sizeof(mutable_read_error));
    keep_prior(&results);
    http = (test_http){.response = {.status = 200, .body_error = mutable_read_error}};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    char *error = NULL;
    int calls_before = setter_calls;
    fail_cause = mutable_read_error;
    fail_cause_dup = 1;
    release_saw_clean = 0;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!fail_cause_dup && setter_calls == calls_before && release_saw_clean);
    CHECK(results.len == 1 && results.items[0].detector_type == 1 && http.calls == 1 && http.releases == 1);
    free(error);
    br_results_clear(&results);

    keep_prior(&results);
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)"{\"success\":true}", 16}}};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport, .user_agent = "ipquality-test"};
    error = NULL;
    calls_before = setter_calls;
    force_null_send_cause = 1;
    release_saw_clean = 0;
    setters_before = setter_after_clean_release;
    rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == 0 && !error && !force_null_send_cause);
    CHECK(results.len == 2 && results.items[0].detector_type == 1 && !results.items[1].verified);
    CHECK(!results.items[1].verification_error && http.calls == 0 && http.releases == 1);
    CHECK(release_saw_clean && setter_calls == calls_before + 1);
    CHECK(setter_after_clean_release == setters_before + 1);
    test_key_result(&results.items[1], 478, key, "key");
    br_results_clear(&results);

    keep_prior(&results);
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)"{\"success\":true}", 16}}};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    error = NULL;
    calls_before = setter_calls;
    force_each_positive = 1;
    release_saw_clean = 0;
    rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!force_each_positive && setter_calls == calls_before && release_saw_clean);
    CHECK(results.len == 1 && results.items[0].detector_type == 1 && http.calls == 1 && http.releases == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 0);
    test_secret(other, 32, 7);
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    context_and_resource(detector);
    order_and_faults(detector);
    return test_finish("IPQuality");
}
