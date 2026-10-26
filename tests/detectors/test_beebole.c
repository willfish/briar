/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char key[41], other_key[41], z_key[41];
static bool fail_503_dup;

/* One positive core setter failure must remain a resource error. */
char *strdup(const char *value)
{
    if (fail_503_dup && !strcmp(value, "unexpected status code: 503")) {
        fail_503_dup = false;
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
    CHECK(br_beebole_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid Beebole detector output")); free(error); error = NULL;
    CHECK(!br_beebole_init(&detector, &error) && detector && !error);
    CHECK(!br_beebole_init(&again, NULL) && again == detector);
    CHECK(detector->type == 684 && detector->version == 0 && !strcmp(detector->name, "Beebole"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Beebole is a time tracking and business management tool. Beebole API keys can be used to access and manage time tracking data and other business-related information."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "beebole"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1 : 0) && !http.calls && !http.releases);
    if (expected) {
        test_key_result(&results.items[0], 684, expected, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[43];
    const char *formats[] = {"beebole %s", "BEEBOLE '%s'", "prefixbeebolesuffix=%s", "beebole\r\n%s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extraction_case(detector, input, key);
    }
    snprintf(input, sizeof(input), "beebole %s", z_key);
    extraction_case(detector, input, z_key); /* Lowercase g-z is valid, not just hex; no entropy rule. */
    extraction_case(detector, key, NULL);
    extraction_case(detector, "", NULL);
    const char *invalid[] = {"beebole _%s", "beebole %s_", "beebole %sx", "beebole %.39s"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        snprintf(input, sizeof(input), invalid[i], key);
        extraction_case(detector, input, NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[20] = 'G';
    snprintf(input, sizeof(input), "BEEBOLE %s", changed);
    extraction_case(detector, input, NULL); /* Case-insensitivity ends after the PREFIX. */
    changed[20] = '-';
    snprintf(input, sizeof(input), "beebole %s", changed);
    extraction_case(detector, input, NULL);
    memcpy(changed, key, 40); memcpy(changed + 40, "==", 3);
    snprintf(input, sizeof(input), "beebole %s", changed);
    extraction_case(detector, input, key); /* Delimiter/padding is not part of the fixed key. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "beebole", 7); memset(input + 7, '.', gap);
        snprintf(input + 7 + gap, sizeof(input) - 7 - gap, "%s", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
}

typedef struct { const char *keys[4]; size_t len; const int *statuses; } expected_requests;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && http->releases + 1 == http->calls);
    const char *secret = expected->keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://beebole-apps.com/api/v2"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 684);
    static const unsigned char payload[] = "{\"service\": \"custom_field.list\"}";
    CHECK(request->body.data && request->body.len == sizeof(payload) - 1);
    CHECK(!memcmp(request->body.data, payload, sizeof(payload) - 1)); /* Exact colon SPACE, opaque bytes. */
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3); /* No explicit Content-Length or Accept. */
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    /* Independent Base64 checks USERNAME=key, PASSWORD=literal x, not reversed
     * credentials or an empty username. 40 + ':' + 'x' is 42 bytes. */
    unsigned char credentials[42], encoded[57];
    memcpy(credentials, secret, 40); credentials[40] = ':'; credentials[41] = 'x';
    CHECK(EVP_EncodeBlock(encoded, credentials, sizeof(credentials)) == 56);
    CHECK(strlen(request->headers[1].value) == 62 && !memcmp(request->headers[1].value, "Basic ", 6));
    CHECK(!strcmp(request->headers[1].value + 6, (const char *)encoded));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog beebole-test"));
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
}

static void occurrences(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "beebole %s\nBEEBOLE %s\nbeebole %s\nbeebole %s", key, other_key, key, z_key);
    const int statuses[] = {200, 401, 200, 200};
    expected_requests expected = {{key, other_key, key, z_key}, 4, statuses};
    test_http http = {.response = {.body_error = "ignored drain/close failure"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "beebole-test"};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
        CHECK(results.len == 4 && http.calls == (verify ? 4 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 4; ++i) {
            test_key_result(&results.items[i], 684, expected.keys[i], "key");
            CHECK(results.items[i].verified == (verify && statuses[i] == 200) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    } /* Verified occurrences never consume, deduplicate or stop later matches. */
}

static void verify_case(const br_detector *detector, test_http *http, bool verified, const char *error)
{
    char input[64]; snprintf(input, sizeof(input), "beebole %s", key);
    expected_requests expected = {{key}, 1, NULL};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &expected;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "beebole-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    test_key_result(&results.items[0], 684, key, "key");
    CHECK(results.items[0].verified == verified);
    if (error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, error));
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    const int statuses[] = {200, 401, 201, 204, 299, 403, 302, 500};
    static const unsigned char body[] = {0xff, 0, '{', '?'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char error[80]; snprintf(error, sizeof(error), "unexpected status code: %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored read/drain error"}};
        verify_case(detector, &http, statuses[i] == 200, i < 2 ? NULL : error);
    }
    const char *errors[] = {"lookup synthetic: no such host", "context canceled", "unsupported: redirects for native HTTP POST", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = errors[i]};
        verify_case(detector, &http, false, errors[i] ? errors[i] : "HTTP transport failed");
    } /* Exactly one SANE POST each; no DNS suppression or GET/LOCAL fallback. */
    test_http dns = {.send_rc = 1, .send_error = "lookup synthetic: no such host"};
    verify_case(detector, &dns, false, dns.send_error);
    verify_case(detector, &dns, false, dns.send_error);
    char cause[256], redacted[256];
    snprintf(cause, sizeof(cause), "key=%s url=https://beebole-apps.com/api/v2 again=%s other=%s", key, key, other_key);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] url=https://beebole-apps.com/api/v2 again=[REDACTED] other=%s", other_key);
    test_http http = {.send_rc = 1, .send_error = cause};
    verify_case(detector, &http, false, redacted);
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "beebole %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified); /* Retain nil-context creation errors. */
    test_key_result(&results.items[0], 684, key, "key");
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&results);
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    for (int deadline = 0; deadline <= 1; ++deadline) {
        http.calls = http.releases = 0;
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled,
            .deadline_monotonic_ms = deadline ? 1 : 0};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == 1 && !results.items[0].verified);
        test_key_result(&results.items[0], 684, key, "key");
        CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error,
              deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
    expected_requests expected = {{key}, 1, NULL};
    http = (test_http){.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "beebole-test"};
    char *error = NULL;
    fail_503_dup = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory sanitizing verification error"));
    CHECK(!fail_503_dup && !results.len && http.calls == 1 && http.releases == 1);
    free(error); br_results_clear(&results);
    http = (test_http){.response = {.status = 503}};
    verify_case(detector, &http, false, "unexpected status code: 503");
}

int main(void)
{
    test_secret(key, 40, 0); test_secret(other_key, 40, 13);
    memset(z_key, 'z', 40); z_key[40] = '\0';
    const br_detector *detector = descriptor();
    extraction(detector);
    occurrences(detector);
    verification(detector);
    context_and_resource(detector);
    return test_finish("Beebole");
}
