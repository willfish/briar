/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key1[177], key2[177];
static bool fail_status_copy;
static size_t fail_add_after;
typedef struct { const char *const *keys; size_t len; bool fail_second; } expected_requests;

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, "unexpected status code: 503")) {
        fail_status_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

/* Separate finding and verification-setter resource failures, both positive
 * core API errors; normal object ownership stays with add_ex. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_cloudflarecakey_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_cloudflarecakey_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 59 && detector->version == 0 && !strcmp(detector->name, "CloudflareCaKey"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Cloudflare is a web infrastructure and website security company. Cloudflare CA keys can be used to manage SSL/TLS certificates and other security settings."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cloudflare"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_cloudflarecakey_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len, const char *key, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    if (count) {
        test_key_result(&results.items[0], 59, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    CHECK(!strstr(key1, "cloudflare")); expect_extraction(detector, key1, strlen(key1), key1, 1); /* DIRECT, not prefixed. */
    char input[256], changed[179];
    snprintf(input, sizeof(input), "cloudflare %s", key1); expect_extraction(detector, input, strlen(input), key1, 1);
    memcpy(changed, "v1.0-", 5); memset(changed + 5, 'A', 171); changed[176] = 0;
    expect_extraction(detector, changed, 176, changed, 1); /* No entropy, UUID or Base64 validation. */
    changed[175] = 0; expect_extraction(detector, changed, 175, NULL, 0);
    changed[175] = 'A'; changed[176] = 'B'; changed[177] = 0; expect_extraction(detector, changed, 177, NULL, 0);
    memcpy(changed, key1, sizeof(key1)); changed[0] = 'V'; expect_extraction(detector, changed, 176, NULL, 0);
    memcpy(changed, key1, sizeof(key1)); changed[2] = 'X'; expect_extraction(detector, changed, 176, NULL, 0); /* Literal dot. */
    memcpy(changed, key1, sizeof(key1)); changed[50] = '_'; expect_extraction(detector, changed, 176, NULL, 0);
    snprintf(input, sizeof(input), "_%s", key1); expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "%s_", key1); expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key1, sizeof(key1)); changed[175] = '-';
    expect_extraction(detector, changed, 176, NULL, 0); /* '-' is nonword, including at EOF. */
    changed[176] = 'Z'; changed[177] = 0;
    char expected[177]; memcpy(expected, changed, 176); expected[176] = 0;
    expect_extraction(detector, changed, 177, expected, 1); /* Boundary after '-' BEFORE a word byte. */
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 59);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.cloudflare.com/client/v4/certificates?zone_id=a"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 4 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "curl/7.68.0"));
    CHECK(!strcmp(request->headers[2].name, "X-Auth-User-Service-Key"));
    CHECK(strlen(request->headers[2].value) == 176 && !strcmp(request->headers[2].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[3].name, "User-Agent"));
    CHECK(!strcmp(request->headers[3].value, ctx->user_agent ? "TruffleHog cloudflare-ca-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* Logical UA order only, not native wire equivalence. */
    if (expected->fail_second && http->calls == 2) { http->response.status = 503; fail_status_copy = true; }
}

static void uniqueness_and_constructor(const br_detector *detector)
{
    char input[768]; snprintf(input, sizeof(input), "%s;\n%s;\n%s", key1, key2, key1);
    CHECK(key1[5] == 'A' && key2[5] == 'a'); /* Byte uniqueness preserves payload case. */
    const char *keys[] = {key1, key2}; expected_requests expected = {keys, 2, false};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 200}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 2 && http.calls == (mode ? 2u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 2; ++i) {
            test_key_result(&results.items[i], 59, keys[i], "key"); CHECK(results.items[i].verified == (mode == 1));
            if (mode == 2) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, "lookup synthetic.invalid: no such host"));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == 2);
        for (size_t i = 0; i < 2; ++i) {
            test_key_result(&results.items[i], 59, keys[i], "key");
            CHECK(!results.items[i].verified && !results.items[i].verification_error); /* RETAIN, no nil-context error. */
        }
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char cause[768], redacted[512];
    snprintf(cause, sizeof(cause), "url=https://api.cloudflare.com/client/v4/certificates?zone_id=a key=%s again=%s other=%s", key1, key1, key2);
    snprintf(redacted, sizeof(redacted), "url=https://api.cloudflare.com/client/v4/certificates?zone_id=a key=[REDACTED] again=[REDACTED] other=%s", key2);
    const char *keys[] = {key1}; expected_requests expected = {keys, 1, false};
    const struct { int status, send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, 0, NULL, true, NULL}, {401, 0, NULL, false, NULL}, {403, 0, NULL, false, NULL},
        {201, 0, NULL, false, "unexpected status code: 201"}, {204, 0, NULL, false, "unexpected status code: 204"},
        {429, 0, NULL, false, "unexpected status code: 429"}, {500, 0, NULL, false, "unexpected status code: 500"},
        {200, 1, "lookup synthetic.invalid: no such host", false, "lookup synthetic.invalid: no such host"},
        {200, -1, "context canceled", false, "context canceled"}, {200, 9, cause, false, redacted},
        {200, 1, NULL, false, "HTTP transport failed"},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cause},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "cloudflare-ca-test"};
        br_results results = test_scan(detector, &ctx, true, key1, strlen(key1));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); test_key_result(&results.items[0], 59, key1, "key");
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        if (cases[i].send_error == cause) {
            CHECK(!strstr(results.items[0].verification_error, key1) && strstr(results.items[0].verification_error, key2));
        }
        br_results_clear(&results);
    }
}

typedef struct { test_http http; char *cause_alias; } scrub_http;
static int scrub_send(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    scrub_http *scrub = user;
    int rc = test_http_send(&scrub->http, ctx, request, response, error);
    scrub->cause_alias = *error;
    return rc;
}
static void scrub_release(void *user, br_http_response *response)
{
    scrub_http *scrub = user;
    CHECK(scrub->cause_alias);
    memset(scrub->cause_alias, '!', strlen(scrub->cause_alias));
    test_http_release(&scrub->http, response);
}
static void cause_owned_before_release(const br_detector *detector)
{
    char cause[256]; snprintf(cause, sizeof(cause), "synthetic key=%s", key1);
    const char *keys[] = {key1}; expected_requests expected = {keys, 1, false};
    scrub_http scrub = {.http = {.send_rc = 1, .send_error = cause, .inspect = inspect_request, .user = &expected}};
    br_transport transport = {&scrub, scrub_send, scrub_release}; br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, key1, strlen(key1));
    CHECK(results.len == 1 && scrub.http.calls == 1 && scrub.http.releases == 1);
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, "synthetic key=[REDACTED]"));
    br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }
static void contexts(const br_detector *detector)
{
    const char *keys[] = {key1}; expected_requests expected = {keys, 1, false};
    for (int deadline = 0; deadline <= 1; ++deadline) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .cancelled = deadline ? NULL : cancelled, .deadline_monotonic_ms = deadline ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, key1, strlen(key1));
        CHECK(results.len == 1 && !http.calls && http.releases == 1); test_key_result(&results.items[0], 59, key1, "key");
        CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, deadline ? "context deadline exceeded" : "context canceled"));
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_status_copy = true;
    CHECK(br_result_set_verification_error(&probe, "unexpected status code: 503", NULL, 0) == 1 && !fail_status_copy);
    fail_add_after = 1;
    CHECK(br_finding_key_bytes(&probe, 59, (br_slice){(const unsigned char *)key1, 176}, "key") != 0 && !fail_add_after);
    br_result_clear(&probe); CHECK(br_results_push(NULL, &probe) == 1);
    char input[768]; snprintf(input, sizeof(input), "%s;\n%s;\n%s", key1, key2, key1);
    const char *keys[] = {key1, key2}; expected_requests expected = {keys, 2, true};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory recording Cloudflare CA key verification error"));
    CHECK(!fail_status_copy && http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL;
    expected.fail_second = false; http.calls = http.releases = 0; http.response.status = 200; fail_add_after = 2;
    rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Cloudflare CA key result"));
    CHECK(!fail_add_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].raw.data == original_raw && results.items[0].verification_error == original_error);
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) { test_key_result(&results.items[i], 59, keys[i], "key"); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    static const char alphabet[] = "Ab9C-dE7fG5hJ3kL1mN0pQrStUvWxYz";
    memcpy(key1, "v1.0-", 5);
    for (size_t i = 0; i < 171; ++i) key1[5 + i] = alphabet[i % (sizeof(alphabet) - 1)];
    key1[175] = 'Z'; key1[176] = 0; memcpy(key2, key1, sizeof(key1)); key2[5] = 'a';
    CHECK(strlen(key1) == 176 && strlen(key2) == 176);
    const br_detector *detector = descriptor();
    extraction(detector); uniqueness_and_constructor(detector); statuses_and_errors(detector); cause_owned_before_release(detector);
    contexts(detector); resource_rollback(detector);
    return test_finish("CloudflareCaKey");
}
