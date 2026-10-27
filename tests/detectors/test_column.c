/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

/* Public synthetic sequences. Goldens independently generated with Python's
 * standard base64.b64encode, not the provider's encoder/auth helper. */
static const char key1[] = "test_AbCdEfGhIjKlMnOpQrStUvWxYz0";
static const char key2[] = "live_ZyXwVuTsRqPoNmLkJiHgFeDcBa9";
static const char golden1[] = "Basic dGVzdF9BYkNkRWZHaElqS2xNbk9wUXJTdFV2V3hZejA=";
static const char golden2[] = "Basic bGl2ZV9aeVh3VnVUc1JxUG9ObUxrSmlIZ0ZlRGNCYTk=";
static size_t fail_add_after;
typedef struct { const char *const *keys; size_t len; } expected_requests;

/* Real positive +1 finding-part failure, including before a constructor skip.
 * No artificial auth-allocation seam; normal ownership stays with add_ex. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_column_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_column_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 749 && detector->version == 0 && !strcmp(detector->name, "Column"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Column is a service used for managing entity data. Column keys can be used to access and modify this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "column"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_column_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len, const char *key, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    if (count) {
        test_key_result(&results.items[0], 749, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[34];
    expect_extraction(detector, key1, 32, NULL, 0); /* Prefix required, not bare-key dispatch. */
    snprintf(input, sizeof(input), "column = '%s'", key1); expect_extraction(detector, input, strlen(input), key1, 1);
    snprintf(input, sizeof(input), "CoLuMn\r\n%s", key2); expect_extraction(detector, input, strlen(input), key2, 1);
    memcpy(changed, key1, sizeof(key1)); changed[0] = 'T';
    snprintf(input, sizeof(input), "COLUMN %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0); /* Keyword CI, literal test_ is not. */
    memcpy(changed, key2, sizeof(key2)); changed[0] = 'L';
    snprintf(input, sizeof(input), "column %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key1, sizeof(key1)); changed[31] = 0;
    snprintf(input, sizeof(input), "column %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    memcpy(changed, key1, sizeof(key1)); changed[32] = 'A'; changed[33] = 0;
    snprintf(input, sizeof(input), "column %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    const char disallowed[] = {'_', '-', '.'};
    for (size_t i = 0; i < sizeof(disallowed); ++i) {
        memcpy(changed, key1, sizeof(key1)); changed[15] = disallowed[i];
        snprintf(input, sizeof(input), "column %s", changed); expect_extraction(detector, input, strlen(input), NULL, 0);
    }
    snprintf(input, sizeof(input), "column _%s", key1); expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "column %s_", key2); expect_extraction(detector, input, strlen(input), NULL, 0);
    snprintf(input, sizeof(input), "column-%s-", key2); expect_extraction(detector, input, strlen(input), key2, 1);
    memcpy(changed, "live_", 5); memset(changed + 5, 'A', 27); changed[32] = 0;
    snprintf(input, sizeof(input), "column %s", changed); expect_extraction(detector, input, strlen(input), changed, 1); /* No entropy filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, '.', gap); padding[gap] = 0;
        snprintf(input, sizeof(input), "column%s%s", padding, key2);
        expect_extraction(detector, input, strlen(input), key2, gap == 40 ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 749);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.column.com/entities"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *key = expected->keys[http->calls - 1], *auth = request->headers[0].value;
    CHECK(!strcmp(key, key1) || !strcmp(key, key2));
    CHECK(strlen(auth) == 50 && auth[50] == '\0' && !memcmp(auth, "Basic ", 6));
    CHECK(!strcmp(auth, !strcmp(key, key1) ? golden1 : golden2));
    CHECK(auth[49] == '=' && auth[48] != '='); /* Exactly one padding byte: KEY32, not KEY:33. */
    unsigned char decoded[36]; int n = EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 44);
    CHECK(n == 33 && n - 1 == 32); /* DecodeBlock includes the single zero padding byte. */
    CHECK(!memcmp(decoded, key, 32) && decoded[32] == 0 && !memchr(decoded, ':', 32));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog column-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source scan-deferred close-only. */
}

static void occurrences_and_skip(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "column %s;\nCOLUMN %s;\ncolumn %s", key1, key2, key1);
    const char *keys[] = {key1, key2, key1}; expected_requests expected = {keys, 3};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 3 && http.calls == (mode ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) {
            test_key_result(&results.items[i], 749, keys[i], "key");
            CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        /* Direct detector extraction retains test_ too. CLI's global badlist
         * filtering is parent-owned and must not be copied into this provider. */
        br_results results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < results.len; ++i) {
            test_key_result(&results.items[i], 749, keys[i], "key"); CHECK(!results.items[i].verified && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char input[128], sensitive[128]; snprintf(input, sizeof(input), "column %s", key2);
    snprintf(sensitive, sizeof(sensitive), "synthetic key=%s", key2);
    const char *keys[] = {key2}; expected_requests expected = {keys, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {200, 1, "out of memory constructing HTTP headers", false},
        {200, 1, "unsupported: native HTTP client configuration", false}, {200, 1, NULL, false},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "column-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); test_key_result(&results.items[0], 749, key2, "key");
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void contexts(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "column %s", key2);
    const char *keys[] = {key2}; expected_requests expected = {keys, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); test_key_result(&results.items[0], 749, key2, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_add_after = 1;
    CHECK(br_finding_key_bytes(&probe, 749, (br_slice){(const unsigned char *)key2, 32}, "key") != 0 && !fail_add_after);
    CHECK(!probe.raw.data && !probe.secret_parts); br_result_clear(&probe); CHECK(br_results_push(NULL, &probe) == 1);
    char input[256]; snprintf(input, sizeof(input), "column %s;\ncolumn %s", key1, key2);
    const char *keys[] = {key1, key2}; expected_requests expected = {keys, 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_add_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Column result"));
    CHECK(!fail_add_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL;
    fail_add_after = 1;
    rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Column result"));
    CHECK(!fail_add_after && results.len == 1 && http.calls == 1 && http.releases == 1);
    CHECK(results.items[0].raw.data == original_raw && results.items[0].verification_error == original_error);
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) { test_key_result(&results.items[i], 749, keys[i], "key"); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 32 && strlen(key2) == 32 && strlen(golden1) == 50 && strlen(golden2) == 50);
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_skip(detector); statuses_and_errors(detector); contexts(detector); resource_rollback(detector);
    return test_finish("Column");
}
