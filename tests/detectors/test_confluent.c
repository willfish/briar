/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

/* Synthetic sequences only. Goldens independently generated with Python's
 * base64.b64encode((key + ':' + secret).encode('ascii')). */
static const char key1[] = "AbCdEfGhIjKlMn09";
static const char key2[] = "zYxWvUtSrQpOnM87";
static const char secret1[] = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGhIjKlMnOpQrStUvWxYz";
static const char secret2[] = "ZZZZZZZZZZZZZZZZ" "ZZZZZZZZZZZZZZZZ" "ZZZZZZZZZZZZZZZZ" "ZZZZZZZZZZZZZZZZ";
static const char *const goldens[2][2] = {
    {"Basic QWJDZEVmR2hJaktsTW4wOTpBYkNkRWZHaElqS2xNbk9wUXJTdFV2V3hZejAxMjM0NTY3ODkrL0FiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFl6",
     "Basic QWJDZEVmR2hJaktsTW4wOTpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpa"},
    {"Basic ell4V3ZVdFNyUXBPbk04NzpBYkNkRWZHaElqS2xNbk9wUXJTdFV2V3hZejAxMjM0NTY3ODkrL0FiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFl6",
     "Basic ell4V3ZVdFNyUXBPbk04NzpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpa"},
};
static const char separation[] = "\n................................................\n";
static size_t encoder_calls, fail_encoder_after, fail_part_after;
static size_t fail_alloc_size, fail_alloc_after, allocation_failures;

/* Test-only native encoder fault and call-order observation. Normal calls use
 * OpenSSL's streaming codec, with its line breaks removed, and match Python
 * goldens below. No provider auth allocation seam or shared helper is added. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls;
    CHECK(len == 81 && in[16] == ':');
    if (fail_encoder_after && --fail_encoder_after == 0) return 1;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[112]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx);
    CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail);
    EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 108); out[at] = '\0';
    return (int)at;
}

/* Actual capture/finding/shared-send resources, never heap auth copies. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 16 && strlen(key2) == 16 && strlen(secret1) == 64 && strlen(secret2) == 64);
    CHECK(br_confluent_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Confluent detector output")); free(error); error = NULL;
    CHECK(!br_confluent_init(&detector, &error) && detector && !error);
    CHECK(!br_confluent_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 60 && detector->version == 0 && !strcmp(detector->name, "Confluent") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Confluent provides a streaming platform based on Apache Kafka to help companies harness their data in real-time. Confluent API keys can be used to access and manage Kafka clusters."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "confluent"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, const char *secret, bool verified)
{
    CHECK(result->detector_type == 60 && !result->detector_name);
    CHECK(result->raw.len == 16 && !memcmp(result->raw.data, key, 16));
    CHECK(result->raw_v2.len == 80 && !memcmp(result->raw_v2.data, key, 16) && !memcmp(result->raw_v2.data + 16, secret, 64));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 16 && !memcmp(json_object_get_string(part), key, 16));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 64 && !memcmp(json_object_get_string(part), secret, 64));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static void expect_pair(const br_detector *detector, const char *input, const char *key, const char *secret)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (key ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (key) check_result(&results.items[0], key, secret, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[1600], changed[66], key[18];
    snprintf(input, sizeof(input), "CoNfLuEnT %s%sconfluent %s", key1, separation, secret1); expect_pair(detector, input, key1, secret1);
    snprintf(input, sizeof(input), "preCoNfLuEnTsuffix\r\n%s%sconfluent\r\n%s", key2, separation, secret2); expect_pair(detector, input, key2, secret2);
    snprintf(input, sizeof(input), "confluent %s %s", key1, secret1); expect_pair(detector, input, key1, secret1); /* Independent patterns can use the same prefix. */
    snprintf(input, sizeof(input), "%s%sconfluent %s", key1, separation, secret1); expect_pair(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "confluent %s%s%s", key1, separation, secret1); expect_pair(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "confluent %s", key1); expect_pair(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "confluent %s", secret1); expect_pair(detector, input, NULL, NULL);
    const char *bad_keys[] = {"AbCdEfGhIjKlMn0", "AbCdEfGhIjKlMn09X", "_AbCdEfGhIjKlMn09", "AbCdEfGhIjKlMn09_", "confluentAbCdEfGhIjKlMn09"};
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        snprintf(input, sizeof(input), "confluent %s%sconfluent %s", bad_keys[i], separation, secret1); expect_pair(detector, input, NULL, NULL);
    }
    memcpy(key, key1, sizeof(key1)); key[8] = '+';
    snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key, separation, secret1); expect_pair(detector, input, NULL, NULL);
    key[8] = '/'; snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key, separation, secret1); expect_pair(detector, input, NULL, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "confluent%*s%s%sconfluent %s", gap, "", key1, separation, secret1); expect_pair(detector, input, gap == 40 ? key1 : NULL, secret1);
        snprintf(input, sizeof(input), "confluent %s%sconfluent%*s%s", key1, separation, gap, "", secret1); expect_pair(detector, input, gap == 40 ? key1 : NULL, secret1);
    }
    memcpy(changed, secret1, sizeof(secret1)); changed[63] = '\0';
    snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key1, separation, changed); expect_pair(detector, input, NULL, NULL);
    snprintf(changed, sizeof(changed), "%sA", secret1);
    snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key1, separation, changed); expect_pair(detector, input, NULL, NULL);
    memcpy(changed, secret1, sizeof(secret1)); changed[20] = '=';
    snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key1, separation, changed); expect_pair(detector, input, NULL, NULL);
    changed[20] = '_'; snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key1, separation, changed); expect_pair(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "confluent %s%sconfluent %s=", key1, separation, secret1); expect_pair(detector, input, key1, secret1); /* '=' OUTSIDE the capture remains a boundary, not padding in RawV2. */
    for (size_t symbol = 0; symbol < 2; ++symbol) {
        memset(changed, 'a', 64); changed[64] = '\0'; changed[0] = symbol ? '/' : '+';
        snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key1, separation, changed); expect_pair(detector, input, NULL, NULL);
        snprintf(input, sizeof(input), "confluent %s%sconfluent x%s", key1, separation, changed); expect_pair(detector, input, key1, changed);
        changed[0] = 'a'; changed[63] = symbol ? '/' : '+';
        snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key1, separation, changed); expect_pair(detector, input, NULL, NULL);
        snprintf(input, sizeof(input), "confluent %s%sconfluent %sx", key1, separation, changed); expect_pair(detector, input, key1, changed);
    }
    memset(changed, '+', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "confluent %s%sconfluent x%sx", key1, separation, changed); expect_pair(detector, input, key1, changed); /* No semantic Base64/entropy validation. */
    snprintf(input, sizeof(input), "confluent %s%1100sconfluent %s", key1, "", secret1); expect_pair(detector, input, key1, secret1); /* The span is an engine hint, not a detector pairing restriction. */
}

typedef struct {
    const char *const *keys, *const *secrets;
    size_t nkeys, nsecrets;
    const br_scan_ctx *ctx;
    const char *borrowed_url, *borrowed_auth, *expected_auth;
    char expected_url[80];
} expected_requests;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user; size_t at = http->calls - 1;
    CHECK(at < expected->nkeys * expected->nsecrets && ctx == expected->ctx && http->releases == at);
    const char *key = expected->keys[at / expected->nsecrets], *secret = expected->secrets[at % expected->nsecrets];
    CHECK(!strcmp(key, key1) || !strcmp(key, key2)); CHECK(!strcmp(secret, secret1) || !strcmp(secret, secret2));
    expected->expected_auth = goldens[!strcmp(key, key2)][!strcmp(secret, secret2)];
    CHECK(request->detector_type == 60 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    int n = snprintf(expected->expected_url, sizeof(expected->expected_url), "https://api.confluent.cloud/iam/v2/api-keys/%s", key);
    CHECK(n > 0 && (size_t)n < sizeof(expected->expected_url) && !strcmp(request->url, expected->expected_url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog confluent-test" : "TruffleHog")); /* No Type/Accept/logical Content-Length. */
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 114 && auth[114] == '\0' && !strcmp(auth, expected->expected_auth) && !strchr(auth, '='));
    unsigned char decoded[82]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 108) == 81);
    CHECK(!memcmp(decoded, key, 16) && decoded[16] == ':' && !memcmp(decoded + 17, secret, 64)); /* TRUE Basic, not KEY alone. */
    expected->borrowed_url = request->url; expected->borrowed_auth = auth;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_requests *expected = http->user;
    CHECK(expected->borrowed_url && !strcmp(expected->borrowed_url, expected->expected_url));
    CHECK(expected->borrowed_auth && strlen(expected->borrowed_auth) == 114 && !strcmp(expected->borrowed_auth, expected->expected_auth));
    expected->borrowed_url = expected->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void products_and_nil(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "confluent %s\nconfluent %s\nconfluent %s%sconfluent %s\nconfluent %s\nconfluent %s", secret1, secret2, secret1, separation, key1, key2, key1);
    const char *keys[] = {key1, key2, key1}, *secrets[] = {secret1, secret2, secret1};
    for (int mode = 0; mode < 3; ++mode) {
        expected_requests expected = {.keys = keys, .secrets = secrets, .nkeys = 3, .nsecrets = 3};
        test_http http = {.response = {.status = 204}, .inspect = inspect, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.ctx = &ctx;
        size_t before = encoder_calls;
        br_results results = test_scan(detector, mode == 2 ? NULL : &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == (mode == 2 ? 0u : 9u));
        CHECK(http.calls == (mode == 1 ? 9u : 0u) && http.releases == http.calls && encoder_calls == before + (mode ? 9u : 0u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], secrets[i % 3], mode == 1);
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key2, separation, secret1);
    const char *keys[] = {key2}, *secrets[] = {secret1};
    const struct { int status, rc; const char *error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {503, 0, NULL, false},
        {200, 1, "net/http: nil Context", false}, {200, -1, "out of memory constructing HTTP headers", false},
        {200, 9, "Confluent native Base64 encoding failed", false}, {200, 1, "cannot create Confluent result", false},
        {200, -1, "synthetic Do error key=zYxWvUtSrQpOnM87", false}, {200, 1, NULL, false},
    };
    static const unsigned char body[] = {0xff, 0, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expected_requests expected = {.keys = keys, .secrets = secrets, .nkeys = 1, .nsecrets = 1};
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = "synthetic ignored read error"}, .send_rc = cases[i].rc, .send_error = cases[i].error, .inspect = inspect, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "confluent-test"}; expected.ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], key2, secret1, cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user; fail_alloc_size = 2 * sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "confluent %s%sconfluent %s", key1, separation, secret1);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
                           .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
                           .deadline_monotonic_ms = mode == 2 ? 1 : 0, .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        size_t before = encoder_calls, failures = allocation_failures;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u) && encoder_calls == before + 1);
        CHECK(!fail_alloc_after && allocation_failures == failures + (mode == 4 ? 1u : 0u));
        check_result(&results.items[0], key1, secret1, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned") && results->items[0].secret_parts == parts);
    br_json *part = NULL; CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[320]; snprintf(input, sizeof(input), "confluent %s%sconfluent %s\nconfluent %s", key1, separation, secret1, secret2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    const char *keys[] = {key1}, *secrets[] = {secret1, secret2};
    for (int mode = 0; mode < 3; ++mode) {
        expected_requests expected = {.keys = keys, .secrets = secrets, .nkeys = 1, .nsecrets = 2};
        test_http http = {.response = {.status = 200}, .inspect = inspect, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key"));
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior));
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
        size_t before = encoder_calls; fail_part_after = 4; /* Secret-part +1 on the SECOND product. */
        int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, "cannot create Confluent result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && encoder_calls == before + (mode ? 1u : 0u));
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        /* Both regex passes return positive +1 on scratch allocation failure;
         * capture copies fail separately. Every nonzero is normalized to -1. */
        const struct { size_t size, after; const char *error; } captures[] = {
            {2 * sizeof(br_span), 1, "out of memory iterating regex"}, {2 * sizeof(br_span), 2, "out of memory iterating regex"},
            {17, 1, "out of memory copying detector capture"}, {65, 1, "out of memory copying detector capture"},
        };
        for (size_t i = 0; i < sizeof(captures) / sizeof(captures[0]); ++i) {
            fail_alloc_size = captures[i].size; fail_alloc_after = captures[i].after; before = encoder_calls;
            rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !strcmp(error, captures[i].error) && !fail_alloc_after && encoder_calls == before);
            check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        }
        if (mode) {
            http.calls = http.releases = 0; before = encoder_calls; fail_encoder_after = 2;
            rc = detector->scan(detector, mode == 2 ? NULL : &ctx, true, data, &results, &error);
            CHECK(rc == -1 && error && !strcmp(error, "Confluent native Base64 encoding failed") && !fail_encoder_after && encoder_calls == before + 2);
            CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls);
            check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        } else {
            fail_alloc_size = 80; fail_alloc_after = 2; before = encoder_calls;
            rc = detector->scan(detector, &ctx, false, data, &results, &error);
            CHECK(rc == -1 && error && !strcmp(error, "cannot create Confluent result") && !fail_alloc_after && encoder_calls == before);
            check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        }
        br_results_clear(&results);
    }
    /* Resource faults must not poison later valid invocations. */
    expected_requests expected = {.keys = keys, .secrets = secrets, .nkeys = 1, .nsecrets = 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], key1, secrets[i], true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); products_and_nil(detector); statuses_and_errors(detector);
    shared_setup_errors(detector); resources_and_rollback(detector);
    return test_finish("Confluent occurrence products + symbol boundaries + true Basic + pre-constructor encoder + own rollback");
}
