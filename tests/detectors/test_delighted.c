/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <openssl/evp.h>

static const char key1[] = "G7h9J2k5M6n8P3q4R1s0T2u5V7w9X2y4";
static const char key2[] = "Z9y8X7w6V5u4T3s2R1q0P9n8M7k6J5h4";
/* Independent standard-Base64(KEY + ':') goldens: 33 bytes, no padding. */
static const char *const goldens[] = {
    "Basic RzdoOUoyazVNNm44UDNxNFIxczBUMnU1Vjd3OVgyeTQ6",
    "Basic Wjl5OFg3dzZWNXU0VDNzMlIxcTBQOW44TTdrNko1aDQ6",
};
static const unsigned char payload[] =
    "{\n"
    "\t\t\t\t\"email\": \"jony@appleseed.com\",\n"
    "\t\t\t\t\"properties\": { \"Purchase Experience\": \"Mobile App\", \"State\": \"CA\" }\n"
    "\t\t\t\t}";
static size_t encoder_calls, fail_encoder_after, fail_alloc_size, fail_alloc_after, fail_part_after;
static int encoder_failure;

/* Observe/fail the existing native codec boundary, not a new production seam.
 * Normal calls use OpenSSL's streaming codec and the independent goldens. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls;
    CHECK(len == 33 && in[32] == ':');
    size_t which = !memcmp(in, key1, 32) ? 0 : 1;
    CHECK(!memcmp(in, which ? key2 : key1, 32));
    if (fail_encoder_after && --fail_encoder_after == 0) return encoder_failure;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[80]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx);
    CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail);
    EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i)
        if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 44 && !memchr(out, '=', at));
    out[at] = '\0';
    CHECK(!memcmp(out, goldens[which] + 6, 45));
    return (int)at;
}

void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key1) == 32 && strlen(key2) == 32 && sizeof(payload) - 1 == 115);
    CHECK(br_delighted_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Delighted detector output"));
    free(error); error = NULL;
    CHECK(br_delighted_init(NULL, NULL) == -1);
    CHECK(br_delighted_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_delighted_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 237 && detector->version == 0 && !strcmp(detector->name, "Delighted"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Delighted is a customer feedback platform. Delighted API keys can be used to access and manage customer feedback data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "delighted"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    /* The source default constructor is enabled. Registry/CLI integration is parent-owned. */
    return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 237, key, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), key, 32));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls;
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    const struct { const char *format; bool matches; } cases[] = {
        {"delighted '%s'", true}, {"DELIGHTED=%s", true}, {"preDeLiGhTeDsuffix\r\n%s", true},
        {"delighted\r%s", true}, {"delighted\n%s", true}, {"delighted +%s/", true},
        {"%s", false}, {"%s delighted", false}, {"de lighted %s", false}, {"delighted%s", false},
        {"delighted x%s", false}, {"delighted _%s", false}, {"delighted %s_", false},
        {"delighted %s9", false}, {"delighted %.31s", false},
    };
    char input[224], changed[33];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key1);
        extraction_case(detector, input, strlen(input), cases[i].matches ? key1 : NULL);
    }
    const char forbidden[] = "_-+./";
    for (size_t i = 0; i < sizeof(forbidden) - 1; ++i) {
        memcpy(changed, key1, sizeof(key1)); changed[15] = forbidden[i];
        snprintf(input, sizeof(input), "delighted %s", changed);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "delighted", 9); memset(input + 9, '.', gap); memcpy(input + 9 + gap, key1, 32);
        extraction_case(detector, input, 9 + gap + 32, gap == 40 ? key1 : NULL);
    }
    memset(changed, 'Z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "delighted %s", changed);
    extraction_case(detector, input, strlen(input), changed); /* Mixed alnum, not hex; no entropy/FP filter. */
    snprintf(input, sizeof(input), "delighted %s %s", key1, key2);
    extraction_case(detector, input, strlen(input), key1); /* Whole matches do not overlap. */
    int n = snprintf(input, sizeof(input), "delighted%c%s", 0, key1);
    CHECK(n == 42); extraction_case(detector, input, (size_t)n, key1);
    n = snprintf(input, sizeof(input), "\xff\ndelighted %s\n\xff", key1);
    extraction_case(detector, input, (size_t)n, key1); /* No invented global UTF-8 guard. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct {
    const char *keys[3]; size_t count;
    const char *agent, *borrowed_auth, *expected_auth;
    br_slice borrowed_body;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; size_t at = http->calls - 1;
    CHECK(at < expected->count && ctx && ctx->transport && !expected->borrowed_auth);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.delighted.com/v1/people.json"));
    CHECK(request->detector_type == 237 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->body.len == 115 && !memcmp(request->body.data, payload, 115) && request->body.data[114] == '}');
    CHECK(request->nheaders == 3); /* Type, Basic, shared UA only; no Accept/invented CL. */
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    const char *auth = request->headers[1].value;
    size_t which = !strcmp(expected->keys[at], key1) ? 0 : 1;
    CHECK(strlen(auth) == 50 && !memchr(auth, '=', 50) && !memcmp(auth, goldens[which], 51));
    unsigned char decoded[33];
    CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 44) == 33);
    CHECK(!memcmp(decoded, expected->keys[at], 32) && decoded[32] == ':'); /* Truly empty password. */
    expected->borrowed_auth = auth; expected->expected_auth = goldens[which]; expected->borrowed_body = request->body;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected->borrowed_auth) {
        CHECK(strlen(expected->borrowed_auth) == 50 && !memcmp(expected->borrowed_auth, expected->expected_auth, 51));
        CHECK(expected->borrowed_body.len == 115 && !memcmp(expected->borrowed_body.data, payload, 115));
        expected->borrowed_auth = NULL; expected->borrowed_body = (br_slice){0};
    } else {
        CHECK(!response->status && !response->body.data && !response->body_error);
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[192]; int n = snprintf(input, sizeof(input), "delighted %s\nDELIGHTED %s\ndelighted %s", key1, key2, key1);
    expected_http expected = {.keys = {key1, key2, key1}, .count = 3, .agent = "TruffleHog delighted-offline"};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "delighted-offline"};
    for (int pass = 0; pass < 3; ++pass) {
        size_t before = encoder_calls;
        br_results results = test_scan(detector, &ctx, pass != 0, input, (size_t)n);
        CHECK(results.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        CHECK(encoder_calls == before + (pass ? 3u : 0u) && !expected.borrowed_auth);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], pass != 0);
        br_results_clear(&results); http.calls = http.releases = 0;
    } /* Preserve duplicates and repeated scans; no verification cache. */
    size_t before = encoder_calls;
    br_results results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(!results.len && encoder_calls == before + 3 && !http.calls && !http.releases);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, (size_t)n);
    CHECK(results.len == 3 && encoder_calls == before + 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], expected.keys[i], false);
    br_results_clear(&results);
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "delighted %s", key1);
    expected_http expected = {.keys = {key1}, .count = 1, .agent = "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status, rc; const char *body_error, *cause; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {204, 0, "ignored", NULL, true},
        {299, 0, "", NULL, true}, {300, 0, NULL, NULL, false}, {401, 0, "ignored", NULL, false},
        {500, 0, NULL, NULL, false}, {200, 1, NULL, "synthetic timeout", false},
        {200, -1, "ignored", "Delighted native Base64 encoding failed", false},
        {200, 1, NULL, "net/http: nil Context", false}, {204, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].body_error},
                          .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1 && !expected.borrowed_auth);
        check_result(&results.items[0], key1, cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_shared_headers(void *user)
{
    (void)user; fail_alloc_size = 3 * sizeof(br_header); fail_alloc_after = 1; return false;
}

static void suppressed_setup(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "delighted %s", key1);
    expected_http expected = {.keys = {key1}, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport, .cancelled = fail_shared_headers},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = encoder_calls;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_alloc_after);
        CHECK(encoder_calls == before + 1);
        check_result(&results.items[0], key1, false); br_results_clear(&results); http.releases = 0;
    }
}

static void check_prior(const br_results *results, const br_result *prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior->raw.data && results->items[0].raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(results->items[0].secret_parts == prior->secret_parts && results->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(prior->verification_error, "caller-owned"));
}

static void expect_failure(const br_detector *detector, const br_scan_ctx *ctx, br_slice data,
                            br_results *results, const br_result *prior, const char *cause)
{
    char *error = NULL;
    CHECK(detector->scan(detector, ctx, true, data, results, &error) == -1 && error && !strcmp(error, cause));
    CHECK(!fail_alloc_after && !fail_part_after && !fail_encoder_after);
    check_prior(results, prior); free(error);
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "delighted %s\ndelighted %s", key1, key2);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    expected_http expected = {.keys = {key1, key2}, .count = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {0}; br_results results = {0};
    CHECK(br_finding_key(&sentinel, 777, "prior", "key") == 0);
    sentinel.verified = true; sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    CHECK(br_results_push(&results, &sentinel) == 0); br_result prior = results.items[0];
    size_t before = encoder_calls;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; /* Real regex failure returns +1. */
    expect_failure(detector, NULL, data, &results, &prior, "out of memory iterating regex");
    fail_alloc_size = 33; fail_alloc_after = 2;
    expect_failure(detector, NULL, data, &results, &prior, "out of memory copying detector capture");
    fail_part_after = 1;
    expect_failure(detector, NULL, data, &results, &prior, "cannot create Delighted result");
    CHECK(encoder_calls == before && !http.calls && !http.releases); /* Finding failure precedes encoding/skip. */
    const int failures[] = {-1, 0, 1, 43, 45};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        fail_encoder_after = 1; encoder_failure = failures[i]; before = encoder_calls;
        expect_failure(detector, NULL, data, &results, &prior, "Delighted native Base64 encoding failed");
        CHECK(encoder_calls == before + 1 && !http.calls && !http.releases); /* Any non-44 is fatal BEFORE skip. */
    }
    fail_part_after = 2;
    expect_failure(detector, &ctx, data, &results, &prior, "cannot create Delighted result");
    CHECK(http.calls == 1 && http.releases == 1 && !expected.borrowed_auth);
    http.calls = http.releases = 0;
    fail_encoder_after = 2; encoder_failure = 1;
    expect_failure(detector, &ctx, data, &results, &prior, "Delighted native Base64 encoding failed");
    CHECK(http.calls == 1 && http.releases == 1 && !expected.borrowed_auth); /* Roll back earlier success. */
    http.calls = http.releases = 0;
    char *error = NULL; size_t capacity = results.cap; results.cap = 0;
    http.send_rc = 1; http.send_error = "cannot append Delighted result";
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Delighted result"));
    results.cap = capacity; check_prior(&results, &prior); free(error);
    CHECK(http.calls == 1 && http.releases == 1 && !expected.borrowed_auth); /* Own +1 push stays fatal after suppressed Do. */
    http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL;
    fail_encoder_after = 2; encoder_failure = -1;
    CHECK(detector->scan(detector, &ctx, true, data, &results, NULL) == -1 && !fail_encoder_after);
    check_prior(&results, &prior); CHECK(http.calls == 1 && http.releases == 1);
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == 0);
    check_prior(&results, &prior); br_results_clear(&results);
    http.calls = http.releases = 0;
    br_results recovered = test_scan(detector, &ctx, true, data.data, data.len);
    CHECK(recovered.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&recovered.items[0], key1, true); check_result(&recovered.items[1], key2, true);
    br_results_clear(&recovered);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_and_send_errors(detector);
    suppressed_setup(detector); resources_and_rollback(detector);
    return test_finish("Delighted direct factory: exact contact body, KEY: Basic, status-only verification and rollback");
}
