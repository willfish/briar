/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

/* Public synthetic sequences; Python base64.b64encode(ID + ':' + KEY) goldens,
 * indexed KEY then ID, independently establish orientation and padding. */
static const char token1[] = "AbCdEfGhIjKlMnOpQr09";
static const char token2[] = "zYxWvUtSrQpOnMlKjI87";
static const char *const goldens[2][2] = {
    {"Basic QWJDZEVmR2hJaktsTW5PcFFyMDk6QWJDZEVmR2hJaktsTW5PcFFyMDk=",
     "Basic ell4V3ZVdFNyUXBPbk1sS2pJODc6QWJDZEVmR2hJaktsTW5PcFFyMDk="},
    {"Basic QWJDZEVmR2hJaktsTW5PcFFyMDk6ell4V3ZVdFNyUXBPbk1sS2pJODc=",
     "Basic ell4V3ZVdFNyUXBPbk1sS2pJODc6ell4V3ZVdFNyUXBPbk1sS2pJODc="},
};
static const unsigned char payload[] = "name=purchase&data%5Bprice%5D=23.45&data%5Bproduct%5D=socks";
static size_t encoder_calls, fail_encoder_after, fail_part_after, capture_copies;
static size_t fail_alloc_size, fail_alloc_after;
static bool fail_agent_copy;

/* Observe the actual native encoder and its short-positive failure branch.
 * Normal calls use OpenSSL's streaming codec and independent goldens above,
 * not a new production auth seam or a heap-allocated Authorization copy. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls;
    CHECK(len == 41 && in[20] == ':');
    if (fail_encoder_after && --fail_encoder_after == 0) return 1;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[128]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx);
    CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail);
    EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 56 && out[55] == '=' && out[54] != '='); out[at] = '\0';
    return (int)at;
}

void *malloc(size_t size)
{
    if (size == 21) ++capture_copies;
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) {
        fail_agent_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(token1) == 20 && strlen(token2) == 20);
    CHECK(br_customerio_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CustomerIO detector output"));
    free(error); error = NULL;
    CHECK(br_customerio_init(NULL, NULL) == -1);
    CHECK(br_customerio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_customerio_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 211 && detector->version == 0 && !strcmp(detector->name, "CustomerIO"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "CustomerIO is a platform for sending automated emails, push notifications, and SMS messages. CustomerIO API keys can be used to interact with the CustomerIO service to manage customer data and trigger events."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "customerio"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *key, const char *id, bool verified)
{
    CHECK(result->detector_type == 211 && !result->detector_name);
    CHECK(result->raw.len == 20 && !memcmp(result->raw.data, key, 20));
    CHECK(result->raw_v2.len == 40 && !memcmp(result->raw_v2.data, key, 20) && !memcmp(result->raw_v2.data + 20, id, 20));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 20 && !memcmp(json_object_get_string(part), key, 20));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 20 && !memcmp(json_object_get_string(part), id, 20));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void extraction_case(const br_detector *detector, br_slice input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls;
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (expected) check_result(&results.items[0], expected, expected, false); /* One occurrence still emits the self-pair. */
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    const struct { const char *format; bool match; } cases[] = {
        {"customer %s", true}, {"customerio %s", true}, {"CuStOmEr = '%s'", true},
        {"xxCUSTOMERsuffix\r\n%s", true}, {"%s customer", false}, {"%s", false},
        {"customer%s", false}, {"customer x%s", false}, {"customer _%s", false},
        {"customer %sx", false}, {"customer %s_", false}, {"customer .%s!", true},
        {"customer \xc3\xa9%s\xc3\xa9", true},
    };
    char input[512], changed[22];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, token1);
        extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, cases[i].match ? token1 : NULL);
    }
    snprintf(input, sizeof(input), "customer %.19s", token1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, NULL);
    snprintf(input, sizeof(input), "customer %sZ", token1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, NULL);
    for (size_t i = 0; i < 3; ++i) {
        memcpy(changed, token1, sizeof(token1)); changed[7] = "_-+"[i];
        snprintf(input, sizeof(input), "customer %s", changed);
        extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, NULL);
    }
    memset(changed, 'A', 20); changed[20] = '\0';
    snprintf(input, sizeof(input), "customer %s", changed);
    extraction_case(detector, (br_slice){(const unsigned char *)input, strlen(input)}, changed); /* No local entropy filter. */
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int unicode = 0; unicode < 2; ++unicode) {
            memcpy(input, "customer", 8); size_t at = 8;
            for (size_t r = 0; r < gap; ++r) {
                if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; }
                else input[at++] = '.';
            }
            memcpy(input + at, token1, sizeof(token1));
            extraction_case(detector, (br_slice){(const unsigned char *)input, at + 20}, gap == 40 ? token1 : NULL);
        }
    }
    /* customerio's trailing 'io' CONSUMES two of customer's 40 prefix runes. */
    for (size_t gap = 38; gap <= 39; ++gap) {
        memcpy(input, "customerio", 10); memset(input + 10, '.', gap);
        memcpy(input + 10 + gap, token1, sizeof(token1));
        extraction_case(detector, (br_slice){(const unsigned char *)input, 10 + gap + 20}, gap == 38 ? token1 : NULL);
    }
    memcpy(input, "customer\0", 9); memcpy(input + 9, token1, sizeof(token1));
    extraction_case(detector, (br_slice){(const unsigned char *)input, 29}, token1);
    input[8] = (char)0xff;
    extraction_case(detector, (br_slice){(const unsigned char *)input, 29}, NULL);
    int n = snprintf(input, sizeof(input), "\xff\ncustomer %s\n\xff", token1);
    extraction_case(detector, (br_slice){(const unsigned char *)input, (size_t)n}, token1);
    extraction_case(detector, (br_slice){0}, NULL);
}

typedef struct {
    const char *const *occurrences; size_t n;
    const char *agent, *borrowed_auth, *golden;
} expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user;
    size_t pair = http->calls - 1;
    CHECK(ctx && pair < expected->n * expected->n);
    const char *key = expected->occurrences[pair / expected->n], *id = expected->occurrences[pair % expected->n];
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://track.customer.io/api/v1/customers/5/events"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 211);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->body.len == sizeof(payload) - 1 && !memcmp(request->body.data, payload, sizeof(payload) - 1));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, expected->agent));
    size_t ki = !strcmp(key, token1) ? 0 : 1, ii = !strcmp(id, token1) ? 0 : 1;
    CHECK(!strcmp(key, ki ? token2 : token1) && !strcmp(id, ii ? token2 : token1));
    const char *auth = request->headers[1].value;
    CHECK(strlen(auth) == 62 && auth[62] == '\0' && auth[61] == '=' && auth[60] != '=');
    CHECK(!strcmp(auth, goldens[ki][ii]));
    unsigned char decoded[48];
    CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, 56) == 42); /* One padding byte; 41 input bytes. */
    CHECK(!memcmp(decoded, id, 20) && decoded[20] == ':' && !memcmp(decoded + 21, key, 20));
    expected->borrowed_auth = auth; expected->golden = goldens[ki][ii];
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_http *expected = http->user;
    if (expected && expected->borrowed_auth) {
        CHECK(!strcmp(expected->borrowed_auth, expected->golden)); /* Stack buffer lives THROUGH release. */
        expected->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http)
{
    return (br_transport){http, test_http_send, release_response};
}

static void products(const br_detector *detector)
{
    char input[2400]; size_t at = (size_t)snprintf(input, sizeof(input), "customer %s\n", token1);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\ncustomer %s\ncustomer %s", token2, token1);
    const char *occurrences[] = {token1, token2, token1};
    expected_http expected = {.occurrences = occurrences, .n = 3, .agent = "TruffleHog customerio-offline"};
    test_http http = {.response = {.status = 204, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "customerio-offline"};
    size_t before = encoder_calls, copies = capture_copies;
    br_results results = test_scan(detector, &ctx, false, input, at);
    CHECK(results.len == 9 && !http.calls && !http.releases && encoder_calls == before && capture_copies == copies + 3);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], occurrences[i / 3], occurrences[i % 3], false);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, at);
    CHECK(results.len == 9 && http.calls == 9 && http.releases == 9 && encoder_calls == before + 9);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], occurrences[i / 3], occurrences[i % 3], true);
    br_results_clear(&results);
    before = encoder_calls;
    results = test_scan(detector, NULL, true, input, at);
    CHECK(!results.len && encoder_calls == before + 9); /* Every pair encodes BEFORE nil-context skip. */
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "customer %s", token1);
    const char *occurrences[] = {token1};
    expected_http expected = {.occurrences = occurrences, .n = 1, .agent = "TruffleHog"};
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status, rc; const char *cause, *read_error; bool verified; } cases[] = {
        {199, 0, NULL, NULL, false}, {200, 0, NULL, NULL, true}, {201, 0, NULL, "ignored", true},
        {204, 0, NULL, "", true}, {299, 0, NULL, "ignored", true}, {300, 0, NULL, NULL, false},
        {401, 0, NULL, NULL, false}, {403, 0, NULL, "ignored", false}, {429, 0, NULL, NULL, false},
        {500, 0, NULL, NULL, false}, {200, -1, "synthetic timeout", "ignored", false},
        {200, 1, "net/http: nil Context", NULL, false},
        {200, 1, "out of memory constructing HTTP headers", NULL, false}, {200, 1, NULL, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error},
                          .send_rc = cases[i].rc, .send_error = cases[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, (size_t)n);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&results.items[0], token1, token1, cases[i].verified); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[128]; int n = snprintf(input, sizeof(input), "customer %s", token1);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
        {.transport = &transport},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; size_t before = encoder_calls;
        if (i == 4) fail_agent_copy = true; /* Actual shared-send allocation +1 is suppressed. */
        br_results results = test_scan(detector, &contexts[i], true, input, (size_t)n);
        CHECK(results.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy && encoder_calls == before + 1);
        check_result(&results.items[0], token1, token1, false); br_results_clear(&results);
    }
    CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 12345, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void fatal_resources(const br_detector *detector)
{
    char input[256]; int n = snprintf(input, sizeof(input), "customer %s\ncustomer %s", token1, token2);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    const char *occurrences[] = {token1, token2};
    expected_http expected = {.occurrences = occurrences, .n = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls; fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create CustomerIO result") && !fail_part_after && encoder_calls == before);
    check_prior(&results, prior); free(error); error = NULL;
    fail_encoder_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "CustomerIO native Base64 encoding failed") && !fail_encoder_after && encoder_calls == before + 1);
    check_prior(&results, prior); free(error); error = NULL;
    fail_part_after = 4;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create CustomerIO result") && !fail_part_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    http.calls = http.releases = 0; fail_encoder_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "CustomerIO native Base64 encoding failed") && !fail_encoder_after && http.calls == 1 && http.releases == 1);
    check_prior(&results, prior); free(error); error = NULL;
    /* Real positive regex workspace and append-guard returns normalize to -1. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior);
    fail_alloc_size = 21; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after);
    check_prior(&results, prior); free(error); error = NULL;
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append CustomerIO result")); results.cap = capacity;
    check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], occurrences[i / 2], occurrences[i % 2], true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); verification(detector); suppressed_setup(detector); fatal_resources(detector);
    return test_finish("CustomerIO customer-prefix N-squared occurrences + true ID:KEY Basic + fixed form event + pre-skip encoding + rollback");
}
