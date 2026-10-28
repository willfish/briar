/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char hidden_key[33], id1[33], id2[33];
static size_t fail_alloc_size, fail_alloc_after, fail_part_after, encoder_calls, fail_encoder_after;
static bool fail_agent_copy, observe_auth;
static const unsigned char *borrowed_credentials;
static const char *borrowed_auth;

/* Interpose the REAL encoder entry, using OpenSSL's streaming codec for normal
 * calls, an independent decoder below and one independent Base64 golden. No new
 * production crypto/auth API, manual codec or heap staging. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls; CHECK(len == 65 && in[32] == ':');
    if (fail_encoder_after && --fail_encoder_after == 0) return 1; /* Real positive wrong-length failure must be fatal. */
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[128]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx); CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1); EVP_EncodeFinal(ctx, wrapped + used, &tail); EVP_ENCODE_CTX_free(ctx);
    size_t at = 0; for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    CHECK(at == 88 && out[87] == '=' && out[86] != '='); out[at] = '\0';
    if (observe_auth) { CHECK(!borrowed_auth && !borrowed_credentials); borrowed_credentials = in; borrowed_auth = (const char *)out - 6; }
    return (int)at;
}

void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_agent_copy && !strcmp(text, "TruffleHog")) { fail_agent_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(hidden_key) == 32 && strlen(id1) == 32 && strlen(id2) == 32);
    CHECK(br_fmfw_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Fmfw detector output")); free(error); error = NULL;
    CHECK(br_fmfw_init(NULL, NULL) == -1);
    CHECK(br_fmfw_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_fmfw_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 653 && detector->version == 0 && !strcmp(detector->name, "Fmfw"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "FMFW is a cryptocurrency exchange platform. FMFW API keys can be used to access and manage account data and perform trading operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "fmfw"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 653, key, "key"); /* ID remains hidden: exactly ONE part and NO RawV2, even verified. */
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error && !result->verification_from_cache);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 32);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; size_t before = encoder_calls;
    br_results results = test_scan(detector, &ctx, false, input, len); CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[33];
    const struct { const char *format; bool matches; } cases[] = {
        {"fmfw '%s'", true}, {"FMfW=%s", true}, {"prefmfw suffix:%s", true}, {"fmfw\r\n%s", true}, {"fmfw\n%s", true},
        {"%s", false}, {"%s fmfw", false}, {"fm fw %s", false}, {"fmfw%s", false}, {"fmfw x%s", false},
        {"fmfw _%s", false}, {"fmfw %s_", false}, {"fmfw %s9", false}, {"fmfw %.31s", false}, {"fmfw \xc3\xa9%s\xc3\xa9", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) { snprintf(input, sizeof(input), cases[i].format, id1); extraction_case(detector, input, strlen(input), cases[i].matches ? id1 : NULL); }
    snprintf(input, sizeof(input), "fmfw %s", hidden_key); extraction_case(detector, input, strlen(input), NULL); /* Key exists, but ID grammar excludes underscore and ID is REQUIRED. */
    const char invalid[] = "+/=.";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { memcpy(changed, id1, sizeof(changed)); changed[16] = invalid[i]; snprintf(input, sizeof(input), "fmfw %s", changed); extraction_case(detector, input, strlen(input), NULL); }
    memcpy(changed, id1, sizeof(changed)); changed[0] = '-'; snprintf(input, sizeof(input), "fmfw %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "fmfw X%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, id1, sizeof(changed)); changed[31] = '-'; snprintf(input, sizeof(input), "fmfw %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "fmfw %sX", changed); extraction_case(detector, input, strlen(input), changed); /* Word-boundary behavior, not full-token delimiters. */
    memset(changed, 'A', 32); changed[32] = '\0'; snprintf(input, sizeof(input), "fmfw %s", changed); extraction_case(detector, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) for (int unicode = 0; unicode < 2; ++unicode) {
        memcpy(input, "fmfw", 4); size_t at = 4;
        for (size_t i = 0; i < gap; ++i) { if (unicode) { memcpy(input + at, "\xc3\xa9", 2); at += 2; } else input[at++] = '.'; }
        memcpy(input + at, id1, 32); at += 32; extraction_case(detector, input, at, gap == 40 ? id1 : NULL);
    }
    int n = snprintf(input, sizeof(input), "fmfw%c%s", 0, id1); extraction_case(detector, input, (size_t)n, id1);
    n = snprintf(input, sizeof(input), "\xff\nfmfw %s\n\xff", id1); extraction_case(detector, input, (size_t)n, id1);
    n = snprintf(input, sizeof(input), "fmfw %s %s", id1, id2); extraction_case(detector, input, (size_t)n, id1); extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *const *keys, *const *ids; size_t nkeys, nids; const char *agent; const br_scan_ctx *original; } expected_http;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_http *expected = http->user; CHECK(ctx && ctx == expected->original && http->calls <= expected->nkeys * expected->nids);
    size_t pair = http->calls - 1; const char *key = expected->keys[pair / expected->nids], *id = expected->ids[pair % expected->nids];
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.fmfw.io/api/3/spot/balance"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 653); /* Selected request override, NOT global client mutation/race proof. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization") && strlen(request->headers[0].value) == 94);
    CHECK(!memcmp(request->headers[0].value, "Basic ", 6) && request->headers[0].value[93] == '=' && request->headers[0].value[92] != '=');
    unsigned char decoded[66]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)request->headers[0].value + 6, 88) == 66);
    CHECK(!memcmp(decoded, id, 32) && decoded[32] == ':' && !memcmp(decoded + 33, key, 32) && decoded[65] == 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, expected->agent));
    CHECK(observe_auth && borrowed_auth == request->headers[0].value && borrowed_credentials && !memcmp(borrowed_credentials, decoded, 65));
    static const char all_a[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    if (!memcmp(key, all_a, 32) && !memcmp(id, all_a, 32))
        CHECK(!strcmp(request->headers[0].value, "Basic QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE6QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=")); /* Independent Python/standard-Base64 golden. */
}

static void release_response(void *user, br_http_response *response)
{
    CHECK(observe_auth && borrowed_credentials && borrowed_auth && strlen(borrowed_auth) == 94 && !memcmp(borrowed_auth, "Basic ", 6));
    unsigned char decoded[66]; CHECK(EVP_DecodeBlock(decoded, (const unsigned char *)borrowed_auth + 6, 88) == 66 && !memcmp(decoded, borrowed_credentials, 65));
    CHECK(borrowed_auth[94] == '\0'); borrowed_auth = NULL; borrowed_credentials = NULL; /* BOTH complete stack buffers survive THROUGH release. */
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static void independent_roles_and_products(const br_detector *detector)
{
    char input[4096]; const char *one_key[] = {hidden_key}, *one_id[] = {id1};
    expected_http expected = {.keys = one_key, .ids = one_id, .nkeys = 1, .nids = 1, .agent = "TruffleHog fmfw-offline"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "fmfw-offline"}; expected.original = &ctx; observe_auth = true;
    const size_t gaps[] = {1, 7, 8};
    for (size_t g = 0; g < sizeof(gaps) / sizeof(gaps[0]); ++g) {
        size_t gap = gaps[g];
        size_t at = (size_t)snprintf(input, sizeof(input), "fmfw %s", hidden_key); memset(input + at, ' ', gap); at += gap; memcpy(input + at, id1, 33);
        http.calls = http.releases = 0; size_t before = encoder_calls;
        br_results results = test_scan(detector, &ctx, true, input, at + 32); CHECK(results.len == (gap <= 7 ? 1u : 0u));
        CHECK(http.calls == (gap <= 7 ? 1u : 0u) && http.releases == http.calls && encoder_calls == before + http.calls);
        if (results.len) check_result(&results.items[0], hidden_key, true);
        br_results_clear(&results);
    } /* ID regex reaches the LATER unprefixed ID at prefix distances 34/40, not 41. Filtering key captures would lose it. */
    const char *records[] = {hidden_key, id1, id2, id1}; size_t at = 0;
    for (size_t i = 0; i < 4; ++i) { at += (size_t)snprintf(input + at, sizeof(input) - at, "fmfw %s", records[i]); memset(input + at, '.', 80); at += 80; }
    const char *ids[] = {id1, id2, id1}; expected.keys = records; expected.nkeys = 4; expected.ids = ids; expected.nids = 3;
    http.calls = http.releases = 0; size_t before = encoder_calls;
    br_results results = test_scan(detector, &ctx, false, input, at); CHECK(results.len == 12 && !http.calls && !http.releases && encoder_calls == before);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], records[i / 3], false);
    CHECK(results.items[0].raw.data != results.items[1].raw.data && results.items[0].secret_parts != results.items[1].secret_parts); br_results_clear(&results);
    for (int pass = 0; pass < 2; ++pass) {
        http.calls = http.releases = 0; before = encoder_calls; results = test_scan(detector, &ctx, true, input, at);
        CHECK(results.len == 12 && http.calls == 12 && http.releases == 12 && encoder_calls == before + 12);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], records[i / 3], true);
        br_results_clear(&results);
    } /* Key-major original products/duplicates/selfpairs, NO verified-break/set/equality policy; ID hidden even verified. */
    http.calls = http.releases = 0; before = encoder_calls; fail_encoder_after = 1;
    results = test_scan(detector, NULL, true, input, at); CHECK(!results.len && !http.calls && !http.releases && encoder_calls == before && fail_encoder_after == 1); fail_encoder_after = 0; br_results_clear(&results); /* Constructor skip BEFORE Basic assembly/crypto. */
    at = (size_t)snprintf(input, sizeof(input), "fmfw %s\n", id1); memset(input + at, '.', 2048); at += 2048; at += (size_t)snprintf(input + at, sizeof(input) - at, "\nfmfw %s", id2);
    const char *far[] = {id1, id2}; expected.keys = expected.ids = far; expected.nkeys = expected.nids = 2; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, at); CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], far[i / 2], true);
    br_results_clear(&results); /* Span 1024 is engine hint, NOT local distance cap. */
    const char *golden[] = {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}; expected.keys = expected.ids = golden; expected.nkeys = expected.nids = 1; http.calls = http.releases = 0;
    snprintf(input, sizeof(input), "fmfw %s", golden[0]); results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], golden[0], true); br_results_clear(&results);
    observe_auth = false;
}

static void statuses_and_suppressed_send(const br_detector *detector)
{
    static const unsigned char body[] = {0, 0xff, '{', '!'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {{199, NULL, false}, {200, NULL, true}, {201, "ignored", true}, {204, "", true}, {299, "ignored", true}, {300, NULL, false}, {401, "ignored", false}, {403, NULL, false}, {500, "", false}};
    const char *one[] = {id1}; expected_http expected = {.keys = one, .ids = one, .nkeys = 1, .nids = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx; observe_auth = true;
    char input[64]; snprintf(input, sizeof(input), "fmfw %s", id1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0; http.response = (br_http_response){.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = cases[i].read_error};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], id1, cases[i].verified); br_results_clear(&results);
    }
    const struct { int rc; const char *cause; } failures[] = {{1, "net/http: nil Context"}, {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, id1}};
    http.response = (br_http_response){.status = 200, .body = {body, sizeof(body)}, .body_error = ""};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_result(&results.items[0], id1, false); br_results_clear(&results);
    }
    observe_auth = false;
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void suppressed_setup(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "fmfw %s", id1); test_http http = {0}; br_transport transport = transport_for(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "invalid\r\nagent"}, {.transport = &transport}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        http.calls = http.releases = 0; observe_auth = i != 0; if (i == 4) fail_agent_copy = true; size_t before = encoder_calls;
        br_results results = test_scan(detector, &contexts[i], true, input, strlen(input)); CHECK(results.len == 1 && encoder_calls == before + 1 && !http.calls && http.releases == (i ? 1u : 0u) && !fail_agent_copy);
        CHECK(!borrowed_auth && !borrowed_credentials); check_result(&results.items[0], id1, false); br_results_clear(&results);
    }
    observe_auth = false; CHECK(cancellations == 1);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 777, .verified = true}; prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "fmfw %s\nfmfw %s", id1, id2); br_slice data = {(const unsigned char *)input, strlen(input)};
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL; size_t before = encoder_calls;
    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Fmfw result") && !fail_part_after && encoder_calls == before); check_prior(&results, prior); free(error); error = NULL;
    const char *values[] = {id1, id2}; expected_http expected = {.keys = values, .ids = values, .nkeys = 2, .nids = 2, .agent = "TruffleHog"};
    test_http http = {.response = {.status = 200, .body_error = "ignored"}, .inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; expected.original = &ctx; observe_auth = true;
    fail_part_after = 2;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Fmfw result") && !fail_part_after && encoder_calls == before + 1 && http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); error = NULL;
    before = encoder_calls; fail_encoder_after = 2; http.calls = http.releases = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "FMFW native Base64 encoding failed") && !fail_encoder_after && encoder_calls == before + 2 && http.calls == 1 && http.releases == 1 && !borrowed_auth && !borrowed_credentials); check_prior(&results, prior); free(error); error = NULL; /* Real encoder +1 error wins before suppressed send, rolls back earlier verified product. */
    br_scan_ctx missing = {0}; observe_auth = false; before = encoder_calls; fail_encoder_after = 1;
    CHECK(detector->scan(detector, &missing, true, data, &results, &error) == -1 && error && !strcmp(error, "FMFW native Base64 encoding failed") && !fail_encoder_after && encoder_calls == before + 1); check_prior(&results, prior); free(error); error = NULL;
    before = encoder_calls; fail_encoder_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error && fail_encoder_after == 1 && encoder_calls == before); fail_encoder_after = 0; check_prior(&results, prior); /* No encode/assembly before constructor. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior); /* KEY regex positive failure. */
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after); check_prior(&results, prior); /* Independent ID regex positive failure after key collection. */
    fail_alloc_size = 33; fail_alloc_after = 3;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory copying detector capture") && !fail_alloc_after); check_prior(&results, prior); free(error); error = NULL; /* Two key copies then first ID copy. */
    size_t capacity = results.cap; results.cap = 0; http.calls = http.releases = 0; observe_auth = true;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error); check_prior(&results, prior);
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Fmfw result")); results.cap = capacity;
    CHECK(http.calls == 1 && http.releases == 1); check_prior(&results, prior); free(error); br_results_clear(&results);
    http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 4 && http.calls == 4 && http.releases == 4);
    for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], values[i / 2], true);
    br_results_clear(&results); observe_auth = false;
}

int main(void)
{
    test_secret(hidden_key, 32, 0); test_secret(id1, 32, 7); test_secret(id2, 32, 15);
    hidden_key[3] = 'Z'; hidden_key[8] = '_'; hidden_key[20] = '-'; hidden_key[31] = 'K'; id1[3] = 'A'; id1[8] = '-'; id1[31] = 'Z'; id2[3] = 'G'; id2[20] = '-'; id2[31] = 'Q';
    const br_detector *detector = descriptor(); extraction(detector); independent_roles_and_products(detector); statuses_and_suppressed_send(detector); suppressed_setup(detector); resources_and_rollback(detector);
    CHECK(!borrowed_auth && !borrowed_credentials); return test_finish("FMFW independent occurrence products + hidden IDs + native Basic auth");
}
