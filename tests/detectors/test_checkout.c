/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key1[] = "sk_01234567-89ab-CDEF-0123-456789abcdef";
static const char key2[] = "sk_test_fedcba98-7654-3210-abCD-ef0123456789";
static const char id1[] = "cus_Ab3dE6gH9jK2mN5pQ8sT1vW4xY";
static const char id2[] = "cus_Z9y8X7w6V5u4T3s2R1q0P9o8N7";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static size_t fail_part_after;
typedef struct { const char *const *keys, *const *ids; size_t len; } expected_requests;

/* Target provider-owned finding allocation, not the adapter/Do domain. The
 * fixture captures are complete ASCII strings with no embedded NUL. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 39 || len == 44 || len == 30);
    if (fail_part_after && --fail_part_after == 0) return NULL;
    char copy[45]; memcpy(copy, value, (size_t)len); copy[len] = 0;
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_checkout_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_checkout_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 187 && detector->version == 0 && !strcmp(detector->name, "Checkout"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Checkout is a global payment solution provider. Checkout API keys can be used to process payments and manage customer data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "checkout"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_checkout_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void pair_result(const br_result *result, const char *key, const char *id)
{
    size_t klen = strlen(key);
    CHECK(result->detector_type == 187 && result->raw.len == klen && !memcmp(result->raw.data, key, klen));
    CHECK(result->raw_v2.len == klen + 30 && !memcmp(result->raw_v2.data, key, klen));
    CHECK(!memcmp(result->raw_v2.data + klen, id, 30));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == klen && !memcmp(json_object_get_string(part), key, klen));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 30 && !memcmp(json_object_get_string(part), id, 30));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static size_t pair_input(char *out, size_t cap, const char *key, const char *id)
{
    int len = snprintf(out, cap, "checkout %s\n%s\nCHECKOUT %s", key, isolation, id);
    CHECK(len > 0 && (size_t)len < cap); return (size_t)len;
}

static void expect_pair(const br_detector *detector, const void *input, size_t len,
                         const char *key, const char *id, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    if (count) { pair_result(&results.items[0], key, id); CHECK(!results.items[0].verified && !results.items[0].verification_error); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[64]; size_t len = pair_input(input, sizeof(input), key1, id1);
    expect_pair(detector, input, len, key1, id1, 1);
    len = pair_input(input, sizeof(input), key2, id2); expect_pair(detector, input, len, key2, id2, 1);
    const char *bad_keys[] = {
        "SK_01234567-89ab-CDEF-0123-456789abcdef", "sk_TEST_fedcba98-7654-3210-abCD-ef0123456789",
        "sk_G1234567-89ab-CDEF-0123-456789abcdef", "sk_0123456-89ab-CDEF-0123-456789abcdef",
        "sk_01234567_89ab-CDEF-0123-456789abcdef", "sk_01234567-89ab-CDEF-0123-456789abcdef0",
        "_sk_01234567-89ab-CDEF-0123-456789abcdef", "sk_01234567-89ab-CDEF-0123-456789abcdef_",
    };
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        len = pair_input(input, sizeof(input), bad_keys[i], id1); expect_pair(detector, input, len, NULL, NULL, 0);
    }
    const char *bad_ids[] = {"CUS_Ab3dE6gH9jK2mN5pQ8sT1vW4xY", "cus_Ab3dE6gH9jK2mN5pQ8sT1vW4x",
                             "cus_Ab3dE6gH9jK2mN5pQ8sT1vW4xYz", "_cus_Ab3dE6gH9jK2mN5pQ8sT1vW4xY",
                             "cus_Ab3dE6gH9jK2mN5pQ8sT1vW4xY_"};
    for (size_t i = 0; i < sizeof(bad_ids) / sizeof(bad_ids[0]); ++i) {
        len = pair_input(input, sizeof(input), key1, bad_ids[i]); expect_pair(detector, input, len, NULL, NULL, 0);
    }
    memcpy(changed, id1, sizeof(id1)); changed[12] = '-';
    len = pair_input(input, sizeof(input), key1, changed); expect_pair(detector, input, len, NULL, NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, ':', gap); padding[gap] = 0;
        int n = snprintf(input, sizeof(input), "ChEcKoUt%s%s\n%s\ncheckout %s", padding, key1, isolation, id1);
        CHECK(n > 0 && (size_t)n < sizeof(input)); expect_pair(detector, input, (size_t)n, key1, id1, gap == 40 ? 1 : 0);
        n = snprintf(input, sizeof(input), "checkout %s\n%s\nChEcKoUt%s%s", key1, isolation, padding, id1);
        CHECK(n > 0 && (size_t)n < sizeof(input)); expect_pair(detector, input, (size_t)n, key1, id1, gap == 40 ? 1 : 0);
    }
    const char *nil_key = "sk_00000000-0000-0000-0000-000000000000";
    len = pair_input(input, sizeof(input), nil_key, id1); expect_pair(detector, input, len, nil_key, id1, 1);
    int n = snprintf(input, sizeof(input), "%s\n%s\ncheckout %s", key1, isolation, id1); CHECK(n > 0);
    expect_pair(detector, input, (size_t)n, NULL, NULL, 0); /* Prefixed extraction, not a bare key pattern. */
    expect_pair(detector, NULL, 0, NULL, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 187);
    char url[128]; snprintf(url, sizeof(url), "https://api.sandbox.checkout.com/customers/%s", expected->ids[http->calls - 1]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url)); /* Production-format sk_ also uses sandbox. */
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, expected->keys[http->calls - 1])); /* No Bearer/Basic prefix. */
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog checkout-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source's scan-deferred close-only lifecycle. */
}

static void products(const br_detector *detector)
{
    char input[1024];
    int n = snprintf(input, sizeof(input), "checkout %s\n%s\ncheckout %s\n%s\ncheckout %s\n%s\ncheckout %s\n%s\ncheckout %s\n%s\ncheckout %s",
                     key1, isolation, key2, isolation, key1, isolation, id1, isolation, id2, isolation, id1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1, key1, key2, key2, key2, key1, key1, key1};
    const char *ids[] = {id1, id2, id1, id1, id2, id1, id1, id2, id1}; expected_requests expected = {keys, ids, 9};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, (size_t)n);
        CHECK(results.len == 9 && http.calls == (mode ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) {
            pair_result(&results.items[i], keys[i], ids[i]);
            CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, (size_t)n);
        CHECK(results.len == (verify ? 0u : 9u));
        for (size_t i = 0; i < results.len; ++i) { pair_result(&results.items[i], keys[i], ids[i]); CHECK(!results.items[i].verification_error); }
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char input[512], sensitive[160]; size_t len = pair_input(input, sizeof(input), key1, id1);
    snprintf(sensitive, sizeof(sensitive), "synthetic key=%s id=%s", key1, id1);
    const char *keys[] = {key1}, *ids[] = {id1}; expected_requests expected = {keys, ids, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {200, 1, "out of memory constructing HTTP headers", false},
        {302, 1, "unsupported: redirects with sensitive HTTP headers", false}, {200, 1, NULL, false}, {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "checkout-test"};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); pair_result(&results.items[0], key1, id1);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preflight_errors(const br_detector *detector)
{
    char input[512]; size_t len = pair_input(input, sizeof(input), key1, id1);
    const char *keys[] = {key1}, *ids[] = {id1}; expected_requests expected = {keys, ids, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u));
        pair_result(&results.items[0], key1, id1); CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_part_after = 1;
    CHECK(br_finding_pair(&probe, 187, key1, "key", id1, "id") != 0);
    CHECK(!fail_part_after && !probe.raw.data && !probe.raw_v2.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1);
    char input[512]; int n = snprintf(input, sizeof(input), "checkout %s\n%s\ncheckout %s\n%s\ncheckout %s", key1, isolation, id1, isolation, id2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1}, *ids[] = {id1, id2}; expected_requests expected = {keys, ids, 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_part_after = 3;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Checkout result"));
    CHECK(!fail_part_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) { pair_result(&results.items[i], keys[i], ids[i]); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 39 && strlen(key2) == 44 && strlen(id1) == 30 && strlen(id2) == 30);
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); statuses_and_errors(detector); preflight_errors(detector); resource_rollback(detector);
    return test_finish("Checkout");
}
