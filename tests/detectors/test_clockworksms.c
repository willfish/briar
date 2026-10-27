/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key1[] = "00123", key2[] = "98765";
static const char token1[] = "Ab3dEf6hIj9kLm2nOp5qRs8t", token2[] = "Z9y8X7w6V5u4T3s2R1q0P9o8";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static size_t fail_add_after;
typedef struct { const char *const *keys, *const *tokens; size_t len; } expected_requests;

/* Target a real positive +1 finding-part add failure, outside the combined
 * adapter/Do domain. Normal JSON ownership remains with add_ex. */
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_clockworksms_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_clockworksms_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 189 && detector->version == 0 && !strcmp(detector->name, "ClockworkSMS"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Clockwork SMS is a service used for sending SMS messages. User keys and access tokens can be used to authenticate and send messages via the Clockwork SMS API."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "clockworksms") && !strcmp(detector->keywords[1], "textanywhere"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_clockworksms_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void pair_result(const br_result *result, const char *key, const char *token)
{
    CHECK(result->detector_type == 189 && result->raw.len == 5 && !memcmp(result->raw.data, key, 5));
    CHECK(result->raw_v2.len == 29 && !memcmp(result->raw_v2.data, key, 5));
    CHECK(!memcmp(result->raw_v2.data + 5, token, 24));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 5 && !memcmp(json_object_get_string(part), key, 5));
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 24 && !memcmp(json_object_get_string(part), token, 24));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static size_t pair_input(char *out, size_t cap, const char *prefix, const char *key, const char *token)
{
    int len = snprintf(out, cap, "%s %s\n%s\n%s %s", prefix, key, isolation, prefix, token);
    CHECK(len > 0 && (size_t)len < cap); return (size_t)len;
}

static void expect_pair(const br_detector *detector, const void *input, size_t len,
                         const char *key, const char *token, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    if (count) { pair_result(&results.items[0], key, token); CHECK(!results.items[0].verified && !results.items[0].verification_error); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512]; size_t len = pair_input(input, sizeof(input), "clockwork", key1, token1);
    CHECK(!strstr(input, "clockworksms") && !strstr(input, "textanywhere")); /* Direct scan differs from CLI dispatch keywords. */
    expect_pair(detector, input, len, key1, token1, 1);
    const char *prefixes[] = {"CLOCKWORK", "ClOcKwOrK", "clockworksms", "TEXTANYWHERE", "TeXtAnYwHeRe"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        len = pair_input(input, sizeof(input), prefixes[i], key1, token1); expect_pair(detector, input, len, key1, token1, 1);
    }
    const char *bad_keys[] = {"0123", "001234", "A0123", "_00123", "00123_"};
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        len = pair_input(input, sizeof(input), "clockwork", bad_keys[i], token1); expect_pair(detector, input, len, NULL, NULL, 0);
    }
    const char *bad_tokens[] = {"Ab3dEf6hIj9kLm2nOp5qRs8", "Ab3dEf6hIj9kLm2nOp5qRs8tA", "_Ab3dEf6hIj9kLm2nOp5qRs8t",
                               "Ab3dEf6hIj9kLm2nOp5qRs8t_", "Ab3dEf6hIj9-Lm2nOp5qRs8t"};
    for (size_t i = 0; i < sizeof(bad_tokens) / sizeof(bad_tokens[0]); ++i) {
        len = pair_input(input, sizeof(input), "clockwork", key1, bad_tokens[i]); expect_pair(detector, input, len, NULL, NULL, 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, '.', gap); padding[gap] = 0;
        int n = snprintf(input, sizeof(input), "clockwork%s%s\n%s\nclockwork %s", padding, key1, isolation, token1);
        CHECK(n > 0 && (size_t)n < sizeof(input)); expect_pair(detector, input, (size_t)n, key1, token1, gap == 40 ? 1 : 0);
        n = snprintf(input, sizeof(input), "clockwork %s\n%s\nclockwork%s%s", key1, isolation, padding, token1);
        CHECK(n > 0 && (size_t)n < sizeof(input)); expect_pair(detector, input, (size_t)n, key1, token1, gap == 40 ? 1 : 0);
    }
    /* sms is NOT part of the extraction keyword: its three runes use the gap. */
    for (size_t dots = 37; dots <= 38; ++dots) {
        char padding[39]; memset(padding, '.', dots); padding[dots] = 0;
        int n = snprintf(input, sizeof(input), "clockworksms%s%s\n%s\nclockwork %s", padding, key1, isolation, token1);
        CHECK(n > 0 && (size_t)n < sizeof(input)); expect_pair(detector, input, (size_t)n, key1, token1, dots == 37 ? 1 : 0);
        n = snprintf(input, sizeof(input), "clockwork %s\n%s\nclockworksms%s%s", key1, isolation, padding, token1);
        CHECK(n > 0 && (size_t)n < sizeof(input)); expect_pair(detector, input, (size_t)n, key1, token1, dots == 37 ? 1 : 0);
    }
    len = pair_input(input, sizeof(input), "textanywhere", "00000", "AAAAAAAAAAAAAAAAAAAAAAAA");
    expect_pair(detector, input, len, "00000", "AAAAAAAAAAAAAAAAAAAAAAAA", 1); /* No numeric parsing or local entropy/FP filter. */
    expect_pair(detector, NULL, 0, NULL, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 189);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.textanywhere.com/API/v1.0/REST/status"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "User_key"));
    CHECK(strlen(request->headers[0].value) == 5 && !strcmp(request->headers[0].value, expected->keys[http->calls - 1]));
    CHECK(!strcmp(request->headers[1].name, "Access_token") && !strcmp(request->headers[1].value, expected->tokens[http->calls - 1]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog clockworksms-test" : "TruffleHog"));
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source's scan-deferred close-only lifecycle. */
}

static void products(const br_detector *detector)
{
    char input[1024];
    int n = snprintf(input, sizeof(input), "clockwork %s\n%s\ntextanywhere %s\n%s\nclockwork %s\n%s\nclockwork %s\n%s\ntextanywhere %s\n%s\nclockwork %s",
                     key1, isolation, key2, isolation, key1, isolation, token1, isolation, token2, isolation, token1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1, key1, key2, key2, key2, key1, key1, key1};
    const char *tokens[] = {token1, token2, token1, token1, token2, token1, token1, token2, token1}; expected_requests expected = {keys, tokens, 9};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, (size_t)n);
        CHECK(results.len == 9 && http.calls == (mode ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) {
            pair_result(&results.items[i], keys[i], tokens[i]);
            CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, (size_t)n); CHECK(results.len == (verify ? 0u : 9u));
        for (size_t i = 0; i < results.len; ++i) { pair_result(&results.items[i], keys[i], tokens[i]); CHECK(!results.items[i].verification_error); }
        br_results_clear(&results);
    }
}

static void statuses_and_errors(const br_detector *detector)
{
    char input[512], sensitive[128]; size_t len = pair_input(input, sizeof(input), "clockwork", key1, token1);
    snprintf(sensitive, sizeof(sensitive), "synthetic user_key=%s access_token=%s", key1, token1);
    const char *keys[] = {key1}, *tokens[] = {token1}; expected_requests expected = {keys, tokens, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false}, {200, 9, sensitive, false},
        {200, 1, "out of memory constructing HTTP headers", false},
        {200, 1, "unsupported: native curl HTTP client profile", false}, {200, 1, NULL, false}, {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "clockworksms-test"};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); pair_result(&results.items[0], key1, token1);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preflight_errors(const br_detector *detector)
{
    char input[512]; size_t len = pair_input(input, sizeof(input), "clockwork", key1, token1);
    const char *keys[] = {key1}, *tokens[] = {token1}; expected_requests expected = {keys, tokens, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); pair_result(&results.items[0], key1, token1);
        CHECK(!results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_add_after = 1;
    CHECK(br_finding_pair(&probe, 189, key1, "key", token1, "token") != 0);
    CHECK(!fail_add_after && !probe.raw.data && !probe.raw_v2.data && !probe.secret_parts); br_result_clear(&probe);
    CHECK(br_results_push(NULL, &probe) == 1);
    char input[512]; int n = snprintf(input, sizeof(input), "clockwork %s\n%s\nclockwork %s\n%s\nclockwork %s", key1, isolation, token1, isolation, token2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1}, *tokens[] = {token1, token2}; expected_requests expected = {keys, tokens, 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_add_after = 3;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating ClockworkSMS result"));
    CHECK(!fail_add_after && http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error) == 0);
    CHECK(!error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) { pair_result(&results.items[i], keys[i], tokens[i]); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 5 && strlen(key2) == 5 && strlen(token1) == 24 && strlen(token2) == 24);
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); statuses_and_errors(detector); preflight_errors(detector); resource_rollback(detector);
    return test_finish("ClockworkSMS");
}
