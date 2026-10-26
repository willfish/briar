/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>
#include <openssl/evp.h>

static const char key1[] = "ABC-DEF-GHI-JKL", key2[] = "LMN-OPQ-RST-UVW";
static const char user1[] = "synthetic7", user2[] = "otheruser9";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static size_t fail_part_after;
typedef struct { const char *const *keys, *const *users; size_t len; } expected_requests;

/* Target a provider-owned finding part allocation, outside the adapter/Do
 * domain. Focused fixtures are non-NUL ASCII, including the long username. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len > 0);
    if (fail_part_after && --fail_part_after == 0) return NULL;
    char *copy = malloc((size_t)len + 1);
    if (!copy) return NULL;
    memcpy(copy, value, (size_t)len); copy[len] = 0;
    struct json_object *part = json_object_new_string(copy);
    free(copy);
    return part;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_cashboard_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_cashboard_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 685 && detector->version == 0 && !strcmp(detector->name, "Cashboard"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Cashboard is a financial management service. Cashboard credentials can be used to access and manage financial data and accounts."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "cashboard"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_cashboard_init(NULL, &error) != 0 && error); free(error);
    return detector;
}

static void pair_result(const br_result *result, const char *key, const char *username)
{
    size_t klen = strlen(key), ulen = strlen(username);
    CHECK(result->detector_type == 685 && result->raw.len == klen && !memcmp(result->raw.data, key, klen));
    CHECK(result->raw_v2.len == klen + ulen && !memcmp(result->raw_v2.data, key, klen));
    CHECK(!memcmp(result->raw_v2.data + klen, username, ulen));
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == klen && !memcmp(json_object_get_string(part), key, klen));
    CHECK(json_object_object_get_ex(result->secret_parts, "username", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == ulen && !memcmp(json_object_get_string(part), username, ulen));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len);
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
}

static size_t pair_input(char *out, size_t cap, const char *key, const char *username)
{
    int len = snprintf(out, cap, "cashboard %s\n%s\nCASHBOARD %s", key, isolation, username);
    CHECK(len > 0 && (size_t)len < cap); return (size_t)len;
}

static void expect_pairs(const br_detector *detector, const void *input, size_t len,
                          const char *const *keys, const char *const *users, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) {
        pair_result(&results.items[i], keys[i], users[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512]; const char *keys[] = {key1}, *users[] = {user1};
    size_t len = pair_input(input, sizeof(input), key1, user1);
    expect_pairs(detector, input, len, keys, users, 1);
    const char *bad_keys[] = {"abc-def-ghi-jkl", "AB-DEF-GHI-JKL", "ABCD-DEF-GHI-JKL", "ABC_DEF-GHI-JKL", "_ABC-DEF-GHI-JKL", "ABC-DEF-GHI-JKL_"};
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        len = pair_input(input, sizeof(input), bad_keys[i], user1);
        expect_pairs(detector, input, len, NULL, NULL, 0);
    }
    const char *valid_users[] = {"a", "123", "abcdefghijklmnopqrstuvwxyz0123456789"};
    for (size_t i = 0; i < sizeof(valid_users) / sizeof(valid_users[0]); ++i) {
        len = pair_input(input, sizeof(input), key1, valid_users[i]);
        const char *wanted[] = {valid_users[i]}; expect_pairs(detector, input, len, keys, wanted, 1);
    }
    const char *bad_users[] = {"UPPER", "lowerCase", "_lower"};
    for (size_t i = 0; i < sizeof(bad_users) / sizeof(bad_users[0]); ++i) {
        len = pair_input(input, sizeof(input), key1, bad_users[i]);
        expect_pairs(detector, input, len, NULL, NULL, 0);
    }
    len = pair_input(input, sizeof(input), key1, "first-second");
    const char *first[] = {"first"}; expect_pairs(detector, input, len, keys, first, 1);
    snprintf(input, sizeof(input), "cashboard ABC-123-DEF-GHI");
    const char *numeric_key[] = {"ABC-123-DEF-GHI"}, *numeric_user[] = {"123"};
    expect_pairs(detector, input, strlen(input), numeric_key, numeric_user, 1); /* Independent user regex captures key fragments. */
    snprintf(input, sizeof(input), "CaShBoArD context %s", key1);
    const char *context[] = {"context"}; expect_pairs(detector, input, strlen(input), keys, context, 1);
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, ':', gap); padding[gap] = 0;
        int n = snprintf(input, sizeof(input), "cashboard%s%s\n%s\ncashboard %s", padding, key1, isolation, user1);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_pairs(detector, input, (size_t)n, keys, users, gap == 40 ? 1 : 0);
        n = snprintf(input, sizeof(input), "cashboard %s\n%s\ncashboard%s%s", key1, isolation, padding, user1);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_pairs(detector, input, (size_t)n, keys, users, gap == 40 ? 1 : 0);
    }
    len = pair_input(input, sizeof(input), "AAA-AAA-AAA-AAA", "a");
    const char *low_keys[] = {"AAA-AAA-AAA-AAA"}, *low_users[] = {"a"};
    expect_pairs(detector, input, len, low_keys, low_users, 1);
    expect_pairs(detector, NULL, 0, NULL, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 685);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.cashboardapp.com/account.xml"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, ctx->user_agent ? "TruffleHog cashboard-test" : "TruffleHog"));
    const char *auth = request->headers[0].value; CHECK(!strncmp(auth, "Basic ", 6));
    size_t encoded = strlen(auth + 6), ulen = strlen(expected->users[http->calls - 1]), klen = strlen(expected->keys[http->calls - 1]);
    CHECK(encoded == 4 * ((ulen + 1 + klen + 2) / 3) && encoded <= INT_MAX);
    unsigned char *decoded = malloc(encoded / 4 * 3 + 1); CHECK(decoded);
    int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, (int)encoded); CHECK(decoded_len >= 0);
    if (auth[6 + encoded - 1] == '=') --decoded_len;
    if (auth[6 + encoded - 2] == '=') --decoded_len;
    CHECK((size_t)decoded_len == ulen + 1 + klen && decoded[ulen] == ':');
    CHECK(!memcmp(decoded, expected->users[http->calls - 1], ulen));
    CHECK(!memcmp(decoded + ulen + 1, expected->keys[http->calls - 1], klen));
    free(decoded);
    CHECK(http->releases == http->calls - 1); /* ABI timing, not source's scan-deferred close-only lifecycle. */
}

static void products(const br_detector *detector)
{
    char input[1024];
    int n = snprintf(input, sizeof(input), "cashboard %s\n%s\ncashboard %s\n%s\ncashboard %s\n%s\ncashboard %s\n%s\ncashboard %s\n%s\ncashboard %s",
                     key1, isolation, key2, isolation, key1, isolation, user1, isolation, user2, isolation, user1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1, key1, key2, key2, key2, key1, key1, key1};
    const char *users[] = {user1, user2, user1, user1, user2, user1, user1, user2, user1};
    expected_requests expected = {keys, users, 9};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, (size_t)n);
        CHECK(results.len == 9 && http.calls == (mode ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) {
            pair_result(&results.items[i], keys[i], users[i]);
            CHECK(results.items[i].verified == (mode == 1) && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, NULL, verify, input, (size_t)n);
        CHECK(results.len == (verify ? 0u : 9u));
        for (size_t i = 0; i < results.len; ++i) { pair_result(&results.items[i], keys[i], users[i]); CHECK(!results.items[i].verification_error); }
        br_results_clear(&results);
    }
}

static void long_username(const br_detector *detector)
{
    const size_t ulen = 8192;
    char *username = malloc(ulen + 1), *input = malloc(ulen + 256); CHECK(username && input);
    memset(username, 'a', ulen); username[ulen] = 0;
    size_t len = pair_input(input, ulen + 256, key1, username);
    const char *keys[] = {key1}, *users[] = {username}; expect_pairs(detector, input, len, keys, users, 1);
    expected_requests expected = {keys, users, 1};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, len);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    pair_result(&results.items[0], key1, username); CHECK(results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results); free(username); free(input);
}

static void statuses_and_errors(const br_detector *detector)
{
    char input[512], sensitive[96]; size_t len = pair_input(input, sizeof(input), key1, user1);
    snprintf(sensitive, sizeof(sensitive), "synthetic key=%s user=%s", key1, user1);
    const char *keys[] = {key1}, *users[] = {user1}; expected_requests expected = {keys, users, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true}, {299, 0, NULL, true},
        {300, 0, NULL, false}, {401, 0, NULL, false}, {403, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false},
        {200, 9, sensitive, false}, {200, 1, "out of memory constructing HTTP headers", false},
        {302, 1, "unsupported: redirects with sensitive HTTP headers", false}, {200, 1, NULL, false}, {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'X', 'M', 'L'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "cashboard-test"};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        pair_result(&results.items[0], key1, user1);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void preflight_errors(const br_detector *detector)
{
    char input[512]; size_t len = pair_input(input, sizeof(input), key1, user1);
    const char *keys[] = {key1}, *users[] = {user1}; expected_requests expected = {keys, users, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport,
                           .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u));
        pair_result(&results.items[0], key1, user1); CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_part_after = 1;
    CHECK(br_finding_pair(&probe, 685, key1, "key", user1, "username") != 0);
    CHECK(!fail_part_after && !probe.raw.data && !probe.raw_v2.data && !probe.secret_parts); br_result_clear(&probe);
    char *auth = NULL;
    CHECK(br_http_basic_auth((br_slice){NULL, 1}, (br_slice){0}, &auth, NULL) == 1 && !auth);
    CHECK(br_results_push(NULL, &probe) == 1);
    char input[512]; int n = snprintf(input, sizeof(input), "cashboard %s\n%s\ncashboard %s\n%s\ncashboard %s", key1, isolation, user1, isolation, user2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1}, *users[] = {user1, user2}; expected_requests expected = {keys, users, 2};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL; fail_part_after = 3; /* First pair has two parts; fail the next pair's key part. */
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory creating Cashboard result"));
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
    for (size_t i = 0; i < 2; ++i) { pair_result(&results.items[i], keys[i], users[i]); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 15 && strlen(key2) == 15);
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); long_username(detector); statuses_and_errors(detector);
    preflight_errors(detector); resource_rollback(detector);
    return test_finish("Cashboard");
}
