/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include <limits.h>
#include <openssl/evp.h>
#include <time.h>

static const char key1[] = "aB3dE6gH9jK2mN5pQ8sT";
static const char key2[] = "Z9y8X7w6V5u4T3s2R1q0";
static const char user1[] = "abc._-defghijk";
static const char user2[] = "XYZ.-_987654";
static const char isolation[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
static bool fail_status_copy;

/* Target the real setter's positive +1 resource return, without changing any
 * shared helper or failing unrelated allocations. */
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, "unexpected HTTP response status 429")) {
        fail_status_copy = false;
        return NULL;
    }
    size_t len = strlen(text) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

typedef struct {
    const char *const *keys, *const *users;
    size_t len;
    uint32_t deadline_cap;
    bool fail_second;
} expected_requests;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && BR_HTTP_BROWSERSTACK == 6);
    CHECK(br_browserstack_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_browserstack_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 756 && detector->version == 0 && !strcmp(detector->name, "BrowserStack"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "BrowserStack is a cloud web and mobile testing platform. BrowserStack credentials can be used to access and manage testing environments."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "browserstack"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_browserstack_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void pair_result(const br_result *result, const char *key, const char *username)
{
    size_t klen = strlen(key), ulen = strlen(username);
    CHECK(result->detector_type == 756 && result->raw.len == klen && !memcmp(result->raw.data, key, klen));
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

static size_t pair_input(char *out, size_t cap, const char *key_prefix, const char *key,
                          const char *user_prefix, const char *username)
{
    int len = snprintf(out, cap, "%s %s\n%s\n%s %s", key_prefix, key, isolation, user_prefix, username);
    CHECK(len >= 0 && (size_t)len < cap);
    return (size_t)len;
}

static void expect_pairs(const br_detector *detector, const void *input, size_t len,
                          const char *const *keys, const char *const *users, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && http.calls == 0 && http.releases == 0);
    for (size_t i = 0; i < count; ++i) {
        pair_result(&results.items[i], keys[i], users[i]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[768];
    const char *keys[] = {key1, key1}, *users[] = {user1};
    size_t len = pair_input(input, sizeof(input), "accessKey", key1, "userName", user1);
    CHECK(!strstr(input, "browserstack")); /* Native FromData differs from engine keyword dispatch. */
    expect_pairs(detector, input, len, keys, users, 1);
    const char *key_prefixes[] = {"hub-cloud.browserstack.com", "accessKey", "\"access_Key\":", "ACCESS_KEY", "key",
                                "browserstackKey", "BS_AUTHKEY", "BROWSERSTACK_ACCESS_KEY"};
    const char *user_prefixes[] = {"hub-cloud.browserstack.com", "userName", "\"username\":", "USER_NAME", "user",
                                 "browserstackUser", "BS_USERNAME", "BROWSERSTACK_USERNAME"};
    for (size_t i = 0; i < 8; ++i) {
        len = pair_input(input, sizeof(input), key_prefixes[i], key1, "userName", user1);
        /* The shared hub prefix also legitimately captures the 20-byte key as a username. */
        const char *hub_users[] = {key1, user1};
        expect_pairs(detector, input, len, keys, i ? users : hub_users, i ? 1 : 2);
        len = pair_input(input, sizeof(input), "accessKey", key1, user_prefixes[i], user1);
        expect_pairs(detector, input, len, keys, users, 1);
    }
    len = pair_input(input, sizeof(input), "hub-cloudXbrowserstackYcom", key1, "userName", user1);
    const char *hub_users[] = {key1, user1};
    expect_pairs(detector, input, len, keys, hub_users, 2); /* Source dots are regex wildcards. */
    len = pair_input(input, sizeof(input), "aCcEsSkEy", key1, "uSeRnAmE", user1);
    expect_pairs(detector, input, len, keys, users, 1);
    len = pair_input(input, sizeof(input), "browserstack", key1, "browserstack", user1);
    expect_pairs(detector, input, len, NULL, NULL, 0); /* Dispatch keyword is not an extraction prefix. */
    const char *bad_keys[] = {"aB3dE6gH9jK2mN5pQ8s", "aB3dE6gH9jK2mN5pQ8sTA", "_aB3dE6gH9jK2mN5pQ8sT",
                              "aB3dE6gH9jK2mN5pQ8sT_", "aB3dE6gH9+K2mN5pQ8sT"};
    for (size_t i = 0; i < sizeof(bad_keys) / sizeof(bad_keys[0]); ++i) {
        len = pair_input(input, sizeof(input), "accessKey", bad_keys[i], "userName", user1);
        expect_pairs(detector, input, len, NULL, NULL, 0);
    }
    const char *valid_users[] = {"AbC123def", "abcdefghijklmnopqrstuvwxyz123", "abc.-_123456", "abcdefghijklmnopqr._-12345678901"};
    for (size_t i = 0; i < sizeof(valid_users) / sizeof(valid_users[0]); ++i) {
        len = pair_input(input, sizeof(input), "accessKey", key1, "userName", valid_users[i]);
        const char *wanted[] = {valid_users[i]}; expect_pairs(detector, input, len, keys, wanted, 1);
    }
    const char *bad_users[] = {"abc123de", "abcdefghijklmnopqrstuvwxyz1234", "ab.-123456", "abc.-12345", "_AbC123def", "AbC123def_"};
    for (size_t i = 0; i < sizeof(bad_users) / sizeof(bad_users[0]); ++i) {
        len = pair_input(input, sizeof(input), "accessKey", key1, "userName", bad_users[i]);
        expect_pairs(detector, input, len, NULL, NULL, 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        char padding[42]; memset(padding, ':', gap); padding[gap] = 0;
        int n = snprintf(input, sizeof(input), "accessKey%s%s\n%s\nuserName %s", padding, key1, isolation, user1);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_pairs(detector, input, (size_t)n, keys, users, gap == 40 ? 1 : 0);
        n = snprintf(input, sizeof(input), "accessKey %s\n%s\nuserName%s%s", key1, isolation, padding, user1);
        CHECK(n > 0 && (size_t)n < sizeof(input));
        expect_pairs(detector, input, (size_t)n, keys, users, gap == 40 ? 1 : 0);
    }
    len = pair_input(input, sizeof(input), "accessKey", "AAAAAAAAAAAAAAAAAAAA", "userName", "AAAAAAAAA");
    const char *low_keys[] = {"AAAAAAAAAAAAAAAAAAAA"}, *low_users[] = {"AAAAAAAAA"};
    expect_pairs(detector, input, len, low_keys, low_users, 1);
    expect_pairs(detector, NULL, 0, NULL, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len && ctx && ctx->transport->user == http);
    CHECK(request->profile == BR_HTTP_BROWSERSTACK && request->detector_type == 756);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://www.browserstack.com/automate/plan.json"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    if (expected->deadline_cap) CHECK(request->timeout_ms > 0 && request->timeout_ms <= expected->deadline_cap);
    else CHECK(request->timeout_ms == 0);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json") && !strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, ctx->user_agent ? "TruffleHog browserstack-test" : "TruffleHog"));
    const char *auth = request->headers[1].value;
    CHECK(!strncmp(auth, "Basic ", 6));
    size_t encoded = strlen(auth + 6), ulen = strlen(expected->users[http->calls - 1]), klen = strlen(expected->keys[http->calls - 1]);
    CHECK(encoded == 4 * ((ulen + 1 + klen + 2) / 3) && encoded <= INT_MAX);
    unsigned char *decoded = malloc(encoded / 4 * 3 + 1); CHECK(decoded);
    int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)auth + 6, (int)encoded);
    CHECK(decoded_len >= 0);
    if (auth[6 + encoded - 1] == '=') --decoded_len;
    if (auth[6 + encoded - 2] == '=') --decoded_len;
    CHECK((size_t)decoded_len == ulen + 1 + klen && decoded[ulen] == ':');
    CHECK(!memcmp(decoded, expected->users[http->calls - 1], ulen));
    CHECK(!memcmp(decoded + ulen + 1, expected->keys[http->calls - 1], klen));
    free(decoded);
    CHECK(http->releases == http->calls - 1);
    if (expected->fail_second && http->calls == 2) {
        http->response.status = 429;
        fail_status_copy = true;
    }
}

static void products(const br_detector *detector)
{
    char input[1024];
    int n = snprintf(input, sizeof(input), "accessKey %s\n%s\naccessKey %s\n%s\naccessKey %s\n%s\nuserName %s\n%s\nuserName %s\n%s\nuserName %s",
                     key1, isolation, key2, isolation, key1, isolation, user1, isolation, user2, isolation, user1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1, key1, key2, key2, key2, key1, key1, key1};
    const char *users[] = {user1, user2, user1, user1, user2, user1, user1, user2, user1};
    expected_requests expected = {keys, users, 9, 0, false};
    for (int mode = 0; mode < 3; ++mode) {
        const char *cause = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL;
        test_http http = {.response = {.status = 200}, .send_rc = mode == 2 ? 1 : 0, .send_error = cause,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, (size_t)n);
        CHECK(results.len == 9 && http.calls == (mode ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) {
            pair_result(&results.items[i], keys[i], users[i]);
            CHECK(results.items[i].verified == (mode == 1));
            if (cause) CHECK(results.items[i].verification_error && !strcmp(results.items[i].verification_error, cause));
            else CHECK(!results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, (size_t)n);
    CHECK(results.len == 9);
    for (size_t i = 0; i < 9; ++i) {
        pair_result(&results.items[i], keys[i], users[i]);
        CHECK(!results.items[i].verified && !strcmp(results.items[i].verification_error, "net/http: nil Context"));
    }
    br_results_clear(&results);
}

static void long_username(const br_detector *detector)
{
    const size_t separators = 8192, ulen = 3 + separators + 6;
    char *username = malloc(ulen + 1), *input = malloc(ulen + 256); CHECK(username && input);
    memcpy(username, "abc", 3); memset(username + 3, '.', separators); memcpy(username + 3 + separators, "defghi", 7);
    size_t len = pair_input(input, ulen + 256, "accessKey", key1, "userName", username);
    const char *keys[] = {key1}, *users[] = {username};
    expect_pairs(detector, input, len, keys, users, 1);
    expected_requests expected = {keys, users, 1, 0, false};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, len);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    pair_result(&results.items[0], key1, username);
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results); free(username); free(input);
}

static void verification(const br_detector *detector)
{
    char input[512], cause[256], redacted[256];
    size_t len = pair_input(input, sizeof(input), "accessKey", key1, "userName", user1);
    snprintf(cause, sizeof(cause), "key=%s username=%s again=%s", key1, user1, key1);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] username=%s again=[REDACTED]", user1);
    static const unsigned char binary[] = {'X', 0, 0xff, 'b', 'l', 'o', 'c', 'k', 'e', 'd', '!'};
    static const unsigned char upper[] = "BLOCKED";
    const br_slice blocked = {binary, sizeof(binary)};
    const struct { int status; br_slice body; const char *read_error; int send_rc; const char *send_error; bool verified; const char *error; } cases[] = {
        {200, blocked, cause, 0, NULL, true, NULL},
        {401, blocked, cause, 0, NULL, false, NULL},
        {403, blocked, NULL, 0, NULL, false, "blocked by browserstack"},
        {403, blocked, cause, 0, NULL, false, redacted},
        {403, {upper, sizeof(upper) - 1}, NULL, 0, NULL, false, NULL},
        {403, {NULL, 0}, NULL, 0, NULL, false, NULL},
        {201, blocked, cause, 0, NULL, false, "unexpected HTTP response status 201"},
        {429, blocked, cause, 0, NULL, false, "unexpected HTTP response status 429"},
        {500, blocked, cause, 0, NULL, false, "unexpected HTTP response status 500"},
        {200, blocked, NULL, 1, cause, false, redacted},
        {200, blocked, NULL, -1, "context canceled", false, "context canceled"},
        {200, blocked, NULL, 1, "lookup synthetic.invalid: no such host", false, "lookup synthetic.invalid: no such host"},
        {200, blocked, NULL, 1, NULL, false, "HTTP transport failed"},
        {200, blocked, NULL, 0, NULL, true, NULL},
    };
    const char *keys[] = {key1}, *users[] = {user1}; expected_requests expected = {keys, users, 1, 0, false};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "browserstack-test"};
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        pair_result(&results.items[0], key1, user1);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        if (cases[i].error == redacted) {
            CHECK(!strstr(results.items[0].verification_error, key1));
            CHECK(strstr(results.items[0].verification_error, user1));
        }
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static int64_t now_ms(void)
{
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void contexts(const br_detector *detector)
{
    char input[512]; size_t len = pair_input(input, sizeof(input), "accessKey", key1, "userName", user1);
    const char *keys[] = {key1}, *users[] = {user1};
    for (int mode = 0; mode < 4; ++mode) {
        expected_requests expected = {keys, users, 1, mode == 2 ? 5000u : 0, false};
        test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        if (mode == 0) ctx.cancelled = cancelled;
        if (mode == 1) ctx.deadline_monotonic_ms = 1;
        if (mode == 2) ctx.deadline_monotonic_ms = now_ms() + 5000;
        if (mode == 3) ctx.deadline_monotonic_ms = now_ms() + (int64_t)UINT32_MAX + 60000;
        br_results results = test_scan(detector, &ctx, true, input, len);
        CHECK(results.len == 1 && http.calls == (mode == 2 ? 1u : 0u) && http.releases == 1);
        pair_result(&results.items[0], key1, user1);
        if (mode == 2) CHECK(results.items[0].verified && !results.items[0].verification_error);
        else {
            const char *error = mode == 0 ? "context canceled" : mode == 1 ? "context deadline exceeded" :
                                "unsupported: BrowserStack deadline exceeds 32-bit timeout";
            CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, error));
        }
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    br_result probe = {0}; fail_status_copy = true;
    CHECK(br_result_set_verification_error(&probe, "unexpected HTTP response status 429", NULL, 0) == 1);
    CHECK(!fail_status_copy && !probe.verification_error); br_result_clear(&probe);
    char *auth = NULL;
    CHECK(br_http_basic_auth((br_slice){NULL, 1}, (br_slice){0}, &auth, NULL) == 1 && !auth);

    char input[768];
    int n = snprintf(input, sizeof(input), "accessKey %s\n%s\nuserName %s\n%s\nuserName %s", key1, isolation, user1, isolation, user2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key1}, *users[] = {user1, user2};
    expected_requests expected = {keys, users, 2, 0, true};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
    unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
    char *error = NULL;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory recording BrowserStack verification error"));
    CHECK(!fail_status_copy && http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
    CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
    CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned"));
    free(error); br_results_clear(&results);
    expected.fail_second = false; http.calls = http.releases = 0; http.response.status = 200;
    results = test_scan(detector, &ctx, true, input, (size_t)n);
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < 2; ++i) { pair_result(&results.items[i], keys[i], users[i]); CHECK(results.items[i].verified); }
    br_results_clear(&results);
}

int main(void)
{
    CHECK(strlen(key1) == 20 && strlen(key2) == 20);
    const br_detector *detector = descriptor();
    extraction(detector); products(detector); long_username(detector); verification(detector); contexts(detector); resource_rollback(detector);
    return test_finish("BrowserStack");
}
