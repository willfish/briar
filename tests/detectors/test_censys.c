/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char token1[33], token2[33], user1[37], user2[37];
static size_t fail_basic_after, fail_finding_after;
typedef struct { const char *const *tokens; size_t ntokens; const char *const *users; size_t nusers; } expected_requests;

/* The real byte-aware Basic helper allocates exactly 7+4*ceil(69/3)=99 bytes
 * for these 36:32 credentials. Fail that allocation, not the HTTP send domain.
 * Zero-filled forwarding memory remains a valid malloc result. */
void *malloc(size_t size)
{
    if (size == 99 && fail_basic_after && --fail_basic_after == 0) return NULL;
    return calloc(1, size);
}

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32 || len == 36);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[37]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_censys_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 524 && detector->version == 0 && !strcmp(detector->name, "Censys"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Censys is a search engine that enables researchers to ask questions about the hosts and networks "
        "that compose the Internet. Censys API keys can be used to access and query this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "censys"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_censys_init(&again, &error) == 0 && !error && again == detector && again->state == detector->state);
    CHECK(br_censys_init(&again, NULL) == 0 && again == detector);
    CHECK(br_censys_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Censys detector output"));
    free(error);
    CHECK(br_censys_init(NULL, NULL) != 0);
    return detector;
}

static void check_pair(const br_result *result, const char *token, const char *user, bool verified)
{
    CHECK(result->detector_type == 524 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, token, 32));
    CHECK(result->raw_v2.len == 68 && !memcmp(result->raw_v2.data, token, 32) && !memcmp(result->raw_v2.data + 32, user, 36));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part));
    CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), token, 32));
    CHECK(json_object_object_get_ex(result->secret_parts, "username", &part));
    CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == 36 && !memcmp(json_object_get_string(part), user, 36));
    CHECK(!json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void pair_input(char *out, size_t cap, const char *token, const char *user)
{
    int n = snprintf(out, cap, "censys %s\ncensys %s", token, user);
    CHECK(n > 0 && (size_t)n < cap);
}

static void expect_extraction(const br_detector *detector, const void *input, size_t len,
                               const char *token, const char *user, size_t count)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_pair(&results.items[i], token, user, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed_token[34], changed_user[38];
    pair_input(input, sizeof(input), token1, user1); expect_extraction(detector, input, strlen(input), token1, user1, 1);
    snprintf(input, sizeof(input), "CENSYS=%s\npreCeNsYssuffix '%s'", user1, token1);
    expect_extraction(detector, input, strlen(input), token1, user1, 1);
    snprintf(input, sizeof(input), "%s\n%s", token1, user1); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    snprintf(input, sizeof(input), "censys %s", token1); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    snprintf(input, sizeof(input), "censys %s", user1); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    memcpy(changed_token, token1, sizeof(token1)); changed_token[10] = '-';
    pair_input(input, sizeof(input), changed_token, user1); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    memcpy(changed_token, token1, sizeof(token1)); changed_token[32] = '_'; changed_token[33] = '\0';
    pair_input(input, sizeof(input), changed_token, user1); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    memcpy(changed_user, user1, sizeof(user1)); changed_user[10] = 'A';
    pair_input(input, sizeof(input), token1, changed_user); expect_extraction(detector, input, strlen(input), NULL, NULL, 0); /* Username stays lowercase. */
    memcpy(changed_user, user1, sizeof(user1)); changed_user[35] = '\0';
    pair_input(input, sizeof(input), token1, changed_user); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    memcpy(changed_user, user1, sizeof(user1)); changed_user[36] = 'z'; changed_user[37] = '\0';
    pair_input(input, sizeof(input), token1, changed_user); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    memset(changed_token, 'Z', 32); changed_token[32] = '\0';
    pair_input(input, sizeof(input), changed_token, user2); expect_extraction(detector, input, strlen(input), changed_token, user2, 1); /* No entropy/UUID/hex filtering. */
    memset(changed_user, 'q', 17); changed_user[17] = '-'; memset(changed_user + 18, 'z', 18); changed_user[36] = '\0';
    pair_input(input, sizeof(input), token1, changed_user); expect_extraction(detector, input, strlen(input), token1, changed_user, 1); /* Arbitrary 17-18 shape. */
    memset(changed_user, 'q', 36); changed_user[0] = '-'; changed_user[36] = '\0';
    pair_input(input, sizeof(input), token1, changed_user); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    snprintf(input, sizeof(input), "censys %s\ncensys X%s", token1, changed_user);
    expect_extraction(detector, input, strlen(input), token1, changed_user, 1); /* Outside word byte supplies leading '-' boundary. */
    memset(changed_user, 'q', 36); changed_user[35] = '-';
    pair_input(input, sizeof(input), token1, changed_user); expect_extraction(detector, input, strlen(input), NULL, NULL, 0);
    snprintf(input, sizeof(input), "censys %s\ncensys %sX", token1, changed_user);
    expect_extraction(detector, input, strlen(input), token1, changed_user, 1);
    memset(changed_user, '-', 36);
    snprintf(input, sizeof(input), "censys %s\ncensys X%sX", token1, changed_user);
    expect_extraction(detector, input, strlen(input), token1, changed_user, 1); /* Even all-hyphen shape is permitted by source. */
    for (int field = 0; field < 2; ++field) for (size_t gap = 40; gap <= 41; ++gap) {
        char prefixed[128]; memcpy(prefixed, "censys", 6); memset(prefixed + 6, ':', gap);
        const char *value = field ? user1 : token1;
        memcpy(prefixed + 6 + gap, value, strlen(value) + 1);
        if (field) snprintf(input, sizeof(input), "censys %s\n%s", token1, prefixed);
        else snprintf(input, sizeof(input), "%s\ncensys %s", prefixed, user1);
        expect_extraction(detector, input, strlen(input), token1, user1, gap == 40 ? 1 : 0);
    }
    expect_extraction(detector, NULL, 0, NULL, NULL, 0);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->ntokens * expected->nusers && http->releases + 1 == http->calls);
    const char *token = expected->tokens[(http->calls - 1) / expected->nusers];
    const char *user = expected->users[(http->calls - 1) % expected->nusers];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://search.censys.io/api/v1/account"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 524);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    unsigned char plaintext[69], encoded[93];
    memcpy(plaintext, user, 36); plaintext[36] = ':'; memcpy(plaintext + 37, token, 32);
    CHECK(EVP_EncodeBlock(encoded, plaintext, sizeof(plaintext)) == 92); /* Independent byte-order/encoding oracle. */
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *field = &request->headers[i];
        if (!strcmp(field->name, "Authorization")) {
            ++auth; CHECK(!strncmp(field->value, "Basic ", 6) && !strcmp(field->value + 6, (const char *)encoded));
        } else if (!strcmp(field->name, "User-Agent")) {
            ++agent; CHECK(!strcmp(field->value, ctx->user_agent ? "TruffleHog censys-test" : "TruffleHog"));
        } else CHECK(!"unexpected Censys header (no Content-Type, Accept or explicit length)");
    }
    CHECK(auth == 1 && agent == 1);
}

static void occurrences_and_products(const br_detector *detector)
{
    char input[320]; snprintf(input, sizeof(input), "censys %s\ncensys %s\ncensys %s\ncensys %s\ncensys %s\ncensys %s", user1, token1, user2, token2, user1, token1);
    const char *tokens[] = {token1, token2, token1}, *users[] = {user1, user2, user1};
    expected_requests expected = {tokens, 3, users, 3};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 204, .body_error = "ignored read/close error"},
                          .send_rc = mode == 2 ? 1 : 0, .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL,
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 9 && http.calls == (mode ? 9u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) check_pair(&results.items[i], tokens[i / 3], users[i % 3], mode == 1);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 9);
    for (size_t i = 0; i < 9; ++i) check_pair(&results.items[i], tokens[i / 3], users[i % 3], false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
}

static void status_and_do_errors(const br_detector *detector)
{
    char input[96], sensitive[192]; pair_input(input, sizeof(input), token2, user2);
    snprintf(sensitive, sizeof(sensitive), "synthetic Do/read error username=%s token=%s", user2, token2);
    const char *tokens[] = {token2}, *users[] = {user2}; expected_requests expected = {tokens, 1, users, 1};
    const struct { int status, send_rc; const char *send_error; bool verified; } cases[] = {
        {199, 0, NULL, false}, {200, 0, NULL, true}, {201, 0, NULL, true}, {204, 0, NULL, true},
        {206, 0, NULL, true}, {299, 0, NULL, true}, {300, 0, NULL, false}, {400, 0, NULL, false},
        {401, 0, NULL, false}, {403, 0, NULL, false}, {429, 0, NULL, false}, {500, 0, NULL, false},
        {200, 1, "lookup synthetic.invalid: no such host", false}, {200, -1, "context canceled", false},
        {200, 7, sensitive, false}, {200, 1, "context deadline exceeded", false},
        {200, 1, "unsupported: synthetic SANE transport", false}, {200, 1, NULL, false},
        {200, 1, "net/http: nil Context", false}, /* Error text does NOT identify a constructor failure. */
        {200, -1, "out of memory preparing native request", false}, /* Unified ABI send-domain partial gap. */
        {200, 0, NULL, true},
    };
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body = {body, sizeof(body)}, .body_error = sensitive},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "censys-test"};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1); check_pair(&results.items[0], token2, user2, cases[i].verified);
        br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void suppressed_preflight_errors(const br_detector *detector)
{
    char input[96]; pair_input(input, sizeof(input), token1, user1);
    const char *tokens[] = {token1}, *users[] = {user1}; expected_requests expected = {tokens, 1, users, 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport, .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 2 ? 0u : 1u)); check_pair(&results.items[0], token1, user1, false);
        br_results_clear(&results);
    }
}

static void resource_rollback(const br_detector *detector)
{
    char *auth = NULL, *error = NULL;
    fail_basic_after = 1;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)user1, 36}, (br_slice){(const unsigned char *)token1, 32}, &auth, &error) == 1);
    CHECK(!fail_basic_after && !auth && error && !strcmp(error, "out of memory constructing Basic authentication")); free(error);
    char input[160]; snprintf(input, sizeof(input), "censys %s\ncensys %s\ncensys %s", token1, user1, user2);
    const char *tokens[] = {token1}, *users[] = {user1, user2}; expected_requests expected = {tokens, 1, users, 2};
    for (int finding_failure = 0; finding_failure < 2; ++finding_failure) {
        test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
        br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0);
        error = NULL;
        if (finding_failure) fail_finding_after = 3; else fail_basic_after = 2;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, finding_failure ? "out of memory creating Censys result" : "out of memory constructing Basic authentication"));
        CHECK(!fail_basic_after && !fail_finding_after && http.calls == 1 && http.releases == 1 && results.len == 1);
        CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
        CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
        CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned")); free(error); error = NULL;
        rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == 0 && !error && results.len == 1 && results.items[0].raw.data == original_raw); br_results_clear(&results);
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        for (size_t i = 0; i < 2; ++i) check_pair(&results.items[i], token1, users[i], true);
        br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(token1, 32, 0); test_secret(token2, 32, 17); token1[0] = 'A'; token2[31] = 'Z';
    test_secret(user1, 36, 9); memset(user2, 'z', 36); user2[36] = '\0';
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_products(detector); status_and_do_errors(detector);
    suppressed_preflight_errors(detector); resource_rollback(detector);
    return test_finish("Censys token-major occurrence products + byte Basic + suppressed Do errors");
}
