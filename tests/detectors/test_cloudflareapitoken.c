/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char old_key[41], old_other[41], user_key[54], account_key[54];
static const char id1[] = "0123456789abcdef0123456789abcdef", id2[] = "fedcba9876543210fedcba9876543210";
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;
static size_t fail_finding_after;

char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(value) + 1; char *copy = malloc(len); if (copy) memcpy(copy, value, len); return copy;
}

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32 || len == 40 || len == 53);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[54]; memcpy(copy, value, (size_t)len); copy[len] = '\0'; return json_object_new_string(copy);
}

typedef struct { const char *token, *account; } expected_pair;
typedef struct {
    const expected_pair *pairs; size_t count;
    const int *statuses;
    bool mutate_error, mutated;
    char *returned_error;
} expected_requests;

static const br_detector *descriptor(int version)
{
    int (*factory)(const br_detector **, char **) = version == 1 ? br_cloudflareapitoken_v1_init : br_cloudflareapitoken_v2_init;
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(factory(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 100 && detector->version == version && !strcmp(detector->name, "CloudflareApiToken") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, version == 1
        ? "Cloudflare is a web infrastructure and website security company, providing content delivery network services, DDoS mitigation, Internet security, and distributed domain name server services. Cloudflare API tokens can be used to manage and interact with Cloudflare services."
        : "Cloudflare is a web infrastructure and website security company. Cloudflare API tokens (cfut_/cfat_ prefixed, 2026+ format) can be used to manage and interact with Cloudflare services."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == (version == 1 ? -1 : 1024));
    CHECK(detector->nkeywords == (version == 1 ? 1u : 2u));
    CHECK(!strcmp(detector->keywords[0], version == 1 ? "cloudflare" : "cfut_"));
    if (version == 2) CHECK(!strcmp(detector->keywords[1], "cfat_"));
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *state = detector->state;
    CHECK(factory(&again, &error) == 0 && !error && again == detector && again->state == state);
    CHECK(factory(&again, NULL) == 0 && again == detector && again->state == state);
    CHECK(factory(NULL, &error) != 0 && error && !strcmp(error, version == 1 ? "invalid CloudflareApiToken v1 detector output" : "invalid CloudflareApiToken v2 detector output"));
    free(error); CHECK(factory(NULL, NULL) != 0); return detector;
}

static void check_result(const br_result *result, const char *token, const char *account, bool verified, const char *error)
{
    size_t len = strlen(token);
    CHECK(result->detector_type == 100 && !result->detector_name && result->raw.len == len && !memcmp(result->raw.data, token, len));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == (account ? 2 : 1));
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == (int)len && !strcmp(json_object_get_string(part), token));
    if (account) {
        CHECK(result->raw_v2.len == len + 32 && !memcmp(result->raw_v2.data, token, len) && !memcmp(result->raw_v2.data + len, account, 32));
        CHECK(json_object_object_get_ex(result->secret_parts, "account_id", &part));
        CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == 32 && !strcmp(json_object_get_string(part), account));
    } else {
        CHECK(!result->raw_v2.data && !result->raw_v2.len);
        CHECK(!json_object_object_get_ex(result->secret_parts, "account_id", &part));
    }
    CHECK(result->verified == verified && !result->verification_from_cache);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error)); else CHECK(!result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set && !result->chunk_offset);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *token, const char *account)
{
    br_results results = test_scan(detector, NULL, false, input, len); CHECK(results.len == (token ? 1u : 0u));
    if (token) check_result(&results.items[0], token, account, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    char input[256], changed[54];
    const struct { const char *format; bool match; } cases[] = {
        {"cloudflare '%s'", true}, {"CLOUDFLARE=%s", true}, {"preCloudflaresuffix %s", true},
        {"cloudflare\r\n%s", true}, {"%s", false}, {"%s cloudflare", false},
        {"cloudflare%s", false}, {"cloudflare _%s", false}, {"cloudflare %s_", false},
        {"cloudflare %sQ", false}, {"cloudflare %.39s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, old_key);
        extraction_case(v1, input, strlen(input), cases[i].match ? old_key : NULL, NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "cloudflare", 10); memset(input + 10, ':', gap); memcpy(input + 10 + gap, old_key, sizeof(old_key));
        extraction_case(v1, input, strlen(input), gap == 40 ? old_key : NULL, NULL);
    }
    memcpy(changed, old_key, sizeof(old_key)); changed[0] = '-';
    snprintf(input, sizeof(input), "cloudflare %s", changed); extraction_case(v1, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "cloudflare Q%s", changed); extraction_case(v1, input, strlen(input), changed, NULL);
    memcpy(changed, old_key, sizeof(old_key)); changed[39] = '-';
    snprintf(input, sizeof(input), "cloudflare %s", changed); extraction_case(v1, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "cloudflare %sQ", changed); extraction_case(v1, input, strlen(input), changed, NULL);
    memset(changed, 'Z', 40); changed[40] = '\0'; snprintf(input, sizeof(input), "cloudflare %s", changed);
    extraction_case(v1, input, strlen(input), changed, NULL); /* No entropy/JWT filtering. */
    memcpy(changed, old_key, sizeof(old_key)); changed[20] = '+';
    snprintf(input, sizeof(input), "CLOUDFLARE %s", changed); extraction_case(v1, input, strlen(input), NULL, NULL);
    extraction_case(v2, user_key, strlen(user_key), user_key, NULL);
    extraction_case(v2, account_key, strlen(account_key), account_key, NULL);
    snprintf(input, sizeof(input), "X%s", user_key); extraction_case(v2, input, strlen(input), NULL, NULL);
    snprintf(input, sizeof(input), "%s_", user_key); extraction_case(v2, input, strlen(input), NULL, NULL);
    memcpy(changed, user_key, sizeof(user_key)); changed[0] = 'C'; extraction_case(v2, changed, strlen(changed), NULL, NULL);
    memcpy(changed, user_key, sizeof(user_key)); changed[15] = '_'; extraction_case(v2, changed, strlen(changed), NULL, NULL);
    memcpy(changed, user_key, sizeof(user_key)); changed[50] = 'A'; extraction_case(v2, changed, strlen(changed), NULL, NULL); /* Lowerhex checksum only. */
    memcpy(changed, user_key, sizeof(user_key)); changed[52] = '\0'; extraction_case(v2, changed, strlen(changed), NULL, NULL);
    snprintf(input, sizeof(input), "%s %s %s", account_key, id1, id1); extraction_case(v2, input, strlen(input), account_key, id1);
    snprintf(input, sizeof(input), "%s X%sZ", account_key, id1); extraction_case(v2, input, strlen(input), account_key, NULL);
    char upper_id[33]; memcpy(upper_id, id1, sizeof(upper_id)); upper_id[12] = 'A';
    snprintf(input, sizeof(input), "%s %s", account_key, upper_id); extraction_case(v2, input, strlen(input), account_key, NULL);
    char far[1280]; size_t at = strlen(account_key); memcpy(far, account_key, at); memset(far + at, '!', 1100); at += 1100;
    memcpy(far + at, id1, 32); at += 32; extraction_case(v2, far, at, account_key, id1); /* Whole input, not a scanner-local proximity filter. */
    extraction_case(v1, NULL, 0, NULL, NULL); extraction_case(v2, NULL, 0, NULL, NULL);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user; CHECK(http->calls > 0 && http->calls <= expected->count && http->releases + 1 == http->calls);
    const expected_pair *pair = &expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http && request->detector_type == 100 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    char url[112];
    if (pair->account) snprintf(url, sizeof(url), "https://api.cloudflare.com/client/v4/accounts/%s/tokens/verify", pair->account);
    else snprintf(url, sizeof(url), "https://api.cloudflare.com/client/v4/user/tokens/verify");
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    size_t auth = 0, type = 0, ua = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Authorization")) { ++auth; CHECK(!strncmp(header->value, "Bearer ", 7) && !strcmp(header->value + 7, pair->token)); }
        else if (!strcmp(header->name, "Content-Type")) { ++type; CHECK(!strcmp(header->value, "application/json")); }
        else if (!strcmp(header->name, "User-Agent")) { ++ua; CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog cf-api-test" : "TruffleHog")); }
        else CHECK(!"unexpected API-token header (no CA authentication, Accept or logical Content-Length)");
    }
    CHECK(auth == 1 && type == 1 && ua == 1);
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
}

static int send_response(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; expected_requests *expected = http->user; int rc = test_http_send(user, ctx, request, response, error);
    expected->returned_error = *error; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_requests *expected = http->user;
    if (expected->mutate_error && expected->returned_error) { memset(expected->returned_error, '!', strlen(expected->returned_error)); expected->mutated = true; }
    expected->returned_error = NULL; test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, send_response, release_response}; }

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify, const char *token, const char *account, bool verified, const char *error)
{
    char input[192];
    int n = snprintf(input, sizeof(input), "%s%s%s%s", detector->version == 1 ? "cloudflare " : "", token, account ? " " : "", account ? account : "");
    CHECK(n > 0 && (size_t)n < sizeof(input));
    br_results results = test_scan(detector, ctx, verify, input, (size_t)n); CHECK(results.len == 1);
    check_result(&results.items[0], token, account, verified, error); br_results_clear(&results);
}

static void projections_and_occurrences(const br_detector *v1, const br_detector *v2)
{
    char input[512];
    snprintf(input, sizeof(input), "cloudflare %s\ncloudflare %s\ncloudflare %s", old_key, old_other, old_key);
    const expected_pair old_pairs[] = {{old_key, NULL}, {old_other, NULL}, {old_key, NULL}};
    expected_requests expected = {.pairs = old_pairs, .count = 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored read/drain/close error"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(v1, &ctx, true, input, strlen(input)); CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], old_pairs[i].token, NULL, true, NULL);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s\n%s %s %s", account_key, user_key, account_key, id1, id2, id1);
    const expected_pair new_pairs[] = {{account_key, id1}, {account_key, id2}, {user_key, NULL}, {account_key, id1}, {account_key, id2}};
    expected = (expected_requests){.pairs = new_pairs, .count = 5}; http.calls = http.releases = 0;
    for (int verify = 0; verify < 2; ++verify) {
        results = test_scan(v2, &ctx, verify != 0, input, strlen(input)); CHECK(results.len == 5 && http.calls == (verify ? 5u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 5; ++i) check_result(&results.items[i], new_pairs[i].token, new_pairs[i].account, verify != 0, NULL);
        br_results_clear(&results);
    }
    results = test_scan(v2, NULL, true, input, strlen(input)); CHECK(results.len == 5);
    for (size_t i = 0; i < 5; ++i) check_result(&results.items[i], new_pairs[i].token, new_pairs[i].account, false, "net/http: nil Context");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", account_key, account_key); http.calls = http.releases = 0;
    for (int nil_ctx = 0; nil_ctx < 2; ++nil_ctx) {
        results = test_scan(v2, nil_ctx ? NULL : &ctx, true, input, strlen(input)); CHECK(results.len == 2 && !http.calls && !http.releases);
        for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], account_key, NULL, false, NULL);
        br_results_clear(&results);
    }
    expect_one(v2, NULL, false, account_key, NULL, false, NULL);
}

static void status_and_redaction(const br_detector *detector, const char *token, const char *account, const char *other)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL}, {201, false, "unexpected status code: 201"},
        {204, false, "unexpected status code: 204"}, {299, false, "unexpected status code: 299"}, {503, false, status_503},
    };
    const expected_pair pair[] = {{token, account}}; expected_requests expected = {.pairs = pair, .count = 1};
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body)}, .body_error = "ignored body/read/drain/close error"}, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "cf-api-test"};
        expect_one(detector, &ctx, true, token, account, statuses[i].verified, statuses[i].error); CHECK(http.calls == 1 && http.releases == 1);
    }
    char cause[384], redacted[256];
    snprintf(cause, sizeof(cause), "token=%s repeat=%s account=%s keep=%s partial=%s", token, token, account ? account : id1, other, token + 20);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] repeat=[REDACTED] account=%s keep=%s partial=%s", account ? account : id1, other, token + 20);
    const struct { const char *cause, *error; } failures[] = {
        {cause, redacted}, {"lookup synthetic.invalid: no such host", "lookup synthetic.invalid: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        expected.mutate_error = i == 0; expected.mutated = false;
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body)}, .body_error = "must not replace Do error"}, .send_rc = i % 2 ? -1 : 1,
                          .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, token, account, false, failures[i].error); CHECK(http.calls == 1 && http.releases == 1);
        if (i == 0) CHECK(expected.mutated);
    }
    expect_one(detector, NULL, true, token, account, false, "net/http: nil Context");
    expect_one(detector, NULL, false, token, account, false, NULL);
}

static bool cancelled(void *user) { (void)user; return true; }
static void context_errors(const br_detector *detector, const char *token, const char *account)
{
    const expected_pair pair[] = {{token, account}}; expected_requests expected = {.pairs = pair, .count = 1};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport, .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        expect_one(detector, &ctx, true, token, account, false, mode == 0 ? "context canceled" : mode == 1 ? "context deadline exceeded" : "HTTP transport not installed");
        CHECK(!http.calls && http.releases == (mode == 2 ? 0u : 1u));
    }
}

static void resource_rollback(const br_detector *detector, const char *input, const expected_pair pairs[2], size_t finding_failure_at, const char *finding_error)
{
    const int statuses[] = {200, 503}; expected_requests expected = {.pairs = pairs, .count = 2, .statuses = statuses};
    for (int finding_failure = 0; finding_failure < 2; ++finding_failure) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
        br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0); char *error = NULL;
        if (finding_failure) fail_finding_after = finding_failure_at; else fail_status_copy = true;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, finding_failure ? finding_error : "cannot store CloudflareApiToken verification error"));
        CHECK(!fail_status_copy && !fail_finding_after && http.calls == (finding_failure ? 1u : 2u) && http.releases == http.calls && results.len == 1);
        CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4 && results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
        CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned")); free(error); br_results_clear(&results);
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        check_result(&results.items[0], pairs[0].token, pairs[0].account, true, NULL);
        check_result(&results.items[1], pairs[1].token, pairs[1].account, false, status_503); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(old_key, 40, 0); old_key[0] = 'A'; old_key[10] = '_'; old_key[22] = '-'; old_key[39] = 'Z';
    memcpy(old_other, old_key, sizeof(old_other)); old_other[0] = 'Q';
    char body[41]; test_secret(body, 40, 9); body[0] = 'Q';
    snprintf(user_key, sizeof(user_key), "cfut_%s0abc12de", body); snprintf(account_key, sizeof(account_key), "cfat_%s0abc12de", body);
    CHECK(strlen(user_key) == 53 && strlen(id1) == 32 && strlen(id2) == 32);
    const br_detector *v1 = descriptor(1), *v2 = descriptor(2); CHECK(v1 != v2 && v1->scan != v2->scan && v1->state != v2->state);
    extraction(v1, v2); projections_and_occurrences(v1, v2);
    status_and_redaction(v1, old_key, NULL, old_other); status_and_redaction(v2, user_key, NULL, account_key); status_and_redaction(v2, account_key, id1, user_key);
    context_errors(v1, old_key, NULL); context_errors(v2, user_key, NULL); context_errors(v2, account_key, id1);
    char input[256];
    snprintf(input, sizeof(input), "cloudflare %s\ncloudflare %s", old_key, old_other);
    const expected_pair old_pairs[] = {{old_key, NULL}, {old_other, NULL}};
    resource_rollback(v1, input, old_pairs, 2, "cannot create CloudflareApiToken v1 result");
    snprintf(input, sizeof(input), "%s %s", user_key, user_key);
    const expected_pair user_pairs[] = {{user_key, NULL}, {user_key, NULL}};
    resource_rollback(v2, input, user_pairs, 2, "cannot create CloudflareApiToken v2 key result");
    snprintf(input, sizeof(input), "%s %s %s", account_key, id1, id2);
    const expected_pair account_pairs[] = {{account_key, id1}, {account_key, id2}};
    resource_rollback(v2, input, account_pairs, 3, "cannot create CloudflareApiToken v2 account result");
    return test_finish("CloudflareApiToken distinct v1/v2 projections + occurrence products + common verification");
}
