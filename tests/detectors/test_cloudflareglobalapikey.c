/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static char old_key[41], old_other[41], new_key[53], new_other[53];
static const char email1[] = "User@Example.test", email2[] = "user@example.test";
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;
static size_t fail_email_after, fail_part_after;

char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    if (fail_email_after && (!strcmp(value, email1) || !strcmp(value, email2)) && --fail_email_after == 0) return NULL;
    size_t len = strlen(value) + 1; char *copy = malloc(len); if (copy) memcpy(copy, value, len); return copy;
}

/* Forward complete, non-NUL captures without a fixture-side email length cap.
 * This targets finding allocation separately from Redacted and setter copies. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len > 0);
    if (fail_part_after && --fail_part_after == 0) return NULL;
    char *copy = malloc((size_t)len + 1); if (!copy) return NULL;
    memcpy(copy, value, (size_t)len); copy[len] = '\0';
    br_json *result = json_object_new_string(copy); free(copy); return result;
}

typedef struct { const char *key, *email; } expected_pair;
typedef struct {
    const expected_pair *pairs; size_t count; const int *statuses;
    bool mutate_error, mutated; char *returned_error;
} expected_requests;

static const br_detector *descriptor(int version)
{
    int (*factory)(const br_detector **, char **) = version == 1 ? br_cloudflareglobalapikey_v1_init : br_cloudflareglobalapikey_v2_init;
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(factory(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 58 && detector->version == version && !strcmp(detector->name, "CloudflareGlobalApiKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, version == 1
        ? "Cloudflare is a web infrastructure and website security company. Its services include content delivery network (CDN), DDoS mitigation, Internet security, and distributed domain name server (DNS) services. Cloudflare API keys can be used to access and modify these services."
        : "Cloudflare is a web infrastructure and website security company. Cloudflare API keys (cfk_ prefixed, 2026+ format) can be used to access and modify these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], version == 1 ? "cloudflare" : "cfk_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *state = detector->state;
    CHECK(factory(&again, &error) == 0 && !error && again == detector && again->state == state);
    CHECK(factory(&again, NULL) == 0 && again == detector && again->state == state);
    CHECK(factory(NULL, &error) != 0 && error && !strcmp(error, version == 1 ? "invalid CloudflareGlobalApiKey v1 detector output" : "invalid CloudflareGlobalApiKey v2 detector output"));
    free(error); CHECK(factory(NULL, NULL) != 0); return detector;
}

static void check_result(const br_result *result, const char *key, const char *email, bool verified, const char *error)
{
    size_t klen = strlen(key), elen = email ? strlen(email) : 0;
    CHECK(result->detector_type == 58 && !result->detector_name && result->raw.len == klen && !memcmp(result->raw.data, key, klen));
    CHECK(!result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == (email ? 2 : 1));
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == (int)klen && !strcmp(json_object_get_string(part), key));
    if (email) {
        CHECK(result->raw_v2.len == klen + elen && !memcmp(result->raw_v2.data, key, klen) && !memcmp(result->raw_v2.data + klen, email, elen));
        CHECK(result->redacted && strlen(result->redacted) == elen && !memcmp(result->redacted, email, elen));
        CHECK(json_object_object_get_ex(result->secret_parts, "email", &part));
        CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == (int)elen && !memcmp(json_object_get_string(part), email, elen));
    } else {
        CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted);
        CHECK(!json_object_object_get_ex(result->secret_parts, "email", &part));
    }
    CHECK(result->verified == verified && !result->verification_from_cache);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error)); else CHECK(!result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set && !result->chunk_offset);
}

static char *input_for(int version, const char *key, const char *email)
{
    size_t cap = strlen(key) + (email ? strlen(email) : 0) + 32;
    char *input = malloc(cap); CHECK(input);
    /* The source grammar's word boundaries require an outside word byte before
     * quoted local parts and after bracketed IP literals. Neither is captured. */
    int n = snprintf(input, cap, "%s%s%s%s%s", version == 1 ? "cloudflare " : "", key,
        email ? (email[0] == '"' ? " X" : " ") : "", email ? email : "",
        email && email[strlen(email) - 1] == ']' ? "X" : "");
    CHECK(n > 0 && (size_t)n < cap); return input;
}

static void extraction_case(const br_detector *detector, const char *input, const char *key, const char *email)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (key ? 1u : 0u));
    if (key) check_result(&results.items[0], key, email, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    char input[256], changed[54];
    for (size_t len = 36; len <= 46; ++len) {
        if (len != 36 && len != 37 && len != 40 && len != 45 && len != 46) continue;
        memset(changed, '0', len); changed[len] = '\0'; char *text = input_for(1, changed, email1);
        extraction_case(v1, text, len >= 37 && len <= 45 ? changed : NULL, email1); free(text);
    }
    snprintf(input, sizeof(input), "CLOUDFLARE %s %s", old_key, email1); extraction_case(v1, input, old_key, email1);
    snprintf(input, sizeof(input), "%s %s", old_key, email1); extraction_case(v1, input, NULL, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "cloudflare", 10); memset(input + 10, ':', gap);
        snprintf(input + 10 + gap, sizeof(input) - 10 - gap, "%s %s", old_key, email1);
        extraction_case(v1, input, gap == 40 ? old_key : NULL, email1);
    }
    memcpy(changed, old_key, sizeof(old_key)); changed[15] = 'A'; char *text = input_for(1, changed, email1);
    extraction_case(v1, text, NULL, NULL); free(text);
    changed[15] = 'g'; text = input_for(1, changed, email1); extraction_case(v1, text, NULL, NULL); free(text);
    text = input_for(2, new_key, email1); extraction_case(v2, text, new_key, email1); free(text);
    memcpy(changed, new_key, sizeof(new_key)); changed[0] = 'C'; text = input_for(2, changed, email1);
    extraction_case(v2, text, NULL, NULL); free(text);
    memcpy(changed, new_key, sizeof(new_key)); changed[20] = '_'; text = input_for(2, changed, email1);
    extraction_case(v2, text, NULL, NULL); free(text);
    memcpy(changed, new_key, sizeof(new_key)); changed[50] = 'A'; text = input_for(2, changed, email1);
    extraction_case(v2, text, NULL, NULL); free(text);
    snprintf(input, sizeof(input), "X%s %s", new_key, email1); extraction_case(v2, input, NULL, NULL);
    snprintf(input, sizeof(input), "%sQ %s", new_key, email1); extraction_case(v2, input, NULL, NULL);
    const char literal[] = "a@[192.0.2.1]";
    text = input_for(2, new_key, literal); extraction_case(v2, text, new_key, literal); free(text); /* Capture 1, not nested IP groups. */
    br_results results = test_scan(v1, NULL, false, NULL, 0); CHECK(!results.len); br_results_clear(&results);
    results = test_scan(v2, NULL, false, NULL, 0); CHECK(!results.len); br_results_clear(&results);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected_requests *expected = http->user; CHECK(http->calls > 0 && http->calls <= expected->count && http->releases + 1 == http->calls);
    const expected_pair *pair = &expected->pairs[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http && request->detector_type == 58 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.cloudflare.com/client/v4/user"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 4);
    size_t key = 0, email = 0, type = 0, ua = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "X-Auth-Key")) { ++key; CHECK(!strcmp(header->value, pair->key)); }
        else if (!strcmp(header->name, "X-Auth-Email")) { ++email; CHECK(strlen(header->value) == strlen(pair->email) && !memcmp(header->value, pair->email, strlen(pair->email))); }
        else if (!strcmp(header->name, "Content-Type")) { ++type; CHECK(!strcmp(header->value, "application/json")); }
        else if (!strcmp(header->name, "User-Agent")) { ++ua; CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog cf-global-test" : "TruffleHog")); }
        else CHECK(!"unexpected Global API header (no Bearer/CA auth, Accept or logical Content-Length)");
    }
    CHECK(key == 1 && email == 1 && type == 1 && ua == 1);
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
}

static int send_response(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; expected_requests *expected = http->user;
    int rc = test_http_send(user, ctx, request, response, error); expected->returned_error = *error; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; expected_requests *expected = http->user;
    if (expected->mutate_error && expected->returned_error) { memset(expected->returned_error, '!', strlen(expected->returned_error)); expected->mutated = true; }
    expected->returned_error = NULL; test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, send_response, release_response}; }

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify, const char *key, const char *email, bool verified, const char *error)
{
    char *input = input_for(detector->version, key, email);
    br_results results = test_scan(detector, ctx, verify, input, strlen(input)); CHECK(results.len == 1);
    check_result(&results.items[0], key, email, verified, error); br_results_clear(&results); free(input);
}

static void products_and_no_email(const br_detector *detector, const char *key, const char *other)
{
    char input[512]; const char *prefix = detector->version == 1 ? "cloudflare " : "";
    snprintf(input, sizeof(input), "%s %s %s\n%s%s\n%s%s\n%s%s", email1, email2, email1, prefix, key, prefix, other, prefix, key);
    const expected_pair pairs[] = {{key, email1}, {key, email2}, {other, email1}, {other, email2}, {key, email1}, {key, email2}};
    expected_requests expected = {.pairs = pairs, .count = 6};
    test_http http = {.response = {.status = 200, .body_error = "ignored read/drain/close error"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    for (int verify = 0; verify < 2; ++verify) {
        br_results results = test_scan(detector, &ctx, verify != 0, input, strlen(input)); CHECK(results.len == 6 && http.calls == (verify ? 6u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 6; ++i) check_result(&results.items[i], pairs[i].key, pairs[i].email, verify != 0, NULL);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 6);
    for (size_t i = 0; i < 6; ++i) check_result(&results.items[i], pairs[i].key, pairs[i].email, false, "net/http: nil Context");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s%s\n%s%s", prefix, key, prefix, key); http.calls = http.releases = 0;
    for (int nil_ctx = 0; nil_ctx < 2; ++nil_ctx) {
        results = test_scan(detector, nil_ctx ? NULL : &ctx, true, input, strlen(input)); CHECK(results.len == (detector->version == 2 ? 2u : 0u) && !http.calls && !http.releases);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], key, NULL, false, NULL);
        br_results_clear(&results);
    }
}

static void complete_emails(const br_detector *detector, const char *key)
{
    const char quoted[] = "\"quoted\x01value\"@Example.test";
    const expected_pair pair[] = {{key, quoted}}; expected_requests expected = {.pairs = pair, .count = 0};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
    expect_one(detector, &ctx, false, key, quoted, false, NULL); CHECK(!http.calls && !http.releases);
    expect_one(detector, NULL, true, key, quoted, false, "net/http: nil Context"); /* Constructor precedes header validation. */
    expect_one(detector, &ctx, true, key, quoted, false, "invalid HTTP header"); CHECK(!http.calls && http.releases == 1);
    /* Preserve the captured C0; do NOT sanitize it merely to invoke transport.
     * Generic native header rejection wording is a documented Go diagnostic gap. */
    const char tabbed[] = "\"tab\\\tvalue\"@Example.test";
    const expected_pair tab_pair[] = {{key, tabbed}}; expected = (expected_requests){.pairs = tab_pair, .count = 1}; http.calls = http.releases = 0;
    expect_one(detector, &ctx, true, key, tabbed, true, NULL); CHECK(http.calls == 1 && http.releases == 1);
    const size_t local_len = 4096; const char suffix[] = "@Example.test";
    char *long_email = malloc(local_len + sizeof(suffix)); CHECK(long_email); memset(long_email, 'A', local_len); memcpy(long_email + local_len, suffix, sizeof(suffix));
    const expected_pair long_pair[] = {{key, long_email}}; expected = (expected_requests){.pairs = long_pair, .count = 1}; http.calls = http.releases = 0;
    expect_one(detector, &ctx, false, key, long_email, false, NULL); CHECK(!http.calls && !http.releases);
    expect_one(detector, &ctx, true, key, long_email, true, NULL); CHECK(http.calls == 1 && http.releases == 1); free(long_email);
}

static void status_and_redaction(const br_detector *detector, const char *key, const char *other)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL}, {201, false, "unexpected status code: 201"},
        {204, false, "unexpected status code: 204"}, {299, false, "unexpected status code: 299"}, {503, false, status_503},
    };
    const expected_pair pair[] = {{key, email1}}; expected_requests expected = {.pairs = pair, .count = 1};
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body)}, .body_error = "ignored body/read/drain/close error"}, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "cf-global-test"};
        expect_one(detector, &ctx, true, key, email1, statuses[i].verified, statuses[i].error); CHECK(http.calls == 1 && http.releases == 1);
    }
    char cause[384], redacted[256];
    snprintf(cause, sizeof(cause), "key=%s repeat=%s email=%s keep=%s partial=%s", key, key, email1, other, key + 20);
    snprintf(redacted, sizeof(redacted), "key=[REDACTED] repeat=[REDACTED] email=%s keep=%s partial=%s", email1, other, key + 20);
    const struct { const char *cause, *error; } failures[] = {
        {cause, redacted}, {"lookup synthetic.invalid: no such host", "lookup synthetic.invalid: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        expected.mutate_error = i == 0; expected.mutated = false;
        test_http http = {.response = {.status = 200, .body_error = "must not replace Do error"}, .send_rc = i % 2 ? -1 : 1, .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, key, email1, false, failures[i].error); CHECK(http.calls == 1 && http.releases == 1);
        if (i == 0) CHECK(expected.mutated);
    }
    expect_one(detector, NULL, false, key, email1, false, NULL);
    expect_one(detector, NULL, true, key, email1, false, "net/http: nil Context");
}

static bool cancelled(void *user) { (void)user; return true; }
static void context_errors(const br_detector *detector, const char *key)
{
    const expected_pair pair[] = {{key, email1}}; expected_requests expected = {.pairs = pair, .count = 0};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http);
        br_scan_ctx ctx = {.transport = mode == 2 ? NULL : &transport, .cancelled = mode == 0 ? cancelled : NULL, .deadline_monotonic_ms = mode == 1 ? 1 : 0};
        expect_one(detector, &ctx, true, key, email1, false, mode == 0 ? "context canceled" : mode == 1 ? "context deadline exceeded" : "HTTP transport not installed");
        CHECK(!http.calls && http.releases == (mode == 2 ? 0u : 1u));
    }
}

static br_results sentinel_results(unsigned char **raw, char **error)
{
    br_result sentinel = {.detector_type = 12345, .verified = true};
    sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
    sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error); *raw = sentinel.raw.data; *error = sentinel.verification_error;
    br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0); return results;
}

static void check_sentinel(const br_results *results, unsigned char *raw, char *error)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 4 && !memcmp(raw, "keep", 4));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned"));
}

static void resource_rollback(const br_detector *detector, const char *key)
{
    char input[256]; snprintf(input, sizeof(input), "%s%s %s %s", detector->version == 1 ? "cloudflare " : "", key, email1, email2);
    const expected_pair pairs[] = {{key, email1}, {key, email2}}; const int statuses[] = {200, 503};
    expected_requests expected = {.pairs = pairs, .count = 2, .statuses = statuses};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport};
        unsigned char *raw; char *caller_error; br_results results = sentinel_results(&raw, &caller_error); char *error = NULL;
        if (mode == 0) fail_status_copy = true;
        if (mode == 1) fail_email_after = 2;
        if (mode == 2) fail_part_after = 3;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, mode == 0 ? "cannot store CloudflareGlobalApiKey verification error" : mode == 1 ? "cannot copy CloudflareGlobalApiKey Redacted email" : "cannot create CloudflareGlobalApiKey paired result"));
        CHECK(!fail_status_copy && !fail_email_after && !fail_part_after && http.calls == (mode == 0 ? 2u : 1u) && http.releases == http.calls);
        check_sentinel(&results, raw, caller_error); free(error); br_results_clear(&results);
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        check_result(&results.items[0], key, email1, true, NULL); check_result(&results.items[1], key, email2, false, status_503); br_results_clear(&results);
    }
}

static void unpaired_resource_rollback(const br_detector *v2)
{
    char input[128]; snprintf(input, sizeof(input), "%s %s", new_key, new_key);
    unsigned char *raw; char *caller_error; br_results results = sentinel_results(&raw, &caller_error); char *error = NULL;
    fail_part_after = 2;
    int rc = v2->scan(v2, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create CloudflareGlobalApiKey unpaired result") && !fail_part_after);
    check_sentinel(&results, raw, caller_error); free(error); br_results_clear(&results);
}

int main(void)
{
    for (size_t i = 0; i < 40; ++i) old_key[i] = "0123456789abcdef"[i % 16];
    old_key[40] = '\0';
    memcpy(old_other, old_key, sizeof(old_other)); old_other[0] = 'b';
    char body[41]; test_secret(body, 40, 9); body[0] = 'Q';
    snprintf(new_key, sizeof(new_key), "cfk_%s0abc12de", body); memcpy(new_other, new_key, sizeof(new_other)); new_other[4] = 'Z';
    CHECK(strlen(new_key) == 52);
    const br_detector *v1 = descriptor(1), *v2 = descriptor(2); CHECK(v1 != v2 && v1->state != v2->state && v1->scan == v2->scan);
    extraction(v1, v2); products_and_no_email(v1, old_key, old_other); products_and_no_email(v2, new_key, new_other);
    complete_emails(v1, old_key); complete_emails(v2, new_key);
    status_and_redaction(v1, old_key, old_other); status_and_redaction(v2, new_key, new_other);
    context_errors(v1, old_key); context_errors(v2, new_key);
    resource_rollback(v1, old_key); resource_rollback(v2, new_key); unpaired_resource_rollback(v2);
    return test_finish("CloudflareGlobalApiKey shared products + complete emails + no-email v2 bypass + key-only causes");
}
