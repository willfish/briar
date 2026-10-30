/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_plaidkey_init(const br_detector **out, char **error);

static bool fail_next_malloc;
static size_t setter_calls, fail_setter, fail_part, fail_extra, arm_body;
static size_t compile_calls, compile_fail_call, capture_calls, capture_fail_call, fail_push;
static const char *expect_id, *expect_secret;

void *malloc(size_t size)
{
    if (fail_next_malloc) { fail_next_malloc = false; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *text)
{
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (name && !strcmp(name, "id") && fail_part && !--fail_part) return 1;
    if (name && !strcmp(name, "environment") && fail_extra && !--fail_extra) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && name && !strcmp(name, "token") && arm_body && !--arm_body) fail_next_malloc = true;
    return rc;
}
#define br_result_set_verification_error plaid_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    CHECK(count == 2 && secrets && secrets[0].len == 24 && secrets[1].len == 30);
    if (expect_id) {
        CHECK(!memcmp(secrets[0].data, expect_id, 24));
        CHECK(!memcmp(secrets[1].data, expect_secret, 30));
    }
    int rc = plaid_real_setter(result, cause, secrets, count);
    return fail_setter && !--fail_setter ? 1 : rc;
}
static int plaid_compile(const char *const *keywords, size_t count, const char *suffix, br_regex **out, char **error)
{
    ++compile_calls;
    if (compile_fail_call && compile_calls == compile_fail_call) {
        *out = NULL; if (error) *error = strdup("owned compile +1"); return 1;
    }
    return br_regex_compile_prefixed(keywords, count, suffix, out, error);
}
static int plaid_capture(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    ++capture_calls;
    CHECK(unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (capture_fail_call && capture_calls == capture_fail_call) {
        if (error && !*error) *error = strdup("owned capture +1");
        return 1;
    }
    return rc;
}
static int plaid_push(br_results *out, br_result *result)
{
    return fail_push && !--fail_push ? 1 : br_results_push(out, result);
}
#define br_regex_compile_prefixed plaid_compile
#define br_captures_find plaid_capture
#define br_results_push plaid_push
#include "../../src/detectors/plaidkey.c"
#undef br_results_push
#undef br_captures_find
#undef br_regex_compile_prefixed

static const char secret_a[] = "fedcba9876543210fedcba98765432";
static const char secret_b[] = "0123456789abcdef0123456789abcd";
static const char id_a[] = "123456789abcdef012345678";
static const char id_b[] = "fedcba9876543210abcdef01";
static const char exact_id[] = "012345670123456701234567";
static const char token_s[] = "access-sandbox-deadbeef-cafe-babe-face-0123456789ab";
static const char token_p[] = "access-production-deadbeef-cafe-babe-face-0123456789ab";
static const char token_low[] = "access-sandbox-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
static const br_detector *detector;

typedef struct {
    test_http http; br_transport transport; br_scan_ctx ctx; br_results *out;
    const char *urls[4], *bodies[4], *cause;
    const char *live_url[4], *live_type[4];
    const unsigned char *live_body[4];
    size_t live_len[4], release_setters[4], release_lens[4], count;
    int statuses[4], send_rc;
} script;

static void reset_faults(void)
{
    fail_next_malloc = false;
    fail_setter = fail_part = fail_extra = arm_body = fail_push = 0;
    capture_calls = capture_fail_call = 0;
    setter_calls = 0; expect_id = expect_secret = NULL;
}
static br_slice bytes(const char *text)
{
    return (br_slice){(const unsigned char *)text, strlen(text)};
}
static void expect_keep(const char *text, bool keep)
{
    CHECK((br_ascii_shannon_entropy(bytes(text)) >= 3) == keep);
}
static const char *part(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(result->secret_parts && json_object_object_get_ex(result->secret_parts, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return json_object_get_string(value);
}
static void fields(const br_result *result, const char *secret, const char *id, const char *token, bool verified)
{
    char joined[192];
    int n = snprintf(joined, sizeof(joined), "%s:%s:%s", secret, id, token);
    CHECK(n > 0 && (size_t)n < sizeof(joined));
    CHECK(result->detector_type == 79 && result->verified == verified);
    CHECK(result->raw.len == 30 && !memcmp(result->raw.data, secret, 30));
    CHECK(result->raw_v2.len == (size_t)n && !memcmp(result->raw_v2.data, joined, (size_t)n));
    CHECK(json_object_object_length(result->secret_parts) == 3);
    CHECK(!strcmp(part(result, "secret"), secret) && !strcmp(part(result, "id"), id) && !strcmp(part(result, "token"), token));
    CHECK(!result->redacted && !result->structured_data && !result->detector_name);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_line && !result->chunk_offset_set);
}
static void extra_url(const br_result *result, const char *environment)
{
    char url[48];
    snprintf(url, sizeof(url), "https://%s.plaid.com", environment);
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "environment", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), url));
    CHECK(!strstr(json_object_get_string(value), "/item"));
}
static int suffix_matches(const char *pattern, const char *text)
{
    br_regex *regex = NULL; char *error = NULL; br_captures found = {0};
    CHECK(br_regex_compile(pattern, &regex, &error) == 0 && !error);
    CHECK(br_captures_find(regex, bytes(text), &found, false, &error) == 0 && !error);
    int count = (int)found.len;
    br_captures_clear(&found); br_regex_free(regex);
    return count;
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(ctx == &s->ctx && at < s->count && at < 4);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, s->urls[at]));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 79);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->body.len == strlen(s->bodies[at]) && !memcmp(request->body.data, s->bodies[at], request->body.len));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog plaidkey-offline"));
    s->live_url[at] = request->url; s->live_type[at] = request->headers[0].value;
    s->live_body[at] = request->body.data; s->live_len[at] = request->body.len;
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    http->response = (br_http_response){.status = s->statuses[at], .body = {binary, sizeof(binary)},
        .body_error = "ignored body read failure"};
    http->send_rc = s->send_rc; http->send_error = s->cause;
}
static void release(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(http->releases < 4 && s->out);
    if (http->calls) {
        size_t at = http->calls - 1;
        CHECK(s->live_url[at] && !strcmp(s->live_url[at], s->urls[at]));
        CHECK(s->live_type[at] && !strcmp(s->live_type[at], "application/json"));
        CHECK(s->live_body[at] && s->live_len[at] == strlen(s->bodies[at]));
        CHECK(!memcmp(s->live_body[at], s->bodies[at], s->live_len[at]));
    } else CHECK(!response->status && !response->body.data && !response->body_error);
    s->release_setters[http->releases] = setter_calls;
    s->release_lens[http->releases] = s->out->len;
    test_http_release(user, response);
}
static void setup(script *s, size_t count)
{
    memset(s, 0, sizeof(*s)); s->count = count;
    for (size_t i = 0; i < count; ++i) s->statuses[i] = 200;
    s->http = (test_http){.inspect = inspect, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, release};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "plaidkey-offline"};
}
static void body_of(char *out, size_t cap, const char *id, const char *secret, const char *token)
{
    int n = snprintf(out, cap, "{\"client_id\":\"%s\",\"secret\":\"%s\",\"access_token\":\"%s\"}", id, secret, token);
    CHECK(n > 0 && (size_t)n < cap);
}
static void url_of(char *out, size_t cap, const char *environment)
{
    int n = snprintf(out, cap, "https://%s.plaid.com/item/get", environment);
    CHECK(n > 0 && (size_t)n < cap);
}
static br_results with_prior(br_bytes *saved)
{
    br_results out = {0}; br_result prior = {0};
    CHECK(br_finding_key(&prior, 19, "caller-owned", "key") == 0);
    CHECK(br_results_push(&out, &prior) == 0);
    *saved = out.items[0].raw;
    return out;
}
static void prior_kept(const br_results *out, br_bytes saved)
{
    CHECK(out->len >= 1 && out->items[0].raw.data == saved.data && out->items[0].raw.len == 12);
    CHECK(!memcmp(out->items[0].raw.data, "caller-owned", 12));
}
static void preserved(const br_results *out, br_bytes saved)
{
    CHECK(out->len == 1);
    prior_kept(out, saved);
}
static int scan_buf(const br_scan_ctx *ctx, bool verify, const char *text, br_results *out, char **error)
{
    return detector->scan(detector, ctx, verify, bytes(text), out, error);
}

int main(void)
{
    char *error = NULL;
    CHECK(br_plaidkey_init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    compile_calls = 0; compile_fail_call = 1;
    const br_detector *out = detector;
    CHECK(br_plaidkey_init(&out, &error) != 0 && !out && error);
    free(error); error = NULL;
    compile_calls = 0; compile_fail_call = 2;
    CHECK(br_plaidkey_init(&out, &error) != 0 && !out && error);
    free(error); error = NULL;
    compile_fail_call = 0; compile_calls = 0; fail_next_malloc = true;
    CHECK(br_plaidkey_init(&out, &error) != 0 && !out && error);
    free(error); error = NULL; fail_next_malloc = false; compile_calls = 0;
    CHECK(br_plaidkey_init(&detector, &error) == 0 && detector && !error);
    CHECK(compile_calls == 3);
    size_t compiled = compile_calls;
    CHECK(br_plaidkey_init(&detector, &error) == 0 && compile_calls == compiled);
    CHECK(detector->type == 79 && detector->version == 0 && !strcmp(detector->name, "PlaidKey"));
    CHECK(!strcmp(detector->custom_name, "") && detector->nkeywords == 1 && !strcmp(detector->keywords[0], "plaid"));
    CHECK(!strcmp(detector->description, "Plaid is a financial services company that provides a way to connect applications to users' bank accounts. Plaid API keys can be used to access and manage financial data."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);

    CHECK(br_ascii_shannon_entropy(bytes(exact_id)) == 3);
    expect_keep(exact_id, true); expect_keep(secret_a, true); expect_keep(secret_b, true);
    expect_keep(id_a, true); expect_keep(id_b, true); expect_keep(token_s, true); expect_keep(token_p, true);
    char zeros30[31], zeros24[25];
    memset(zeros30, '0', 30); zeros30[30] = 0; memset(zeros24, '0', 24); zeros24[24] = 0;
    expect_keep(zeros30, false); expect_keep(zeros24, false); expect_keep(token_low, false);
    CHECK(suffix_matches("\\b([a-f0-9]{30})\\b", zeros30) == 1);
    CHECK(suffix_matches("\\b([a-f0-9]{24})\\b", zeros24) == 1);
    CHECK(suffix_matches("\\b([a-f0-9]{24})\\b", exact_id) == 1);
    CHECK(suffix_matches("\\b(access-(sandbox|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\\b", token_low) == 1);
    CHECK(strlen(secret_a) == 30 && strlen(secret_b) == 30 && strlen(id_a) == 24 && strlen(id_b) == 24);
    CHECK(strlen(token_s) == 51 && strlen(token_p) == 54 && strlen(token_low) == 51);

    char chunk[8192];
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s", secret_a, id_a, token_s);
    br_results results = {0};
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !error && results.len == 1 && !setter_calls);
    fields(&results.items[0], secret_a, id_a, token_s, false);
    CHECK(!results.items[0].extra_data && !results.items[0].verification_error);
    br_results_clear(&results);

    snprintf(chunk, sizeof(chunk), "PLAID %s\nPlaid %s xxplaid %s", secret_b, id_b, token_p);
    results = (br_results){0};
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && results.len == 1);
    fields(&results.items[0], secret_b, id_b, token_p, false);
    CHECK(!results.items[0].extra_data);
    br_results_clear(&results);

    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s plaid %s plaid %s plaid %s",
             secret_a, secret_b, id_a, id_b, token_p, token_s);
    const char *secrets[] = {secret_a, secret_b}, *ids[] = {id_a, id_b}, *tokens[] = {token_p, token_s};
    results = (br_results){0};
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && results.len == 8 && !setter_calls);
    for (size_t s = 0, n = 0; s < 2; ++s) for (size_t i = 0; i < 2; ++i) for (size_t t = 0; t < 2; ++t, ++n) {
        fields(&results.items[n], secrets[s], ids[i], tokens[t], false);
        CHECK(!results.items[n].extra_data);
    }
    br_results_clear(&results);

    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s plaid %s plaid %s", secret_a, secret_a, id_a, id_a, token_s);
    results = (br_results){0};
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && results.len == 1);
    br_results_clear(&results);
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s", secret_a, id_a);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s", secret_a, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s", id_a, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);

    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s", secret_a, exact_id, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && results.len == 1);
    fields(&results.items[0], secret_a, exact_id, token_s, false);
    br_results_clear(&results);
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s plaid %s", zeros30, secret_a, zeros24, id_a);
    snprintf(chunk + strlen(chunk), sizeof(chunk) - strlen(chunk), " plaid %s plaid %s", token_low, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && results.len == 1);
    fields(&results.items[0], secret_a, id_a, token_s, false);
    br_results_clear(&results);
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s", secret_a, id_a, token_low);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);

    char gap40[41], gap41[42];
    memset(gap40, ' ', 40); gap40[40] = 0; memset(gap41, ' ', 41); gap41[41] = 0;
    snprintf(chunk, sizeof(chunk), "plaid%s%s plaid %s plaid %s", gap40, secret_a, id_a, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && results.len == 1);
    br_results_clear(&results);
    snprintf(chunk, sizeof(chunk), "plaid%s%s plaid %s plaid %s", gap41, secret_a, id_a, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);

    snprintf(chunk, sizeof(chunk), "plaid %sa plaid %s plaid %s", secret_a, id_a, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);
    snprintf(chunk, sizeof(chunk), "plaid %s- plaid %sg plaid %s plaid access-development-deadbeef-cafe-babe-face-0123456789ab plaid %s",
             secret_a, id_a, id_b, token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && results.len == 1);
    fields(&results.items[0], secret_a, id_b, token_s, false);
    br_results_clear(&results);
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid ACCESS-SANDBOX-deadbeef-cafe-babe-face-0123456789ab", secret_a, id_a);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);
    snprintf(chunk, sizeof(chunk), "plaid 0123456789ABCDEF0123456789ABCD plaid FEDCBA9876543210ABCDEF01 plaid %s", token_s);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) == 0 && !results.len);

    memset(chunk, 'x', 1200); chunk[1200] = 0;
    char wide[8192];
    snprintf(wide, sizeof(wide), "plaid %s\n%s\nplaid %s\n%s\nplaid %s", secret_a, chunk, id_a, chunk, token_s);
    CHECK(strlen(wide) > 1024);
    CHECK(scan_buf(NULL, false, wide, &results, &error) == 0 && results.len == 1);
    fields(&results.items[0], secret_a, id_a, token_s, false);
    br_results_clear(&results);

    br_detector bare = {0}; br_slice bad = {NULL, 1}; br_results empty = {0};
    CHECK(detector->scan(NULL, NULL, false, bytes("plaid"), &empty, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(detector->scan(&bare, NULL, false, bytes("plaid"), &empty, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, false, bad, NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, false, bytes(""), &empty, &error) == 0 && !empty.len && !error);

    br_bytes saved = {0};
    for (size_t call = 1; call <= 3; ++call) {
        reset_faults(); capture_fail_call = call;
        results = with_prior(&saved);
        CHECK(scan_buf(NULL, true, wide, &results, &error) != 0 && error);
        preserved(&results, saved); CHECK(!setter_calls && capture_calls == call);
        free(error); error = NULL; br_results_clear(&results);
    }
    reset_faults(); fail_part = 1;
    results = with_prior(&saved);
    CHECK(scan_buf(NULL, false, wide, &results, &error) != 0 && error);
    preserved(&results, saved); CHECK(!setter_calls);
    free(error); error = NULL; br_results_clear(&results);

    char body_s[192], body_p[192], url_s[64], url_p[64];
    body_of(body_s, sizeof(body_s), id_a, secret_a, token_s);
    body_of(body_p, sizeof(body_p), id_a, secret_a, token_p);
    url_of(url_s, sizeof(url_s), "sandbox"); url_of(url_p, sizeof(url_p), "production");
    snprintf(chunk, sizeof(chunk), "production plaid %s plaid %s sandbox plaid %s plaid %s", secret_a, id_a, token_s, token_p);
    script http; setup(&http, 2);
    http.urls[0] = url_s; http.urls[1] = url_p; http.bodies[0] = body_s; http.bodies[1] = body_p;
    expect_id = id_a; expect_secret = secret_a;
    results = with_prior(&saved); http.out = &results;
    CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) == 0 && !error && results.len == 3);
    CHECK(http.http.calls == 2 && http.http.releases == 2 && setter_calls == 2);
    CHECK(http.release_setters[0] == 0 && http.release_lens[0] == 1);
    CHECK(http.release_setters[1] == 1 && http.release_lens[1] == 2);
    fields(&results.items[1], secret_a, id_a, token_s, true); extra_url(&results.items[1], "sandbox");
    fields(&results.items[2], secret_a, id_a, token_p, true); extra_url(&results.items[2], "production");
    CHECK(!results.items[1].verification_error && !results.items[2].verification_error);
    prior_kept(&results, saved); br_results_clear(&results);

    struct { int status; bool verified; const char *cause; } table[] = {
        {200, true, NULL}, {400, false, NULL}, {201, false, "unexpected HTTP response status 201"},
        {401, false, "unexpected HTTP response status 401"}, {500, false, "unexpected HTTP response status 500"},
        {0, false, "unexpected HTTP response status 0"}, {-1, false, "unexpected HTTP response status -1"},
    };
    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s", secret_a, id_a, token_s);
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); ++i) {
        reset_faults(); setup(&http, 1); http.urls[0] = url_s; http.bodies[0] = body_s; http.statuses[0] = table[i].status;
        expect_id = id_a; expect_secret = secret_a;
        results = (br_results){0}; http.out = &results;
        CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) == 0 && results.len == 1);
        CHECK(http.http.calls == 1 && http.http.releases == 1 && setter_calls == 1);
        CHECK(http.release_setters[0] == 0 && http.release_lens[0] == 0);
        fields(&results.items[0], secret_a, id_a, token_s, table[i].verified);
        extra_url(&results.items[0], "sandbox");
        if (table[i].cause) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, table[i].cause));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    reset_faults(); setup(&http, 1); http.urls[0] = url_s; http.bodies[0] = body_s; expect_id = id_a; expect_secret = secret_a;
    results = (br_results){0}; http.out = &results;
    CHECK(scan_buf(NULL, true, chunk, &results, &error) == 0 && results.len == 1);
    CHECK(!http.http.calls && !http.http.releases && setter_calls == 1 && !results.items[0].verified);
    extra_url(&results.items[0], "sandbox");
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    char redacted[320];
    snprintf(redacted, sizeof(redacted), "rejected %s %s %s", id_a, secret_a, token_s);
    reset_faults(); setup(&http, 1); http.urls[0] = url_s; http.bodies[0] = body_s;
    http.send_rc = 1; http.cause = redacted; expect_id = id_a; expect_secret = secret_a;
    results = with_prior(&saved); http.out = &results;
    CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) == 0 && results.len == 2 && setter_calls == 1);
    CHECK(http.http.calls == 1 && http.http.releases == 1 && http.release_setters[0] == 0 && http.release_lens[0] == 1);
    CHECK(!results.items[1].verified); extra_url(&results.items[1], "sandbox");
    CHECK(results.items[1].verification_error && strstr(results.items[1].verification_error, token_s));
    CHECK(!strstr(results.items[1].verification_error, id_a) && !strstr(results.items[1].verification_error, secret_a));
    CHECK(strstr(results.items[1].verification_error, "[REDACTED]"));
    prior_kept(&results, saved); br_results_clear(&results);

    reset_faults(); setup(&http, 1); http.ctx.user_agent = "bad\nagent"; expect_id = id_a; expect_secret = secret_a;
    results = (br_results){0}; http.out = &results;
    CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) == 0 && results.len == 1 && setter_calls == 1);
    CHECK(!http.http.calls && http.http.releases == 1 && !results.items[0].verified);
    extra_url(&results.items[0], "sandbox");
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "invalid HTTP user agent"));
    br_results_clear(&results);

    snprintf(chunk, sizeof(chunk), "plaid %s plaid %s plaid %s plaid %s", secret_a, id_a, token_s, token_p);
    reset_faults(); arm_body = 2; setup(&http, 2);
    http.urls[0] = url_s; http.urls[1] = url_p; http.bodies[0] = body_s; http.bodies[1] = body_p;
    results = with_prior(&saved); http.out = &results;
    CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) != 0 && error);
    preserved(&results, saved); CHECK(http.http.calls == 1 && http.http.releases == 1 && setter_calls == 1);
    free(error); error = NULL; br_results_clear(&results);

    reset_faults(); fail_extra = 2; setup(&http, 2);
    http.urls[0] = url_s; http.urls[1] = url_p; http.bodies[0] = body_s; http.bodies[1] = body_p;
    results = with_prior(&saved); http.out = &results;
    CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) != 0 && error);
    preserved(&results, saved); CHECK(http.http.calls == 2 && http.http.releases == 2 && setter_calls == 1);
    free(error); error = NULL; br_results_clear(&results);

    reset_faults(); fail_setter = 2; setup(&http, 2);
    http.urls[0] = url_s; http.urls[1] = url_p; http.bodies[0] = body_s; http.bodies[1] = body_p;
    results = with_prior(&saved); http.out = &results;
    CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) != 0 && error);
    preserved(&results, saved); CHECK(http.http.calls == 2 && http.http.releases == 2 && setter_calls == 2);
    free(error); error = NULL; br_results_clear(&results);

    reset_faults(); fail_push = 2; setup(&http, 2);
    http.urls[0] = url_s; http.urls[1] = url_p; http.bodies[0] = body_s; http.bodies[1] = body_p;
    results = with_prior(&saved); http.out = &results;
    CHECK(scan_buf(&http.ctx, true, chunk, &results, &error) != 0 && error);
    preserved(&results, saved); CHECK(http.http.calls == 2 && http.http.releases == 2 && setter_calls == 2);
    free(error); error = NULL; br_results_clear(&results);

    reset_faults(); fail_push = 1;
    results = with_prior(&saved);
    CHECK(scan_buf(NULL, false, chunk, &results, &error) != 0 && error);
    preserved(&results, saved); CHECK(!setter_calls);
    free(error);
    return test_finish("plaidkey");
}
