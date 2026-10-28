/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "ya29.abC012_-xy", second[] = "ya29.Other012_-";
static const char prefix[] = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=";
static size_t fail_size, fail_after, failed, fail_add;
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed; return NULL; }
    return calloc(1, size);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add && --fail_add == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
typedef struct { const char *key, *url; const br_scan_ctx *ctx; } script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    script *s = http->user;
    CHECK(ctx == s->ctx && http->calls == http->releases + 1);
    CHECK(!strcmp(r->method, "GET") && !strncmp(r->url, prefix, sizeof(prefix) - 1));
    CHECK(!strcmp(r->url + sizeof(prefix) - 1, s->key));
    CHECK(r->profile == BR_HTTP_SANE && r->timeout_ms == 5000 && r->detector_type == 69);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == 1 && !strcmp(r->headers[0].name, "User-Agent") && !strcmp(r->headers[0].value, "TruffleHog oauth-offline"));
    s->url = r->url; /* Borrow only the provider URL, never prepared headers or UA. */
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    CHECK(s->url && !strcmp(s->url + sizeof(prefix) - 1, s->key));
    s->url = NULL; test_http_release(user, response);
}
static br_results run(const br_detector *d, const br_scan_ctx *ctx, bool verify, const char *input)
{
    return test_scan(d, ctx, verify, input, strlen(input));
}
static void raw_check(const br_result *r, const char *expected)
{
    CHECK(r->detector_type == 69 && r->raw.len == strlen(expected) && !memcmp(r->raw.data, expected, r->raw.len));
    CHECK(!r->detector_name && !r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data);
    CHECK(!r->primary_secret.data && !r->primary_line && !r->chunk_offset_set && !r->chunk_offset && !r->verification_from_cache);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *v = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &v));
    CHECK(json_object_is_type(v, json_type_string) && (size_t)json_object_get_string_len(v) == strlen(expected) && !memcmp(json_object_get_string(v), expected, strlen(expected)));
}
static void extraction(const br_detector *d)
{
    const char *bad[] = {"YA29.abcdefghij", "ya29.abcdefghi", "xya29.abcdefghij", "_ya29.abcdefghij"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(*bad); ++i) { br_results r = run(d, NULL, false, bad[i]); CHECK(!r.len); br_results_clear(&r); }
    const char *good[] = {key, "ya29.abcdefghij_ABC-xyz", "ya29.abcdefghi\xc5\xbf", "ya29.abcdefghi\xe2\x84\xaa"};
    for (size_t i = 0; i < sizeof(good)/sizeof(*good); ++i) {
        br_results r = run(d, NULL, false, good[i]); CHECK(r.len == 1); raw_check(&r.items[0], good[i]); CHECK(!r.items[0].extra_data && !r.items[0].verification_error); br_results_clear(&r);
    }
    char input[256]; snprintf(input, sizeof(input), "%s %s\n%s!ya29.abc012_-xy", key, key, second);
    br_results r = run(d, NULL, false, input); CHECK(r.len == 3); raw_check(&r.items[0], key); raw_check(&r.items[1], second); raw_check(&r.items[2], "ya29.abc012_-xy"); br_results_clear(&r);
    /* A consumed uppercase delimiter cannot be the next token's boundary. */
    r = run(d, NULL, false, "ya29.abcdefghijZya29.0123456789"); CHECK(r.len == 1); raw_check(&r.items[0], "ya29.abcdefghijZya29"); br_results_clear(&r);
    /* Greedy matching backtracks to uppercase Z before an invalid-byte barrier. */
    const unsigned char backtrack[] = "ya29.abcdefghijZ-\xff";
    r = test_scan(d, NULL, false, backtrack, sizeof(backtrack) - 1); CHECK(r.len == 1); raw_check(&r.items[0], "ya29.abcdefghij"); br_results_clear(&r);
    size_t n = 100005; char *longkey = malloc(n + 1); CHECK(longkey); memcpy(longkey, "ya29.", 5); memset(longkey + 5, 'A', n - 5); longkey[n] = 0;
    r = run(d, NULL, false, longkey); CHECK(r.len == 1); raw_check(&r.items[0], longkey); br_results_clear(&r); free(longkey);
    r = run(d, NULL, true, key); CHECK(r.len == 1 && !r.items[0].verified && !strcmp(r.items[0].verification_error, "net/http: nil Context")); raw_check(&r.items[0], key); br_results_clear(&r);
}
static void field(const br_result *r, const char *name, const void *expected, size_t len)
{
    br_json *v = NULL; CHECK(r->extra_data && json_object_object_get_ex(r->extra_data, name, &v));
    CHECK(json_object_is_type(v, json_type_string) && (size_t)json_object_get_string_len(v) == len && !memcmp(json_object_get_string(v), expected, len));
}
static void body(test_http *http, int status, const char *text, const char *read_error)
{
    http->response = (br_http_response){.status = status, .body = {(const unsigned char *)text, strlen(text)}, .body_error = read_error};
    http->send_rc = 0; http->send_error = NULL;
}
static void ordinary(const br_detector *d, br_scan_ctx *ctx, test_http *http)
{
    const char *empty[] = {"{}", "null", "{} trailing"};
    for (size_t i = 0; i < sizeof(empty)/sizeof(*empty); ++i) {
        body(http, 200, empty[i], i == 1 ? NULL : "later read error"); br_results r = run(d, ctx, true, key); CHECK(r.len == 1 && r.items[0].verified && !r.items[0].verification_error && json_object_object_length(r.items[0].extra_data) == 4);
        field(&r.items[0], "google_email", "", 0); field(&r.items[0], "email_verified", "", 0); field(&r.items[0], "scope", "", 0); field(&r.items[0], "access_type", "", 0); raw_check(&r.items[0], key); br_results_clear(&r);
    }
    body(http, 200, "{\"EMAIL\":\"first\",\"email\":\"last\\u0000x\",\"email\":null,\"SCOPE\":\"read\",\"scope\":null,\"email_verified\":\"true\",\"access_type\":\"offline\",\"unknown\":1e999999}", NULL);
    br_results r = run(d, ctx, true, key); CHECK(r.len == 1 && r.items[0].verified); field(&r.items[0], "google_email", "last\0x", 6); field(&r.items[0], "scope", "read", 4); field(&r.items[0], "email_verified", "true", 4); field(&r.items[0], "access_type", "offline", 7); br_results_clear(&r);
    const char repaired[] = "{\"email\":\"\xff\"}"; body(http, 200, repaired, NULL); r = run(d, ctx, true, key); CHECK(r.items[0].verified); field(&r.items[0], "google_email", "\xef\xbf\xbd", 3); br_results_clear(&r);
    const char *typed[] = {"{\"email\":7,\"email\":\"ok\",\"exp\":\"0\"}", "{\"email\":false,\"scope\":4}", "[]", "{\"exp\":8}"};
    for (size_t i = 0; i < sizeof(typed)/sizeof(*typed); ++i) {
        body(http, 200, typed[i], NULL); r = run(d, ctx, true, key); CHECK(r.len == 1 && !r.items[0].verified && !r.items[0].extra_data && r.items[0].verification_error);
        CHECK(!strncmp(r.items[0].verification_error, "json: cannot unmarshal ", 23)); CHECK(!strstr(r.items[0].verification_error, "failed to decode response")); br_results_clear(&r);
    }
    body(http, 200, "{", "read root cause"); r = run(d, ctx, true, key); CHECK(!strcmp(r.items[0].verification_error, "read root cause")); br_results_clear(&r);
    body(http, 400, "{\"error_description\":\"Invalid Value\",\"error_description\":null}", "ignored after object"); r = run(d, ctx, true, key); CHECK(!r.items[0].verified && !r.items[0].extra_data && !r.items[0].verification_error); br_results_clear(&r);
    const char *errors[] = {"{\"error_description\":\"Invalid value\"}", "{}", "null", "{\"error_description\":\"it's wrong\"}"};
    for (size_t i = 0; i < sizeof(errors)/sizeof(*errors); ++i) {
        body(http, 400, errors[i], NULL); r = run(d, ctx, true, key); CHECK(!r.items[0].verified && !r.items[0].extra_data && r.items[0].verification_error && strstr(r.items[0].verification_error, prefix) && strstr(r.items[0].verification_error, key)); CHECK(!strncmp(r.items[0].verification_error, "unexpected error description '", 30)); br_results_clear(&r);
    }
    body(http, 400, "{\"error_description\":3,\"error_description\":\"x\\u0000\"}", NULL); r = run(d, ctx, true, key); CHECK(!strcmp(r.items[0].verification_error, "json: cannot unmarshal number into Go struct field errorInfo.error_description of type string")); br_results_clear(&r);
    const int statuses[] = {0, 201, 204, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses)/sizeof(*statuses); ++i) {
        body(http, statuses[i], "not JSON", "ignored"); r = run(d, ctx, true, key); char expected[256]; snprintf(expected, sizeof(expected), "unexpected response %d for %s%s", statuses[i], prefix, key); CHECK(!r.items[0].verified && !r.items[0].extra_data && !strcmp(r.items[0].verification_error, expected)); br_results_clear(&r);
    }
    const char *causes[] = {"failed to decode response: arbitrary injected cause", "out of memory constructing HTTP headers", "context canceled", key};
    for (size_t i = 0; i < sizeof(causes)/sizeof(*causes); ++i) {
        http->send_rc = -7; http->send_error = causes[i]; r = run(d, ctx, true, key); CHECK(!r.items[0].verified && !r.items[0].extra_data && !strcmp(r.items[0].verification_error, causes[i])); br_results_clear(&r);
    }
    body(http, 200, "{}", NULL);
}
static void time_cases(const br_detector *d, br_scan_ctx *ctx, test_http *http)
{
    CHECK(setenv("TZ", "UTC", 1) == 0);
    const char *exp[] = {"0", "+1", "-1", "-62135596800", "253402300799"};
    const char *expected[] = {"1970-01-01 00:00:00 +0000 UTC", "1970-01-01 00:00:01 +0000 UTC", "1969-12-31 23:59:59 +0000 UTC", "0001-01-01 00:00:00 +0000 UTC", "9999-12-31 23:59:59 +0000 UTC"};
    char text[256];
    for (size_t i = 0; i < sizeof(exp)/sizeof(*exp); ++i) {
        snprintf(text, sizeof(text), "{\"exp\":\"%s\"}", exp[i]); body(http, 200, text, NULL); br_results r = run(d, ctx, true, key); CHECK(r.items[0].verified); field(&r.items[0], "expires_at", expected[i], 29); br_results_clear(&r);
    }
    CHECK(setenv("TZ", "", 1) == 0); body(http, 200, "{\"exp\":\"0\"}", NULL); br_results r = run(d, ctx, true, key); field(&r.items[0], "expires_at", expected[0], 29); br_results_clear(&r);
    CHECK(unsetenv("TZ") == 0);
    const char *bad[] = {"", " 0", "0 ", "0\\u0000", "0x10", "1_0", "+", "9223372036854775808", "-9223372036854775809"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(*bad); ++i) {
        snprintf(text, sizeof(text), "{\"exp\":\"%s\"}", bad[i]); body(http, 200, text, NULL); r = run(d, ctx, true, key); CHECK(r.items[0].verified && json_object_object_length(r.items[0].extra_data) == 4); br_results_clear(&r);
    }
}
static bool cancelled(void *user) { (void)user; return true; }
static void fatal_cases(const br_detector *d, br_scan_ctx *ctx, test_http *http)
{
    const char *bodies[] = {"{\"exp\":\"0\"}", "{\"exp\":\"0\"}", "{\"exp\":\"253402300800\"}", "{\"exp\":\"-62135596801\"}", "{\"exp\":\"9223372036854775807\"}", "{\"error_description\":\"bad\\u0000tail\"}"};
    const char *zones[] = {NULL, "not-a-zone", "UTC", "UTC", "UTC", NULL};
    for (size_t i = 0; i < sizeof(bodies)/sizeof(*bodies); ++i) {
        CHECK(zones[i] ? setenv("TZ", zones[i], 1) == 0 : unsetenv("TZ") == 0);
        body(http, i == 5 ? 400 : 200, bodies[i], NULL);
        br_results r = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "caller", "key") == 0 && br_results_push(&r, &prior) == 0); unsigned char *raw = r.items[0].raw.data;
        char *error = NULL; CHECK(d->scan(d, ctx, true, (br_slice){(const unsigned char *)key, strlen(key)}, &r, &error) != 0 && error && strstr(error, "unsupported:")); CHECK(r.len == 1 && r.items[0].raw.data == raw); free(error); br_results_clear(&r);
    }
    CHECK(setenv("TZ", "UTC", 1) == 0); body(http, 200, "{}", NULL);
    for (int mode = 0; mode < 5; ++mode) {
        br_results r = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "caller", "key") == 0 && br_results_push(&r, &prior) == 0); unsigned char *raw = r.items[0].raw.data;
        char input[100]; snprintf(input, sizeof(input), "%s %s", key, second); char *error = NULL; size_t before = failed;
        if (mode == 0) { fail_size = sizeof(prefix) + strlen(key); fail_after = 1; }
        if (mode == 1) { fail_add = 7; } /* Second finding after first was appended. */
        if (mode == 2) { fail_size = strlen(key); fail_after = 1; }
        if (mode == 3) { body(http, 500, "", NULL); fail_size = strlen("unexpected response 500 for ") + strlen(prefix) + strlen(key) + 1; fail_after = 2; } /* Setter's copy after cause. */
        size_t cap = r.cap; if (mode == 4) r.cap = 0;
        CHECK(d->scan(d, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0 && error);
        if (mode == 4) r.cap = cap;
        CHECK(r.len == 1 && r.items[0].raw.data == raw && !memcmp(raw, "caller", 6));
        CHECK(!fail_after && !fail_add); if (mode == 0 || mode == 2 || mode == 3) CHECK(failed == before + 1);
        free(error); br_results_clear(&r); body(http, 200, "{}", NULL);
    }
}
int main(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && br_googleoauth2_init(&d, &error) == 0 && d && !error);
    CHECK(br_googleoauth2_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 69 && d->version == 0 && !strcmp(d->name, "GoogleOauth2") && !*d->custom_name);
    CHECK(!strcmp(d->description, "Google OAuth 2.0 tokens are used for authenticating and authorizing access to Google APIs and services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ya29.") && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->scan && d->state && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    extraction(d);
    script s = {.key = key}; test_http http = {.inspect = inspect, .user = &s}; br_transport t = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &t, .user_agent = "oauth-offline"}; s.ctx = &ctx;
    ordinary(d, &ctx, &http); time_cases(d, &ctx, &http);
    /* Resource checks use either token while retaining exact request inspection. */
    http.inspect = NULL; t.release = test_http_release;
    fatal_cases(d, &ctx, &http);
    size_t calls = http.calls, releases = http.releases; ctx.cancelled = cancelled;
    br_results r = run(d, &ctx, true, key); CHECK(r.len == 1 && !r.items[0].verified && r.items[0].verification_error && http.calls == calls && http.releases == releases + 1); br_results_clear(&r);
    ctx.cancelled = NULL; body(&http, 200, "{\"exp\":\"0\"}", NULL); CHECK(unsetenv("TZ") == 0); r = run(d, &ctx, false, key); CHECK(!r.items[0].extra_data && !r.items[0].verification_error && http.calls == calls); br_results_clear(&r);
    CHECK(http.releases == http.calls + 1);
    return test_finish("GoogleOauth2");
}
