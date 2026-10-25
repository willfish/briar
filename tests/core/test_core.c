/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static size_t checks;
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)
#define SLICE(text) ((br_slice){ (const unsigned char *)(text), sizeof(text) - 1 })

static br_bytes bytes(const void *data, size_t len)
{
    br_bytes b = { malloc(len ? len : 1), len };
    CHECK(b.data != NULL);
    if (len) memcpy(b.data, data, len);
    return b;
}

static br_result candidate(const char *raw, const char *redacted, bool verified)
{
    br_result r = { .raw = bytes(raw, strlen(raw)), .verified = verified };
    if (redacted) { r.redacted = strdup(redacted); CHECK(r.redacted); }
    return r;
}

static void result_tests(void)
{
    br_result r = {0};
    br_results rs = {0};
    r.detector_name = strdup("synthetic");
    r.raw = bytes("x\0y", 3);
    r.raw_v2 = bytes("", 0);
    r.primary_secret = bytes("primary", 7);
    r.redacted = strdup("");
    r.extra_data = json_object_new_object();
    r.secret_parts = json_object_new_object();
    r.structured_data = json_object_new_object();
    br_json *external = json_object_get(r.secret_parts);
    r.primary_line = 2;
    r.chunk_offset_set = true;
    CHECK(br_results_push(&rs, &r) == 0);
    CHECK(!r.raw.data && !r.raw.len && !r.secret_parts && !r.chunk_offset_set);
    CHECK(rs.len == 1 && rs.items[0].raw.len == 3);
    CHECK(rs.items[0].raw.data[1] == 0);
    CHECK(rs.items[0].raw_v2.data != NULL && !rs.items[0].raw_v2.len);
    CHECK(rs.items[0].chunk_offset_set);
    CHECK(br_results_push(&rs, &rs.items[0]) != 0);
    br_results_clear(&rs);
    CHECK(!rs.items && !rs.len && !rs.cap);
    CHECK(json_object_object_length(external) == 0);
    json_object_put(external);
    br_result_clear(&r);
    br_results_clear(&rs);
    r = candidate("unmoved", NULL, false);
    CHECK(br_results_push(NULL, &r) != 0 && r.raw.len == 7);
    br_result_clear(&r);

    const br_slice secrets[] = { SLICE("synthetic-key"), SLICE("other-key") };
    CHECK(br_result_set_verification_error(&r, "synthetic-key timeout synthetic-key other-key", secrets, 2) == 0);
    CHECK(!strcmp(r.verification_error, "[REDACTED] timeout [REDACTED] [REDACTED]"));
    CHECK(br_result_set_verification_error(&r, NULL, NULL, 0) == 0);
    CHECK(!strcmp(r.verification_error, "[REDACTED] timeout [REDACTED] [REDACTED]"));
    CHECK(br_result_set_verification_error(&r, "connection refused", NULL, 0) == 0);
    CHECK(!strcmp(r.verification_error, "connection refused"));
    CHECK(br_result_set_verification_error(&r, "not installed", NULL, 1) != 0);
    CHECK(!strcmp(r.verification_error, "connection refused"));
    br_result_clear(&r);

    r = candidate("first", NULL, false); CHECK(!br_results_push(&rs, &r));
    r = candidate("second", NULL, false); CHECK(!br_results_push(&rs, &r));
    br_clean_results(&rs, false);
    CHECK(rs.len == 1 && rs.items[0].raw.len == 5 && !memcmp(rs.items[0].raw.data, "first", 5));
    br_results_clear(&rs);
    r = candidate("drop", "different", false); CHECK(!br_results_push(&rs, &r));
    r = candidate("old", "same", true); CHECK(!br_results_push(&rs, &r));
    r = candidate("new", "same", true);
    r.verification_from_cache = true;
    CHECK(!br_result_set_verification_error(&r, "preserved", NULL, 0));
    CHECK(!br_results_push(&rs, &r));
    r = candidate("distinct", "other", true); CHECK(!br_results_push(&rs, &r));
    br_clean_results(&rs, true);
    CHECK(rs.len == 2);
    CHECK(rs.items[0].raw.len == 3 && !memcmp(rs.items[0].raw.data, "new", 3));
    CHECK(rs.items[0].verification_from_cache && !strcmp(rs.items[0].verification_error, "preserved"));
    CHECK(!strcmp(rs.items[1].redacted, "other"));
    br_results_clear(&rs);
    r = candidate("null", NULL, true); CHECK(!br_results_push(&rs, &r));
    r = candidate("empty", "", true); CHECK(!br_results_push(&rs, &r));
    br_clean_results(&rs, false);
    CHECK(rs.len == 1 && rs.items[0].raw.len == 5 && !memcmp(rs.items[0].raw.data, "empty", 5));
    br_results_clear(&rs);
}

typedef struct { br_span spans[16][4]; size_t ngroups[16], count; int abort_code; } captures;
static int capture(void *user, const br_span *groups, size_t n)
{
    captures *c = user;
    CHECK(c->count < 16 && n <= 4);
    c->ngroups[c->count] = n;
    memcpy(c->spans[c->count++], groups, n * sizeof(*groups));
    return c->abort_code;
}

static captures match(const char *pattern, br_slice input)
{
    br_regex *re = NULL;
    char *error = NULL;
    captures c = {0};
    CHECK(!br_regex_compile(pattern, &re, &error) && !error);
    CHECK(!br_regex_each(re, input, capture, &c, &error) && !error);
    br_regex_free(re);
    return c;
}

static void regex_tests(void)
{
    const char *const keywords[] = { "ab.tract", "abyssale" };
    char *prefix = NULL;
    CHECK(!br_prefix_regex(keywords, 2, &prefix));
    CHECK(!strcmp(prefix, "(?i:ab.tract|abyssale)(?:.|[\\n\\r]){0,40}?"));
    free(prefix);
    CHECK(!br_prefix_regex(NULL, 0, &prefix));
    CHECK(!strcmp(prefix, "(?i:)(?:.|[\\n\\r]){0,40}?"));
    free(prefix);
    captures c = match("(a)?(b)", SLICE("b ab"));
    CHECK(c.count == 2 && c.ngroups[0] == 3);
    CHECK(c.spans[0][1].begin == SIZE_MAX && c.spans[0][1].end == SIZE_MAX);
    CHECK(c.spans[0][2].begin == 0 && c.spans[0][2].end == 1);
    CHECK(c.spans[1][0].begin == 2 && c.spans[1][0].end == 4);
    c = match("a*", SLICE("aaab"));
    CHECK(c.count == 2 && c.spans[0][0].end == 3 && c.spans[1][0].begin == 4);
    c = match("", SLICE("\xc3\xa9x"));
    CHECK(c.count == 3 && c.spans[1][0].begin == 2 && c.spans[2][0].begin == 3);
    c = match("x$", SLICE("x\n")); CHECK(c.count == 0);
    c = match("\\b(x)\\b", SLICE("\xc3\xa9x\xc3\xa9")); CHECK(c.count == 1);
    c = match("x", SLICE("x\0x")); CHECK(c.count == 2 && c.spans[1][0].begin == 2);
    c = match("(?i:keyword)([a-z]+)", SLICE("KEYWORDa KEYWORDA")); CHECK(c.count == 1);
    br_regex *re = NULL;
    char *error = NULL;
    const char *bad[] = { "[", "(?=a)", "(a)\\1", "a++", "(?R)", "\\K" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        CHECK(br_regex_compile(bad[i], &re, &error) != 0 && error && !re);
        free(error); error = NULL;
    }
    CHECK(!br_regex_compile("x", &re, &error));
    c = (captures){ .abort_code = 7 };
    CHECK(br_regex_each(re, SLICE("xx"), capture, &c, &error) == 7 && c.count == 1 && error);
    free(error); error = NULL;
    c = (captures){0};
    CHECK(br_regex_each(re, SLICE("\xffx"), capture, &c, &error) != 0 && error && !c.count);
    free(error); error = NULL;
    br_regex_free(re);
    CHECK(!br_regex_compile("(a+)+$", &re, &error));
    c = (captures){0};
    CHECK(br_regex_each(re, SLICE("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"), capture, &c, &error) != 0 && error && !c.count);
    CHECK(strstr(error, "limit") != NULL);
    free(error);
    br_regex_free(re);
}

static void fp_tests(void)
{
    static const char *const terms[] = { "example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****" };
    char *reason = NULL;
    CHECK(br_known_false_positive(SLICE("EXAMPLE"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "matches term: example")); free(reason);
    CHECK(br_known_false_positive(SLICE("23ExAmPlE91"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "contains term: example")); free(reason);
    CHECK(br_known_false_positive(SLICE("\xff"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "invalid utf8")); free(reason);
    CHECK(!br_known_false_positive(SLICE("b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y"), terms, 7, true, &reason) && !reason);
    const char *words[] = { "password", "dictionary", "rustonomicon", "00000000-0000-0000-0000-000000000000" };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); ++i) {
        br_slice s = { (const unsigned char *)words[i], strlen(words[i]) };
        CHECK(br_known_false_positive(s, NULL, 0, true, &reason));
        CHECK(reason && !strncmp(reason, "matches wordlist: ", 18)); free(reason);
        CHECK(!br_known_false_positive(s, NULL, 0, false, &reason) && !reason);
    }
    CHECK(br_known_false_positive(SLICE("k\0example"), terms, 7, false, &reason));
    CHECK(!strcmp(reason, "contains term: example")); free(reason);
    CHECK(br_known_false_positive(SLICE("\xc3\x89"), terms, 7, true, &reason));
    CHECK(!strncmp(reason, "unsupported:", 12)); free(reason);
}

typedef struct { size_t calls, releases; bool transport_failure; uint32_t timeout; br_http_profile profile; } fake;
static int fake_send(void *user, const br_scan_ctx *ctx, const br_http_request *req,
                      br_http_response *response, char **error)
{
    fake *f = user;
    ++f->calls;
    CHECK(ctx->transport->user == f);
    CHECK(!strcmp(req->method, "POST") && !strcmp(req->url, "https://synthetic.invalid/path?q=a%20b"));
    CHECK(req->nheaders == 4);
    CHECK(!strcmp(req->headers[0].name, "X-Repeat") && !strcmp(req->headers[0].value, "one"));
    CHECK(!strcmp(req->headers[1].name, "X-Repeat") && !strcmp(req->headers[1].value, "two"));
    CHECK(!strcmp(req->headers[2].name, "User-Agent") && !strcmp(req->headers[2].value, "caller"));
    CHECK(!strcmp(req->headers[3].name, "User-Agent") && !strcmp(req->headers[3].value, "TruffleHog synthetic-tests"));
    CHECK(req->body.len == 3 && !memcmp(req->body.data, "a\0b", 3));
    CHECK(req->profile == f->profile && req->detector_type == 521);
    CHECK(req->timeout_ms > 0 && req->timeout_ms <= f->timeout);
    if (f->profile != BR_HTTP_SANE) CHECK(req->timeout_ms == f->timeout);
    if (f->transport_failure) { *error = strdup("synthetic timeout"); return 9; }
    response->status = 200;
    response->body = SLICE("partial");
    response->body_error = "synthetic body error";
    return 0;
}
static void fake_release(void *user, br_http_response *response)
{
    fake *f = user;
    ++f->releases;
    CHECK(response->status == 0 || response->status == 200);
}
static bool always_cancelled(void *user) { (void)user; return true; }

static void http_tests(void)
{
    fake f = { .timeout = 5000 };
    const br_transport transport = { &f, fake_send, fake_release };
    br_scan_ctx ctx = { .transport = &transport, .user_agent = "synthetic-tests" };
    const br_header headers[] = { {"X-Repeat", "one"}, {"X-Repeat", "two"}, {"User-Agent", "caller"} };
    br_http_request request = {
        .method = "POST", .url = "https://synthetic.invalid/path?q=a%20b",
        .headers = headers, .nheaders = 3, .body = SLICE("a\0b"),
        .profile = BR_HTTP_SANE, .detector_type = 521,
    };
    br_http_response response = {0};
    char *error = NULL;
    CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
    CHECK(response.status == 200 && response.body.len == 7 && response.body_error);
    CHECK(!strcmp(headers[2].value, "caller") && !request.timeout_ms && request.nheaders == 3);
    br_http_release(&ctx, &response);
    CHECK(!response.status && !response.body.data && !response.body_error && f.releases == 1);
    f.transport_failure = true;
    CHECK(br_http_send(&ctx, &request, &response, &error) == 9 && error);
    free(error); error = NULL;
    br_http_release(&ctx, &response);
    f.transport_failure = false;
    request.timeout_ms = 123; f.timeout = 123;
    CHECK(!br_http_send(&ctx, &request, &response, &error));
    br_http_release(&ctx, &response);
    request.timeout_ms = 0; f.timeout = 1000;
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    ctx.deadline_monotonic_ms = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + 1000;
    CHECK(!br_http_send(&ctx, &request, &response, &error));
    br_http_release(&ctx, &response);
    size_t sent = f.calls;
    ctx.deadline_monotonic_ms = 1;
    CHECK(br_http_send(&ctx, &request, &response, &error) && !strcmp(error, "context deadline exceeded"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    ctx.deadline_monotonic_ms = 0; ctx.cancelled = always_cancelled;
    CHECK(br_http_send(&ctx, &request, &response, &error) && !strcmp(error, "context canceled"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    ctx.cancelled = NULL;
    for (int profile = BR_HTTP_DETECTOR_LOCAL; profile <= BR_HTTP_DETECTOR_PUBLIC; ++profile) {
        request.profile = f.profile = (br_http_profile)profile;
        request.timeout_ms = 0; f.timeout = 10000;
        CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
        br_http_release(&ctx, &response);
        request.timeout_ms = 123; f.timeout = 123;
        CHECK(!br_http_send(&ctx, &request, &response, &error) && !error);
        br_http_release(&ctx, &response);
    }
    request.timeout_ms = 0;
    sent = f.calls;
    for (int profile = BR_HTTP_PINNED_RETRYABLE; profile <= BR_HTTP_RETRYABLE; ++profile) {
        request.profile = (br_http_profile)profile;
        CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "unsupported"));
        free(error); error = NULL; br_http_release(&ctx, &response);
    }
    request.profile = BR_HTTP_SANE; request.dedup_key = SLICE("synthetic");
    CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "coalescing"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    request.dedup_key = (br_slice){0}; ctx.user_agent = "bad\r\nvalue";
    CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "user agent"));
    free(error); error = NULL; br_http_release(&ctx, &response);
    CHECK(f.calls == sent);
    ctx.transport = NULL;
    CHECK(br_http_send(&ctx, &request, &response, &error) && strstr(error, "not installed"));
    CHECK(!response.status && !response.body.data);
    free(error);
    br_http_release(&ctx, &response);
}

/* Private adapter hook, also exercised by the isolated proxy regression. */
extern const br_transport *br_curl_transport_init(char **error);

static void unsupported_native_profiles(void)
{
    char *error = NULL;
    const br_transport *transport = br_curl_transport_init(&error);
    CHECK(transport != NULL && error == NULL);
    br_scan_ctx ctx = {.transport = transport};
    /* Invalid URL prevents DNS even if a future regression removes the guard. */
    br_http_request request = {.method = "GET", .url = "://invalid"};
    br_http_response response = {0};
    for (int profile = BR_HTTP_DETECTOR_LOCAL; profile <= BR_HTTP_DETECTOR_PUBLIC; ++profile) {
        request.profile = (br_http_profile)profile;
        CHECK(br_http_send(&ctx, &request, &response, &error) != 0);
        CHECK(error && !strcmp(error, "unsupported: native curl HTTP client profile"));
        CHECK(response.status == 0 && response.body.data == NULL);
        free(error); error = NULL;
        br_http_release(&ctx, &response);
    }
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    result_tests(); regex_tests(); fp_tests(); http_tests(); unsupported_native_profiles();
    printf("core: %zu assertions, 0 failures\n", checks);
    return 0;
}
