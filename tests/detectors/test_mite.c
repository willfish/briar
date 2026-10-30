/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/go_url.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

int br_mite_init(const br_detector **out, char **error);

static size_t fail_size, fail_after, malloc_after, parse_calls, decode_calls;
static size_t fail_parse, fail_decode, fail_request_parse, fail_key_after;
static bool fail_prefixed, fail_url_compile, fail_capture, fail_auth, fail_push, fail_setter;
static unsigned capture_calls, auth_calls, push_calls, setter_calls;

void *malloc(size_t n)
{
    if (malloc_after && !--malloc_after) return NULL;
    if (fail_after && n == fail_size && !--fail_after) return NULL;
    return calloc(1, n);
}
char *strdup(const char *text)
{
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && !--fail_key_after) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
#define br_result_set_verification_error mite_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    return fail_setter ? 1 : mite_real_setter(result, cause, secrets, nsecrets);
}
#define br_go_url_parse mite_real_parse
#define br_go_url_decode mite_real_decode
#include "../../src/go_url.c"
#undef br_go_url_parse
#undef br_go_url_decode
int br_go_url_parse(br_slice input, br_go_url_parts *out, br_go_url_error *ordinary, char **error)
{
    ++parse_calls;
    int rc = mite_real_parse(input, out, ordinary, error);
    if (fail_request_parse && parse_calls == fail_request_parse) malloc_after = 2;
    if (fail_parse && parse_calls == fail_parse) { if (error && !*error) *error = strdup("owned parser +1"); return 1; }
    return rc;
}
int br_go_url_decode(br_slice input, bool query, br_bytes *out, bool *valid, char **error)
{
    ++decode_calls;
    int rc = mite_real_decode(input, query, out, valid, error);
    if (fail_decode && decode_calls == fail_decode) { if (error && !*error) *error = strdup("owned decoder +1"); return 1; }
    return rc;
}
static int mite_prefixed(const char *const *keys, size_t nkeys, const char *suffix, br_regex **out, char **error)
{
    if (fail_prefixed) { *out = NULL; if (error) *error = strdup("owned prefixed +1"); return 1; }
    return br_regex_compile_prefixed(keys, nkeys, suffix, out, error);
}
static int mite_compile(const char *pattern, br_regex **out, char **error)
{
    if (fail_url_compile) { *out = NULL; if (error) *error = strdup("owned URL compile +1"); return 1; }
    return br_regex_compile(pattern, out, error);
}
static int mite_captures(const br_regex *regex, br_slice input, br_captures *captures, bool unique, char **error)
{
    ++capture_calls;
    int rc = br_captures_find(regex, input, captures, unique, error);
    if (fail_capture && capture_calls == 2) { if (error && !*error) *error = strdup("owned capture +1"); return 1; }
    return rc;
}
static int mite_basic(br_slice user, br_slice password, char **out, char **error)
{
    ++auth_calls;
    if (fail_auth) { if (error) *error = strdup("owned Basic +1"); return 1; }
    return br_http_basic_auth(user, password, out, error);
}
static int mite_push(br_results *out, br_result *result)
{
    ++push_calls;
    return fail_push ? 1 : br_results_push(out, result);
}
#define br_regex_compile_prefixed mite_prefixed
#define br_regex_compile mite_compile
#define br_captures_find mite_captures
#define br_http_basic_auth mite_basic
#define br_results_push mite_push
#include "../../src/detectors/mite.c"
#undef br_results_push
#undef br_http_basic_auth
#undef br_captures_find
#undef br_regex_compile
#undef br_regex_compile_prefixed

static const char key1[] = "b7c9d2e5f6g8h3j4", key2[] = "m2n3p4q5r6s7t8u9";
static const char alpha[] = "https://alpha.mite.yo.lk/account.json";
static const char beta[] = "https://beta/mite.yo.lk/account.json";

typedef struct {
    test_http http; br_transport transport;
    const char *urls[4], *keys[4], *users[4], *passwords[4];
    const char *borrowed_url[4], *borrowed_key[4], *borrowed_auth[4];
    int statuses[4], errors[4]; br_header markers[4];
    size_t count, release_order[4], release_len[4];
    const br_results *out;
} fixture;
static void mite_check_auth(const char *actual, const char *user, const char *password)
{
    char plain[80], expected[120]; int n = snprintf(plain, sizeof(plain), "%s:%s", user, password);
    CHECK(n > 0 && (size_t)n < sizeof(plain)); memcpy(expected, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)expected + 6, (const unsigned char *)plain, n) == 4 * ((n + 2) / 3));
    CHECK(actual && !strcmp(actual, expected));
}
static void mite_inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    static const unsigned char binary[] = {0xff, 0, '{', ']'};
    fixture *s = http->user; size_t i = http->calls - 1;
    CHECK(i < s->count && i < 4 && ctx->transport == &s->transport);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, s->urls[i]));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 682);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == (s->users[i] ? 4u : 3u));
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Miteapikey") && !strcmp(request->headers[1].value, s->keys[i]));
    s->borrowed_url[i] = request->url; s->borrowed_key[i] = request->headers[1].value;
    if (s->users[i]) {
        CHECK(!strcmp(request->headers[2].name, "Authorization"));
        s->borrowed_auth[i] = request->headers[2].value; mite_check_auth(s->borrowed_auth[i], s->users[i], s->passwords[i]);
    }
    CHECK(!strcmp(request->headers[request->nheaders - 1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[request->nheaders - 1].value, "TruffleHog mite-offline"));
    s->markers[i] = (br_header){"synthetic-attempt", s->keys[i]};
    http->response = (br_http_response){.headers = &s->markers[i], .nheaders = 1,
        .status = s->statuses[i] ? s->statuses[i] : 200, .body = {binary, sizeof(binary)}, .body_error = "ignored body failure"};
    http->send_rc = s->errors[i]; http->send_error = s->errors[i] ? "unsupported: shared preparation or Do error" : NULL;
}
static void mite_close(void *opaque, br_http_response *response)
{
    test_http *http = opaque; fixture *s = http->user; size_t i = 0;
    while (i < s->count && response->headers != &s->markers[i]) ++i;
    CHECK(http->releases < 4 && s->out);
    if (i < s->count) {
        CHECK(!strcmp(s->borrowed_url[i], s->urls[i]) && !strcmp(s->borrowed_key[i], s->keys[i]));
        if (s->users[i]) mite_check_auth(s->borrowed_auth[i], s->users[i], s->passwords[i]);
    } else CHECK(!response->status && !response->headers && !response->body.data && !response->body_error);
    s->release_order[http->releases] = i; s->release_len[http->releases] = s->out->len;
    test_http_release(opaque, response);
}
static br_scan_ctx mite_context(fixture *s)
{
    s->http = (test_http){.inspect = mite_inspect, .user = s};
    s->transport = (br_transport){&s->http, test_http_send, mite_close};
    return (br_scan_ctx){.transport = &s->transport, .user_agent = "mite-offline"};
}
static int mite_invoke(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        const void *input, size_t n, br_results *out, char **error)
{
    return detector->scan(detector, ctx, verify, (br_slice){input, n}, out, error);
}
static size_t mite_input(unsigned char *out, const char *key, const unsigned char *url, size_t n)
{
    size_t keylen = strlen(key); memcpy(out, "mite ", 5); memcpy(out + 5, key, keylen); out[5 + keylen] = '\n';
    memcpy(out + 6 + keylen, url, n); return 6 + keylen + n;
}
static void mite_fields(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 682, key, "key"); CHECK(result->verified == verified && !result->verification_error);
}
static size_t mite_nov(const br_detector *detector, const unsigned char *input, size_t len)
{
    size_t parses = parse_calls; br_results out = test_scan(detector, NULL, false, input, len);
    CHECK(parse_calls == parses);
    for (size_t i = 0; i < out.len; ++i) mite_fields(&out.items[i], key1, false);
    size_t n = out.len; br_results_clear(&out); return n;
}
static void mite_url_case(const br_detector *detector, const unsigned char *url, size_t len,
                          size_t extracted, const char *rendered, const char *user, const char *password)
{
    unsigned char input[512]; size_t n = mite_input(input, key1, url, len);
    CHECK(mite_nov(detector, input, n) == extracted);
    br_results out = {0}; char *error = NULL;
    fixture s = {.count = rendered ? 1u : 0u, .urls = {rendered}, .keys = {key1}, .users = {user}, .passwords = {password}, .out = &out};
    br_scan_ctx ctx = mite_context(&s);
    CHECK(mite_invoke(detector, &ctx, true, input, n, &out, &error) == 0 && !error);
    CHECK(out.len == s.count && s.http.calls == s.count && s.http.releases == s.count);
    if (out.len) { mite_fields(&out.items[0], key1, true); CHECK(s.release_len[0] == 1); }
    br_results_clear(&out);
}
static void mite_prior(br_results *out, br_result *saved)
{
    br_result result = {.detector_type = 19}; result.raw.data = (unsigned char *)strdup("preserve caller"); result.raw.len = 15;
    result.verification_error = strdup("caller diagnostic"); result.extra_data = json_object_new_object();
    CHECK(br_results_push(out, &result) == 0); *saved = out->items[0];
}
static void mite_fatal(const br_detector *detector, const br_scan_ctx *ctx, bool verify, const unsigned char *input, size_t n,
                       br_results *out, const br_result *saved)
{
    char *error = NULL;
    CHECK(mite_invoke(detector, ctx, verify, input, n, out, &error) != 0 && error);
    CHECK(out->len == 1 && !memcmp(&out->items[0], saved, sizeof(*saved))); free(error);
}

int main(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    fail_prefixed = true; CHECK(br_mite_init(&detector, &error) != 0 && !detector && error); free(error); error = NULL; fail_prefixed = false;
    fail_url_compile = true; CHECK(br_mite_init(&detector, &error) != 0 && !detector && error); free(error); error = NULL; fail_url_compile = false;
    CHECK(br_mite_init(&detector, &error) == 0 && detector && !error);
    CHECK(BR_ABI_REVISION == 1 && detector->type == 682 && detector->version == 0 && !strcmp(detector->name, "Mite") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Mite is a time tracking tool. Mite API keys can be used to access and modify time tracking data."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mite"));
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const br_detector *again = NULL; CHECK(br_mite_init(&again, &error) == 0 && again == detector && !error);
    CHECK(br_mite_init(NULL, &error) != 0 && error); free(error); error = NULL;

    struct url_case { const char *input, *output, *user, *password; } cases[] = {
        {"alpha.mite.yo.lk", alpha, NULL, NULL},
        {"alpha/mite.yo.lk", "https://alpha/mite.yo.lk/account.json", NULL, NULL},
        {"alpha?mite.yo.lk", "https://alpha?mite.yo.lk/account.json", NULL, NULL},
        {"alpha#mite.yo.lk", "https://alpha#mite.yo.lk/account.json", NULL, NULL},
        {"alpha@mite.yo.lk", "https://alpha@mite.yo.lk/account.json", "alpha", ""},
        {"alpha:mite@yo.lk", "https://alpha:mite@yo.lk/account.json", "alpha", "mite"},
        {"alpha@mite@yo.lk", "https://alpha%40mite@yo.lk/account.json", "alpha@mite", ""},
        {"alpha:mite:yo@lk", "https://alpha:mite%3Ayo@lk/account.json", "alpha", "mite:yo"},
        {"alpha\xf0\x9f\x92\xa1mite.yo.lk", "https://alpha%F0%9F%92%A1mite.yo.lk/account.json", NULL, NULL},
        {"alpha/mite\xc3\xa9yo.lk", "https://alpha/mite%C3%A9yo.lk/account.json", NULL, NULL},
        {"alpha/mite yo.lk", "https://alpha/mite%20yo.lk/account.json", NULL, NULL},
        {"alpha/mite!yo.lk", "https://alpha/mite!yo.lk/account.json", NULL, NULL},
        {"alpha/mite[yo.lk", "https://alpha/mite[yo.lk/account.json", NULL, NULL},
        {"alpha/mite+yo.lk", "https://alpha/mite+yo.lk/account.json", NULL, NULL},
        {"alpha?mite yo.lk", "https://alpha?mite yo.lk/account.json", NULL, NULL},
        {"alpha?mite.yo%lk", "https://alpha?mite.yo%lk/account.json", NULL, NULL},
        {"alpha#mite\vyo.lk", "https://alpha#mite%0Byo.lk/account.json", NULL, NULL},
        {"alpha#mite\xc3\xa9yo.lk", "https://alpha#mite%C3%A9yo.lk/account.json", NULL, NULL},
        {"alpha mite.yo.lk", NULL, NULL, NULL}, {"alpha:mite.yo.lk", NULL, NULL, NULL},
        {"alpha\\mite.yo.lk", NULL, NULL, NULL}, {"alpha/mite.yo%lk", NULL, NULL, NULL},
        {"alpha\vmite.yo.lk", NULL, NULL, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        mite_url_case(detector, (const unsigned char *)cases[i].input, strlen(cases[i].input), 1, cases[i].output, cases[i].user, cases[i].password);
    static const unsigned char nul[] = "alpha\0mite.yo.lk", nul_fragment[] = "alpha#mite\0yo.lk";
    mite_url_case(detector, nul, sizeof(nul) - 1, 1, NULL, NULL, NULL);
    mite_url_case(detector, nul_fragment, sizeof(nul_fragment) - 1, 1, "https://alpha#mite%00yo.lk/account.json", NULL, NULL);
    const char *invalid_urls[] = {"alpha\nmite.yo.lk", "Alpha.mite.yo.lk", "alpha.MITE.yo.lk", "alpha.mite.Yo.lk", "alpha.mite.yo.lkX", "alpha.mite.yo.lkx", "alpha\xffmite.yo.lk"};
    for (size_t i = 0; i < sizeof(invalid_urls) / sizeof(invalid_urls[0]); ++i)
        mite_url_case(detector, (const unsigned char *)invalid_urls[i], strlen(invalid_urls[i]), 0, NULL, NULL, NULL);

    unsigned char input[8192]; size_t n = mite_input(input, key1, (const unsigned char *)"alpha.mite.yo.lk", 16);
    CHECK(mite_nov(detector, (const unsigned char *)"mite b7c9d2e5f6g8h3j4", 21) == 0);
    CHECK(mite_nov(detector, (const unsigned char *)"alpha.mite.yo.lk", 16) == 0);
    const char *invalid_keys[] = {"B7c9d2e5f6g8h3j4", "b7c9d2e5f6g8h3j", "b7c9d2e5f6g8h3j4a", "_b7c9d2e5f6g8h3j4", "b7c9d2e5f6g8h3j4_"};
    for (size_t i = 0; i < sizeof(invalid_keys) / sizeof(invalid_keys[0]); ++i) {
        size_t m = mite_input(input, invalid_keys[i], (const unsigned char *)"alpha.mite.yo.lk", 16); CHECK(mite_nov(detector, input, m) == 0);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "MITE", 4); size_t m = 4;
        for (size_t j = 0; j < gap; ++j) { memcpy(input + m, "\xf0\x9f\x92\xa1", 4); m += 4; }
        memcpy(input + m, key1, 16); m += 16; memcpy(input + m, "\nalpha.mite.yo.lk", 17); m += 17;
        CHECK(mite_nov(detector, input, m) == (gap == 40 ? 1u : 0u));
    }
    memcpy(input, "MITE\r\n", 6); memcpy(input + 6, key1, 16); memcpy(input + 22, "\nalpha.mite.yo.lk", 17);
    CHECK(mite_nov(detector, input, 39) == 1);
    n = mite_input(input, key1, (const unsigned char *)"alpha.mite.yo.lk", 16);
    memmove(input + 3022, input + 22, 16); memset(input + 22, ' ', 3000); CHECK(mite_nov(detector, input, 3038) == 1);
    memset(input + 22, 'a', 3000); memcpy(input + 3022, ".mite.yo.lk", 11); CHECK(mite_nov(detector, input, 3033) == 1);

    /* Independent complete lists, duplicate products and key-outer ordering. */
    n = (size_t)snprintf((char *)input, sizeof(input), "mite %s\nmite %s\nalpha.mite.yo.lk beta/mite.yo.lk", key1, key2);
    br_results out = {0}; fixture s = {.urls = {alpha, beta, alpha, beta}, .keys = {key1, key1, key2, key2}, .count = 4, .out = &out};
    br_scan_ctx ctx = mite_context(&s);
    CHECK(mite_invoke(detector, &ctx, true, input, n, &out, &error) == 0 && !error && out.len == 4);
    for (size_t i = 0; i < 4; ++i) { mite_fields(&out.items[i], i < 2 ? key1 : key2, true); CHECK(s.release_order[i] == 3 - i && s.release_len[i] == 4); }
    CHECK(s.http.calls == 4 && s.http.releases == 4); br_results_clear(&out);
    s = (fixture){.urls = {alpha, beta, alpha, beta}, .keys = {key1, key1, key2, key2}, .count = 4, .out = &out, .errors = {0, 7, 0, 0}}; ctx = mite_context(&s);
    CHECK(mite_invoke(detector, &ctx, true, input, n, &out, &error) == 0 && !error && out.len == 4);
    CHECK(s.release_order[0] == 1 && s.release_len[0] == 1 && s.release_order[1] == 3 && s.release_order[2] == 2 && s.release_order[3] == 0);
    for (size_t i = 0; i < 4; ++i) mite_fields(&out.items[i], i < 2 ? key1 : key2, i != 1);
    br_results_clear(&out);
    n = (size_t)snprintf((char *)input, sizeof(input), "mite %s\nmite %s\nalpha.mite.yo.lk alpha.mite.yo.lk", key1, key1);
    CHECK(mite_nov(detector, input, n) == 4);

    n = mite_input(input, key1, (const unsigned char *)"alpha.mite.yo.lk", 16);
    const int statuses[] = {199, 200, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        s = (fixture){.urls = {alpha}, .keys = {key1}, .count = 1, .statuses = {statuses[i]}, .out = &out}; ctx = mite_context(&s);
        CHECK(mite_invoke(detector, &ctx, true, input, n, &out, &error) == 0 && !error && out.len == 1);
        mite_fields(&out.items[0], key1, statuses[i] >= 200 && statuses[i] < 300); CHECK(s.http.releases == 1); br_results_clear(&out);
    }
    /* Mandatory finding and literal URL precede nil; parse/auth do not. NoV
     * never constructs or parses the URL, even on invalid/control captures. */
    br_result saved; mite_prior(&out, &saved); size_t before_parse = parse_calls;
    CHECK(mite_invoke(detector, NULL, true, input, n, &out, &error) == 0 && !error && out.len == 1 && parse_calls == before_parse);
    fail_size = 16; fail_after = 1; mite_fatal(detector, NULL, true, input, n, &out, &saved); fail_after = 0;
    fail_key_after = 1; mite_fatal(detector, NULL, true, input, n, &out, &saved); CHECK(!fail_key_after);
    fail_size = strlen(alpha) + 1; fail_after = 1; mite_fatal(detector, NULL, true, input, n, &out, &saved); CHECK(!fail_after && parse_calls == before_parse);
    fail_after = 1; CHECK(mite_invoke(detector, NULL, false, input, n, &out, &error) == 0 && !error && out.len == 2 && fail_after == 1); fail_after = 0;
    br_result_clear(&out.items[--out.len]);
    n = mite_input(input, key1, nul, sizeof(nul) - 1); fail_after = 1;
    mite_fatal(detector, NULL, true, input, n, &out, &saved); CHECK(!fail_after && parse_calls == before_parse);
    fail_parse = parse_calls + 1; s = (fixture){.out = &out}; ctx = mite_context(&s);
    mite_fatal(detector, &ctx, true, input, n, &out, &saved); fail_parse = 0; CHECK(!s.http.calls && !s.http.releases);

    /* Late owned failures preserve earlier caller objects and roll back only
     * this invocation, releasing successful requests after publication. */
    n = (size_t)snprintf((char *)input, sizeof(input), "mite %s\nmite %s\nalpha.mite.yo.lk", key1, key2);
    struct allocation { size_t size, after, sends; } failures[] = {{17, 2, 0}, {17, 3, 0}, {16, 2, 1}, {38, 3, 1}, {38, 4, 1}};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        s = (fixture){.urls = {alpha, alpha}, .keys = {key1, key2}, .count = 2, .out = &out}; ctx = mite_context(&s);
        fail_size = failures[i].size; fail_after = failures[i].after;
        mite_fatal(detector, &ctx, true, input, n, &out, &saved); CHECK(!fail_after && s.http.calls == failures[i].sends && s.http.releases == s.http.calls); fail_after = 0;
        if (s.http.releases) CHECK(s.release_len[0] == 2);
    }
    s = (fixture){.urls = {alpha, alpha}, .keys = {key1, key2}, .count = 2, .out = &out}; ctx = mite_context(&s);
    fail_request_parse = parse_calls + 2; mite_fatal(detector, &ctx, true, input, n, &out, &saved); fail_request_parse = 0;
    CHECK(!malloc_after && s.http.calls == 1 && s.http.releases == 1 && s.release_len[0] == 2);
    fail_capture = true; capture_calls = 0; mite_fatal(detector, NULL, false, input, n, &out, &saved); fail_capture = false;
    s = (fixture){.urls = {alpha, alpha}, .keys = {key1, key2}, .count = 2, .out = &out}; ctx = mite_context(&s);
    fail_push = true; mite_fatal(detector, &ctx, true, input, n, &out, &saved); fail_push = false; CHECK(s.http.calls == 1 && s.http.releases == 1);
    n = mite_input(input, key1, (const unsigned char *)"alpha/mite yo.lk", 16); fail_decode = decode_calls + 1;
    s = (fixture){.out = &out}; ctx = mite_context(&s); mite_fatal(detector, &ctx, true, input, n, &out, &saved); fail_decode = 0; CHECK(!s.http.calls && !s.http.releases);
    n = mite_input(input, key1, (const unsigned char *)"alpha:mite@yo.lk", 16); fail_auth = true;
    mite_fatal(detector, &ctx, true, input, n, &out, &saved); fail_auth = false; CHECK(!s.http.calls && !s.http.releases);
    br_results_clear(&out);
    /* Whole shared preparation errors are ordinary and release once. */
    ctx = (br_scan_ctx){0}; n = mite_input(input, key1, (const unsigned char *)"alpha.mite.yo.lk", 16);
    fail_setter = true; CHECK(mite_invoke(detector, &ctx, true, input, n, &out, &error) == 0 && !error && out.len == 1); mite_fields(&out.items[0], key1, false); br_results_clear(&out);
    s = (fixture){.count = 1, .out = &out}; ctx = mite_context(&s); ctx.user_agent = "invalid\r\nsuffix";
    CHECK(mite_invoke(detector, &ctx, true, input, n, &out, &error) == 0 && !error && out.len == 1 && !s.http.calls && s.http.releases == 1 && !s.release_len[0]); br_results_clear(&out);
    CHECK(setter_calls == 0); fail_setter = false;
    CHECK(auth_calls > 0 && decode_calls > 0 && capture_calls > 0 && push_calls > 0);
    return test_finish("mite");
}
