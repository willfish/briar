/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static const char key[] = "Ab3dE5fGh7Jk9LmNoP2q";
static const char pat[] = "glpat-abcdefghijklmnopqrst";
static const char modern[] = "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ0.a2.abcdefgh9";
static size_t fail_add;
int json_object_object_add(struct json_object *map, const char *name, struct json_object *value)
{
    if (fail_add && !--fail_add) return 1;
    return json_object_object_add_ex(map, name, value, 0);
}
#ifdef BR_GITLAB_FAULTS
static int fault;
static size_t fail_malloc_size;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n)
{
    if (fault == 5 && n == fail_malloc_size) { fault = 0; return NULL; }
    return __real_malloc(n);
}
int __real_br_finding_pair_bytes(br_result *, int32_t, br_slice, const char *, br_slice, const char *, br_slice);
int __wrap_br_finding_pair_bytes(br_result *r, int32_t t, br_slice k, const char *kn, br_slice h, const char *hn, br_slice sep)
{
    if (fault == 1) { fault = 0; return 1; }
    return __real_br_finding_pair_bytes(r, t, k, kn, h, hn, sep);
}
int __real_br_json_document(br_slice, br_json **, char **);
int __wrap_br_json_document(br_slice b, br_json **v, char **c)
{
    if (fault == 2) { fault = 0; return -1; }
    return __real_br_json_document(b, v, c);
}
int __real_br_result_set_verification_error(br_result *, const char *, const br_slice *, size_t);
int __wrap_br_result_set_verification_error(br_result *r, const char *c, const br_slice *s, size_t n)
{
    CHECK(!s && !n);
    if (fault == 3) { fault = 0; return 1; }
    return __real_br_result_set_verification_error(r, c, s, n);
}
int __real_br_results_push(br_results *, br_result *);
int __wrap_br_results_push(br_results *r, br_result *v)
{
    if (fault == 4) { fault = 0; return 1; }
    return __real_br_results_push(r, v);
}
#endif

typedef struct { int status, rc; const char *body, *cause, *read; size_t len; bool fail_metadata; } step;
typedef struct {
    step steps[8]; size_t count, calls, releases;
    const char *auth, *url;
    char saved_auth[400], saved_url[8192];
} fake;
static int send_fake(void *opaque, const br_scan_ctx *ctx, const br_http_request *req,
                     br_http_response *res, char **error)
{
    fake *f = opaque;
    CHECK(ctx && f->calls < f->count && !f->auth && !f->url);
    CHECK(!strcmp(req->method, "GET") && req->profile == BR_HTTP_SANE && req->timeout_ms == 5000);
    CHECK(req->detector_type == 9 && !req->body.data && !req->body.len && !req->dedup_key.len);
    CHECK(req->nheaders == 2 && !strcmp(req->headers[0].name, "Authorization"));
    CHECK(!strncmp(req->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(req->headers[1].name, "User-Agent") && !strcmp(req->headers[1].value, "TruffleHog offline"));
    CHECK(strstr(req->url, "/api/v4/user"));
    /* These values borrow provider-owned storage, not synthesized headers/UA. */
    f->auth = req->headers[0].value; f->url = req->url;
    snprintf(f->saved_auth, sizeof(f->saved_auth), "%s", f->auth);
    snprintf(f->saved_url, sizeof(f->saved_url), "%s", f->url);
    step *s = &f->steps[f->calls++];
    *res = (br_http_response){.status = s->status, .body = {(const unsigned char *)s->body, s->len ? s->len : s->body ? strlen(s->body) : 0}, .body_error = s->read};
    *error = s->cause ? strdup(s->cause) : NULL;
    if (s->fail_metadata) fail_add = 1;
    return s->rc;
}
static void release_fake(void *opaque, br_http_response *res)
{
    fake *f = opaque;
    CHECK(res);
    if (f->auth) {
        CHECK(f->url && !strcmp(f->auth, f->saved_auth) && !strcmp(f->url, f->saved_url));
    } else {
        /* Shared preparation can reject before the backend sees a request. */
        CHECK(!f->url && !res->status && !res->headers && !res->nheaders &&
              !res->body.data && !res->body.len && !res->body_error);
    }
    ++f->releases; f->auth = f->url = NULL;
}
static br_results run_bytes(const br_detector *d, const void *data, size_t len, bool verify, fake *f, const br_endpoints *eps)
{
    br_transport transport = {f, send_fake, release_fake};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "offline", .endpoints = eps};
    return test_scan(d, &ctx, verify, data, len);
}
static br_results run(const br_detector *d, const char *text, bool verify, fake *f, const br_endpoints *eps)
{
    return run_bytes(d, text, strlen(text), verify, f, eps);
}
static void member(br_json *map, const char *name, const void *value, size_t len)
{
    br_json *v = NULL;
    CHECK(json_object_object_get_ex(map, name, &v) && json_object_is_type(v, json_type_string));
    CHECK((size_t)json_object_get_string_len(v) == len && !memcmp(json_object_get_string(v), value, len));
}
static void base(const br_result *r, int version, const void *token, size_t len, const char *host)
{
    CHECK(r->detector_type == 9 && r->raw.len == len && !memcmp(r->raw.data, token, len));
    CHECK(r->raw_v2.len == len + strlen(host) && !memcmp(r->raw_v2.data, token, len));
    CHECK(!memcmp(r->raw_v2.data + len, host, strlen(host)));
    member(r->secret_parts, "key", token, len); member(r->secret_parts, "host", host, strlen(host));
    char ver = (char)('0' + version); member(r->extra_data, "version", &ver, 1);
    const char *guide = "https://howtorotate.com/docs/tutorials/gitlab/";
    member(r->extra_data, "rotation_guide", guide, strlen(guide));
    CHECK(!r->redacted && !r->detector_name && !r->primary_secret.data && !r->structured_data && !r->chunk_offset_set && !r->verification_from_cache);
}
static void grammars(const br_detector **d)
{
    fake f = {0}; char input[2048]; br_results r;
    for (size_t n = 19; n <= 23; ++n) {
        snprintf(input, sizeof(input), "GITLAB %.*s", (int)n, "Ab3dE5fGh7Jk9LmNoP2qRsT");
        r = run(d[0], input, false, &f, NULL); CHECK(r.len == (n >= 20 && n <= 22)); br_results_clear(&r);
        memcpy(input, "glpat-", 6); memset(input + 6, 'a', n); input[6 + n] = 0;
        r = run(d[1], input, false, &f, NULL); CHECK(r.len == (n >= 20 && n <= 22)); br_results_clear(&r);
    }
    const char *v1formats[] = {"gitlab glpat-: %s", "gitlab GLPAT-: %s", "%s", "gitlab %s_", "gitlab\n\r%s"};
    const size_t expected[] = {0,1,0,1,1};
    for (size_t i = 0; i < 5; ++i) {
        snprintf(input, sizeof(input), v1formats[i], key);
        r = run(d[0], input, false, &f, NULL); CHECK(r.len == expected[i]); br_results_clear(&r);
    }
    r = run(d[0], "gitlab aaaaaaaaaaaaaaaaaaaa", false, &f, NULL); CHECK(!r.len); br_results_clear(&r);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "gitlab", 6); memset(input + 6, '.', gap); memcpy(input + 6 + gap, key, sizeof(key));
        r = run(d[0], input, false, &f, NULL); CHECK(r.len == (gap == 40)); br_results_clear(&r);
    }
    r = run(d[1], "GLPAT-abcdefghijklmnopqrst", false, &f, NULL); CHECK(!r.len); br_results_clear(&r);
    r = run(d[1], "glpat-abcdefghijklmnopqrst=", false, &f, NULL); CHECK(r.len == 1 && r.items[0].raw.len == strlen(pat)); br_results_clear(&r);
    for (size_t n = 26; n <= 301; ++n) {
        if (n > 27 && n < 300) continue;
        memcpy(input, "glpat-", 6); memset(input + 6, 'A', n); strcpy(input + 6 + n, ".a2.abcdefgh9");
        r = run(d[2], input, false, &f, NULL); CHECK(r.len == (n == 27 || n == 300)); br_results_clear(&r);
    }
    const char *wild[] = {"\xf0\x9f\x98\x80", "\v", "\r", "", "\n"};
    for (size_t i = 0; i < 5; ++i) {
        size_t n = i == 0 ? 300 : 27, w = i == 3 ? 1 : strlen(wild[i]);
        memcpy(input, "glpat-", 6); memset(input + 6, 'A', n); size_t at = 6 + n;
        if (i == 3) input[at] = 0; else memcpy(input + at, wild[i], w);
        at += w; memcpy(input + at, "a2", 2); at += 2;
        if (i == 3) input[at] = 0; else memcpy(input + at, wild[i], w);
        at += w; memcpy(input + at, "abcdefgh9", 9); at += 9;
        r = run_bytes(d[2], input, at, false, &f, NULL); CHECK(r.len == (i != 4));
        if (r.len) { base(&r.items[0], 3, input, at, "https://gitlab.com"); if (!i) CHECK(at == 325); }
        br_results_clear(&r);
    }
    for (size_t i = 0; i < 3; ++i) {
        const char *text = i == 0 ? "gitlab Ab3dE5fGh7Jk9LmNoP2q" : i == 1 ? pat : modern;
        snprintf(input, sizeof(input), "%s %s", text, text);
        r = run(d[i], input, false, &f, NULL); CHECK(r.len == 2); br_results_clear(&r);
    }
    CHECK(!f.calls && !f.releases);
}
static void verification(const br_detector *d)
{
    const char *input = d->version == 1 ? "gitlab Ab3dE5fGh7Jk9LmNoP2q" : d->version == 2 ? pat : modern;
    const char *token = d->version == 1 ? key : input;
    const char *hosts[] = {"http://one.test:999999/path//", "https://two.test", "https://user@bad.test"};
    br_endpoints eps = {.configured = hosts, .nconfigured = 2, .use_cloud = true};
    fake f = {0};
    br_results r = run(d, input, false, &f, &eps); CHECK(r.len == 3);
    for (size_t i = 0; i < 3; ++i) base(&r.items[i], d->version, token, strlen(token), i < 2 ? hosts[i] : "https://gitlab.com");
    br_results_clear(&r);
    r = run(d, input, false, &f, &(br_endpoints){0}); CHECK(!r.len); br_results_clear(&r);
    r = run(d, input, true, &f, &(br_endpoints){0}); CHECK(!r.len && !f.calls); br_results_clear(&r);
    const char *bodies[] = {"{}", "null", "true", "[]", "\"x\"", "1e9999", "{\"n\":1e9999}", "{} trailing", "", "NaN", "01", "false true", "{", "[1,]"};
    for (size_t i = 0; i < 14; ++i) {
        f = (fake){.steps = {{.status = 200, .body = bodies[i]}}, .count = 1};
        r = run(d, input, true, &f, NULL); CHECK(r.len == 1 && r.items[0].verified == (i < 7));
        CHECK(!r.items[0].verification_error && f.calls == 1 && f.releases == 1);
        CHECK(!strcmp(f.saved_auth + 7, token) && !strcmp(f.saved_url, "https://gitlab.com/api/v4/user")); br_results_clear(&r);
    }
    const int statuses[] = {200, 403, 401, 500};
    for (size_t i = 0; i < 4; ++i) {
        f = (fake){.steps = {{.status = statuses[i], .body = "{}", .read = ""}}, .count = 1};
        r = run(d, input, true, &f, NULL); CHECK(!r.items[0].verified && r.items[0].verification_error && !*r.items[0].verification_error); br_results_clear(&r);
    }
    static const char blocked[] = "x\0" "403 Forbidden - Your account has been blocked";
    f = (fake){.steps = {{.status = 403, .body = blocked, .len = sizeof(blocked) - 1}}, .count = 1};
    r = run(d, input, true, &f, NULL); CHECK(r.items[0].verified); member(r.items[0].extra_data, "blocked", "True", 4); br_results_clear(&r);
    f = (fake){.steps = {{.status = 403, .body = "forbidden"}}, .count = 1};
    r = run(d, input, true, &f, NULL); CHECK(r.items[0].verified && json_object_object_length(r.items[0].extra_data) == 2); br_results_clear(&r);
    char cause[500]; snprintf(cause, sizeof(cause), "invalid header: %s canceled timeout", token);
    f = (fake){.steps = {{.status = 403, .body = "{}", .read = cause}}, .count = 1};
    r = run(d, input, true, &f, NULL); CHECK(!r.items[0].verified && !strcmp(r.items[0].verification_error, cause)); br_results_clear(&r);
    f = (fake){.steps = {{.rc = 1, .cause = cause}, {.status = 401}, {.status = 503}}, .count = 3};
    r = run(d, input, true, &f, &eps); CHECK(r.len == 3 && f.calls == 3 && f.releases == 3);
    CHECK(!strcmp(r.items[0].verification_error, cause) && !r.items[1].verification_error);
    CHECK(!strcmp(r.items[2].verification_error, "unexpected HTTP response status 503")); br_results_clear(&r);
    char repeated[256]; snprintf(repeated, sizeof(repeated), "%s %s", input, input);
    f = (fake){.steps = {{.status = 403}, {.status = 403}}, .count = 2};
    r = run(d, repeated, true, &f, &eps); CHECK(r.len == 2 && f.calls == 2 && f.releases == 2); br_results_clear(&r);
    char long_host[6000]; memcpy(long_host, "https://long.test/", 18); memset(long_host + 18, 'a', sizeof(long_host) - 19); long_host[sizeof(long_host) - 1] = 0;
    const char *long_list[] = {long_host}; br_endpoints long_eps = {.configured = long_list, .nconfigured = 1};
    f = (fake){.steps = {{.status = 401}}, .count = 1};
    r = run(d, input, true, &f, &long_eps); CHECK(r.len == 1 && strlen(f.saved_url) == strlen(long_host) + strlen("/api/v4/user")); br_results_clear(&r);
    eps.nconfigured = 3; eps.use_cloud = false;
    f = (fake){.steps = {{.status = 401}, {.status = 403}}, .count = 2};
    r = run(d, input, true, &f, &eps); CHECK(r.len == 2 && r.items[1].verified && f.calls == 2); br_results_clear(&r);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(r.len == 1 && !r.items[0].verified && !strcmp(r.items[0].verification_error, "net/http: nil Context")); br_results_clear(&r);
    f = (fake){0}; r = run(d, input, false, &f, &eps); CHECK(r.len == 3 && !f.calls); br_results_clear(&r);
    br_transport tr = {&f, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &tr, .user_agent = "offline", .endpoints = &eps};
    f = (fake){.steps = {{.status = 401}, {.status = 401}}, .count = 2};
    br_result seed = {.detector_type = 123}; CHECK(!br_results_push(&r, &seed)); char *error = NULL;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
    CHECK(error && strstr(error, "unsupported") && r.len == 1 && r.items[0].detector_type == 123 && f.calls == f.releases); free(error); br_results_clear(&r);
    ctx.endpoints = NULL;
    f = (fake){.steps = {{.status = 403, .body = blocked, .len = sizeof(blocked) - 1, .fail_metadata = true}}, .count = 1}; error = NULL;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
    CHECK(error && !r.len && f.calls == 1 && f.releases == 1); free(error); br_results_clear(&r);
#ifdef BR_GITLAB_FAULTS
    for (int i = 1; i <= 5; ++i) {
        f = (fake){.steps = {{.status = i == 3 ? 500 : 200, .body = "{}"}}, .count = 1};
        error = NULL; seed = (br_result){.detector_type = 123}; CHECK(!br_results_push(&r, &seed)); fault = i;
        fail_malloc_size = strlen("https://gitlab.com") + sizeof("/api/v4/user");
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
        CHECK(!fault && error && r.len == 1 && r.items[0].detector_type == 123 && f.calls == f.releases);
        free(error); br_results_clear(&r);
    }
    for (size_t i = 0; i < 2; ++i) {
        fault = i ? 5 : 1; fail_malloc_size = strlen("https://gitlab.com") + sizeof("/api/v4/user");
        error = NULL;
        CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
        CHECK(!fault && error && !r.len); free(error); br_results_clear(&r);
    }
#endif
}
int main(void)
{
    const br_detector *d[3]; char *error = NULL;
    CHECK(!br_gitlab_v1_init(&d[0], &error) && !error);
    CHECK(!br_gitlab_v2_init(&d[1], &error) && !error);
    CHECK(!br_gitlab_v3_init(&d[2], &error) && !error);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(d[i]->type == 9 && d[i]->version == (int)i + 1 && !strcmp(d[i]->name, "Gitlab"));
        CHECK(d[i]->nkeywords == 1 && !strcmp(d[i]->keywords[0], i ? "glpat-" : "gitlab"));
        CHECK(d[i]->max_secret_size == -1 && d[i]->start_offset == -1 && d[i]->max_credential_span == -1 && !d[i]->clean && !d[i]->false_positive);
        CHECK(!strcmp(d[i]->cloud_endpoint, "https://gitlab.com"));
        CHECK(d[i]->validate_endpoints(&(br_endpoints){0}, &error) != 0 && error); free(error); error = NULL;
        const char *empty[] = {""}; CHECK(!d[i]->validate_endpoints(&(br_endpoints){.configured = empty, .nconfigured = 1}, &error) && !error);
    }
    grammars(d); for (size_t i = 0; i < 3; ++i) verification(d[i]);
    char binary[100]; memcpy(binary, modern, sizeof(modern)); binary[33] = 0;
    fake f = {0}; br_results r = run_bytes(d[2], binary, strlen(modern), false, &f, NULL); CHECK(r.len == 1); br_results_clear(&r);
    br_transport tr = {&f, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &tr};
    CHECK(d[2]->scan(d[2], &ctx, true, (br_slice){(const unsigned char *)binary, strlen(modern)}, &r, &error) != 0);
    CHECK(error && strstr(error, "binary Authorization") && !f.calls && !r.len); free(error); br_results_clear(&r);
    r = test_scan(d[2], NULL, true, binary, strlen(modern)); CHECK(r.len == 1 && r.items[0].verification_error && !strcmp(r.items[0].verification_error, "net/http: nil Context")); br_results_clear(&r);
    binary[33] = '\v'; r = run_bytes(d[2], binary, strlen(modern), true, &f, NULL);
    CHECK(r.len == 1 && !r.items[0].verified && r.items[0].verification_error && !strcmp(r.items[0].verification_error, "invalid HTTP header"));
    CHECK(!f.calls && f.releases == 1); br_results_clear(&r);
    return test_finish("gitlab v1/v2/v3");
}
