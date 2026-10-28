/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static const char hex[] = "0123456789abcdef0123456789abcdef01234567";
static const char token[] = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static size_t fail_add;
int json_object_object_add(struct json_object *map, const char *name, struct json_object *value)
{
    if (fail_add && !--fail_add) return -1;
    return json_object_object_add_ex(map, name, value, 0);
}
typedef struct {
    int status, rc;
    const char *body, *cause, *read_error;
    const br_header *headers;
    size_t nheaders;
    bool fail_projection;
} step;
typedef struct {
    step steps[4];
    size_t count, calls, releases;
    const char *url, *auth;
} fake;
static int send_fake(void *opaque, const br_scan_ctx *ctx, const br_http_request *request,
                     br_http_response *response, char **error)
{
    fake *f = opaque;
    CHECK(f->calls < f->count && ctx);
    CHECK(!strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 8 && !request->dedup_key.len && !request->body.data && !request->body.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json; charset=utf-8"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "token ", 6));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog offline"));
    f->url = request->url; f->auth = request->headers[1].value;
    const step *s = &f->steps[f->calls++];
    *response = (br_http_response){.status = s->status, .headers = s->headers, .nheaders = s->nheaders,
        .body = {(const unsigned char *)s->body, s->body ? strlen(s->body) : 0}, .body_error = s->read_error};
    *error = s->cause ? strdup(s->cause) : NULL;
    if (s->fail_projection) fail_add = 1;
    return s->rc;
}
static void release_fake(void *opaque, br_http_response *response)
{
    fake *f = opaque;
    CHECK(response && f->url && strstr(f->url, "/user"));
    CHECK(f->auth && !strncmp(f->auth, "token ", 6));
    f->url = f->auth = NULL; ++f->releases;
}
static br_results run(const br_detector *d, const char *input, bool verify, fake *f, const br_endpoints *endpoints)
{
    br_transport transport = {f, send_fake, release_fake};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "offline", .endpoints = endpoints};
    return test_scan(d, &ctx, verify, input, strlen(input));
}
static br_json *field(const br_result *r, const char *name)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(r->extra_data, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    return value;
}
static void text(const br_result *r, const char *name, const char *expected)
{
    CHECK(!strcmp(json_object_get_string(field(r, name)), expected));
}
static void base(const br_result *r, int version, const char *key)
{
    CHECK(r->detector_type == 8 && r->raw.len == strlen(key) && !memcmp(r->raw.data, key, strlen(key)));
    CHECK(!r->raw_v2.data && !r->redacted && !r->structured_data && !r->primary_secret.data && !r->chunk_offset_set);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
    text(r, "version", version == 1 ? "1" : "2");
    text(r, "rotation_guide", "https://howtorotate.com/docs/tutorials/github/");
    if (version == 2) CHECK(field(r, "token_type"));
}
static void extraction(const br_detector *v1, const br_detector *v2)
{
    const char *prefixes[] = {"github_token", "github_secret", "github_key", "github_api", "github_pat",
        "githubtoken", "githubsecret", "githubkey", "githubapi", "githubpat", "gh_token", "gh_secret",
        "gh_key", "gh_api", "gh_pat", "ghtoken", "ghsecret", "ghkey", "ghapi", "ghpat"};
    char input[1024]; fake f = {0};
    for (size_t i = 0; i < 20; ++i) {
        snprintf(input, sizeof(input), "%s %s", prefixes[i], hex);
        br_results r = run(v1, input, false, &f, NULL);
        CHECK(r.len == 1); base(&r.items[0], 1, hex); br_results_clear(&r);
    }
    const char *formats[] = {"GITHUB_TOKEN %s", "github_token actions/%s", "github_token ACTIONS/%s",
        "github_token github.com/%s", "github_token sha256:%s", "%s", "github_token %s_"};
    const size_t counts[] = {1, 0, 1, 0, 0, 0, 0};
    for (size_t i = 0; i < 7; ++i) {
        snprintf(input, sizeof(input), formats[i], hex);
        br_results r = run(v1, input, true, &f, &(br_endpoints){0});
        CHECK(r.len == counts[i]); br_results_clear(&r);
    }
    br_results r = run(v1, "github_token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true, &f, NULL);
    CHECK(!r.len); br_results_clear(&r);
    r = run(v1, "github_token ABCDEF0123456789ABCDEF0123456789ABCDEF01", false, &f, NULL);
    CHECK(!r.len); br_results_clear(&r);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "gh_key", 6); memset(input + 6, '.', gap); memcpy(input + 6 + gap, hex, sizeof(hex));
        r = run(v1, input, false, &f, NULL); CHECK(r.len == (gap == 40)); br_results_clear(&r);
    }
    snprintf(input, sizeof(input), "github_token %s\ngithub_token %s", hex, hex);
    r = run(v1, input, false, &f, NULL); CHECK(r.len == 2); br_results_clear(&r);
    const char *types[] = {"Personal Access Token (classic)", "OAuth Access Token", "GitHub App User-to-Server Token",
        "GitHub App Server-to-Server (installation) Token", "GitHub App Refresh Token", "Personal Access Token (fine-grained)"};
    for (size_t i = 0; i < 6; ++i) {
        snprintf(input, sizeof(input), "%sABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", v2->keywords[i]);
        r = run(v2, input, false, &f, NULL); CHECK(r.len == 1); base(&r.items[0], 2, input);
        text(&r.items[0], "token_type", types[i]); br_results_clear(&r);
    }
    for (size_t n = 35; n <= 256; ++n) {
        if (n > 36 && n < 255) continue;
        memcpy(input, "ghp_", 4); memset(input + 4, 'a', n); input[4 + n] = 0;
        r = run(v2, input, false, &f, NULL); CHECK(r.len == (n == 36 || n == 255)); br_results_clear(&r);
    }
    r = run(v2, "GHP_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", false, &f, NULL); CHECK(!r.len); br_results_clear(&r);
    snprintf(input, sizeof(input), "%s %s", token, token);
    r = run(v2, input, false, &f, NULL); CHECK(r.len == 2); br_results_clear(&r);
    CHECK(!f.calls && !f.releases);
}
static void verification(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), d->version == 1 ? "github_token %s" : "%s", d->version == 1 ? hex : token);
    const char *endpoints[] = {"http://one.test:999999/path//", "https://two.test", "https://three.test"};
    br_endpoints settings = {.configured = endpoints, .nconfigured = 3};
    const char *bodies[] = {"{}", "null", "{\"login\":\"first\",\"login\":null}",
        "{\"login\":\"first\",\"LOGIN\":\"last\",\"type\":\"User\",\"name\":\"N\",\"company\":\"C\",\"html_url\":\"U\",\"email\":\"E\",\"location\":\"L\",\"ldap_dn\":\"D\",\"site_admin\":true}",
        "{\"unknown\":1e9999999}", "{\"login\":\"a\\u0000b\\u263a\"} trailing"};
    for (size_t i = 0; i < 6; ++i) {
        fake f = {.steps = {{.status = 299, .body = bodies[i], .read_error = i == 1 ? NULL : "late read failure"}}, .count = 1};
        br_results r = run(d, input, true, &f, NULL);
        CHECK(r.len == 1 && r.items[0].verified && !r.items[0].verification_error && f.calls == 1 && f.releases == 1);
        base(&r.items[0], d->version, d->version == 1 ? hex : token);
        CHECK(field(&r.items[0], "username") && field(&r.items[0], "url") && field(&r.items[0], "account_type"));
        if (i == 2) text(&r.items[0], "username", "first");
        if (i == 3) { text(&r.items[0], "username", "last"); text(&r.items[0], "site_admin", "true"); text(&r.items[0], "ldap_dn", "D"); }
        if (i == 5) CHECK(json_object_get_string_len(field(&r.items[0], "username")) == 6);
        br_results_clear(&r);
    }
    fake f = {.steps = {{.rc = -1, .cause = "first"}, {.status = 200, .body = "{\"login\":3,\"login\":\"ok\"}"}, {.status = 401}}, .count = 3};
    br_results r = run(d, input, true, &f, &settings);
    CHECK(r.len == 1 && !r.items[0].verified && !r.items[0].verification_error && f.calls == 3 && f.releases == 3); br_results_clear(&r);
    char cause[512]; snprintf(cause, sizeof(cause), "last %s twice %s", d->version == 1 ? hex : token, d->version == 1 ? hex : token);
    f = (fake){.steps = {{.status = 200, .body = "{\"site_admin\":\"true\"}"}, {.status = 200, .body = "{"}, {.rc = -1, .cause = cause}}, .count = 3};
    r = run(d, input, true, &f, &settings);
    CHECK(!r.items[0].verified && !strcmp(r.items[0].verification_error, "last [REDACTED] twice [REDACTED]")); br_results_clear(&r);
    br_header headers[] = {{"x-oauth-scopes", ""}, {"X-OAuth-Scopes", "ignored"}, {"GITHUB-AUTHENTICATION-TOKEN-EXPIRATION", "tomorrow"}};
    f = (fake){.steps = {{.status = 200, .body = "{}", .headers = headers, .nheaders = 3}}, .count = 1};
    r = run(d, input, true, &f, NULL); CHECK(r.items[0].verified);
    CHECK(!json_object_object_get_ex(r.items[0].extra_data, "scopes", NULL)); text(&r.items[0], "expiry", "tomorrow"); br_results_clear(&r);
    f = (fake){0}; r = run(d, input, true, &f, &(br_endpoints){0}); CHECK(r.len == 1 && !r.items[0].verified && !f.calls); br_results_clear(&r);
    r = test_scan(d, NULL, true, input, strlen(input)); CHECK(r.len == 1 && !r.items[0].verified); br_results_clear(&r);
    const char *bad[] = {"https://one.test", "https://user@two.test"};
    settings = (br_endpoints){.configured = bad, .nconfigured = 2};
    f = (fake){.steps = {{.status = 200, .body = "{}"}}, .count = 1};
    r = run(d, input, true, &f, &settings); CHECK(r.items[0].verified && f.calls == 1); br_results_clear(&r);
    f = (fake){.steps = {{.status = 401}}, .count = 1};
    br_transport transport = {&f, send_fake, release_fake}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "offline", .endpoints = &settings};
    char *error = NULL; br_result seed = {.detector_type = 123}; CHECK(!br_results_push(&r, &seed));
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
    CHECK(error && strstr(error, "unsupported") && r.len == 1 && r.items[0].detector_type == 123 && f.calls == 1 && f.releases == 1); free(error); br_results_clear(&r);
    settings.configured = bad + 1; settings.nconfigured = 1; f = (fake){0}; error = NULL;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
    CHECK(error && !f.calls && !r.len); free(error);
    r = run(d, input, false, &f, &settings); CHECK(r.len == 1 && !f.calls); br_results_clear(&r);
    settings = (br_endpoints){0}; f = (fake){.steps = {{.status = 200, .body = "{}", .fail_projection = true}}, .count = 1};
    ctx.endpoints = NULL; error = NULL;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
    CHECK(error && !r.len && f.calls == 1 && f.releases == 1); free(error); br_results_clear(&r);
}
int main(void)
{
    const br_detector *v1 = NULL, *v2 = NULL; char *error = NULL;
    CHECK(!br_github_v1_init(&v1, &error) && !error);
    CHECK(!br_github_v2_init(&v2, &error) && !error);
    CHECK(v1->type == 8 && v2->type == 8 && v1->version == 1 && v2->version == 2);
    CHECK(!strcmp(v1->name, "Github") && strcmp(v1->description, v2->description));
    CHECK(v1->nkeywords == 2 && v2->nkeywords == 6 && !strcmp(v1->cloud_endpoint, "https://api.github.com"));
    CHECK(v1->max_secret_size == -1 && v1->start_offset == -1 && v1->max_credential_span == -1 && !v1->clean && !v1->false_positive);
    br_endpoints zero = {0}; CHECK(v1->validate_endpoints(&zero, &error) != 0 && error); free(error); error = NULL;
    const char *empty[] = {""}; br_endpoints setter = {.configured = empty, .nconfigured = 1}; CHECK(!v2->validate_endpoints(&setter, &error) && !error);
    extraction(v1, v2); verification(v1); verification(v2);
    return test_finish("github v1/v2");
}
