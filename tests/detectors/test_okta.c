/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_okta_init(const br_detector **out, char **error);

static size_t module_fail_after, module_calls, dup_fail_after, module_dups;
static size_t arm_after_domain, arm_module_failure, map_fail_after, pair_fail_after;
static size_t capture_calls, capture_fail_call, compile_calls, compile_fail_call;
static size_t setter_calls, null_setters, setter_fail_after, push_fail_after, searches;
static bool in_real_setter, fail_real_setter_copy;
static br_result *active_result;
static br_slice active_token, active_domain;
static const br_detector *detector;

char *strdup(const char *text)
{
    if (in_real_setter && fail_real_setter_copy) { fail_real_setter_copy = false; return NULL; }
    size_t n = strlen(text) + 1; char *copy = malloc(n);
    if (copy) memcpy(copy, text, n);
    return copy;
}
static void *module_malloc(size_t n)
{
    ++module_calls;
    if (module_fail_after && !--module_fail_after) return NULL;
    return malloc(n);
}
static char *module_strdup(const char *text)
{
    ++module_dups;
    if (dup_fail_after && !--dup_fail_after) return NULL;
    return strdup(text);
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "domain") && map_fail_after && !--map_fail_after) return 7;
    int rc = json_object_object_add_ex(object, name, value, 0);
    /* Existing post-metadata seam: only provider allocations are counted, never
     * opaque regex/shared allocations or a guessed allocation size. */
    if (!rc && !strcmp(name, "domain") && arm_after_domain && !--arm_after_domain)
        module_fail_after = arm_module_failure;
    return rc;
}
#define br_result_set_verification_error okta_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
static int compile_regex(const char *pattern, br_regex **out, char **error)
{
    ++compile_calls;
    if (compile_fail_call && compile_calls == compile_fail_call) { *out = NULL; if (error) *error = strdup("owned compile +1"); return 1; }
    return br_regex_compile(pattern, out, error);
}
static int capture_regex(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    ++capture_calls; CHECK(unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (capture_fail_call && capture_calls == capture_fail_call) { if (error && !*error) *error = strdup("owned capture +1"); return 1; }
    return rc;
}
static int finding_pair(br_result *result, int32_t type, br_slice token, const char *token_name,
                         br_slice domain, const char *domain_name, br_slice separator)
{
    active_result = result; active_token = token; active_domain = domain;
    int rc = br_finding_pair_bytes(result, type, token, token_name, domain, domain_name, separator);
    if (pair_fail_after && !--pair_fail_after) return 1;
    return rc;
}
static int push_result(br_results *out, br_result *result)
{
    return push_fail_after && !--push_fail_after ? 1 : br_results_push(out, result);
}
static size_t find_bytes(br_slice input, br_slice needle, size_t start)
{
    ++searches; return br_slice_find(input, needle, start);
}
#define malloc module_malloc
#define strdup module_strdup
#define br_regex_compile compile_regex
#define br_captures_find capture_regex
#define br_finding_pair_bytes finding_pair
#define br_results_push push_result
#define br_slice_find find_bytes
#include "../../src/detectors/okta.c"
#undef br_slice_find
#undef br_results_push
#undef br_finding_pair_bytes
#undef br_captures_find
#undef br_regex_compile
#undef strdup
#undef malloc

typedef struct {
    test_http http; br_transport transport; br_scan_ctx ctx;
    size_t count, setters, release_len[4], release_setters[4], release_calls[4];
    const char *tokens[4], *domains[4], *auth[4], *urls[4], *causes[4], *expected_errors[4];
    int statuses[4], send_rc[4]; bool verified[4];
    br_slice bodies[4]; const char *body_errors[4]; br_header markers[4];
    bool poison, observable_release; size_t arm_dup_at_send;
    br_results *out;
} script;
static script *running;
static char token[43], other[43];
static const char domain1[] = "alpha.okta.com", domain2[] = "beta.oktapreview.com";
static const unsigned char marker[] = "{\"activated\":false}";

int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls; if (!cause) ++null_setters;
    CHECK(result == active_result && !secrets && !count);
    if (running) {
        size_t i = running->setters++;
        /* Preparation failures release once without reaching the backend. */
        CHECK(i < running->count && running->http.releases == (running->observable_release ? i + 1 : 0));
        CHECK(result->verified == running->verified[i]);
        CHECK((cause == NULL) == (running->expected_errors[i] == NULL));
        if (cause) CHECK(!strcmp(cause, running->expected_errors[i]));
    }
    in_real_setter = true;
    int rc = okta_real_setter(result, cause, secrets, count);
    in_real_setter = false;
    if (setter_fail_after && !--setter_fail_after) return 1;
    return rc;
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t i = http->calls - 1; char url[160];
    CHECK(ctx == &s->ctx && i < s->count && i < 4 && active_result && !active_result->verified && !active_result->verification_error);
    snprintf(url, sizeof(url), "https://%s/api/v1/users/me", s->domains[i]);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 21);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization") && !memcmp(request->headers[2].value, "SSWS ", 5));
    CHECK(strlen(request->headers[2].value) == 47 && !strcmp(request->headers[2].value + 5, s->tokens[i]));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog okta-offline"));
    s->auth[i] = request->headers[2].value; s->urls[i] = request->url; /* Original values only. */
    s->markers[i] = (br_header){"synthetic-attempt", s->domains[i]};
    http->response = (br_http_response){.status = s->statuses[i], .headers = &s->markers[i], .nheaders = 1,
        .body = s->bodies[i], .body_error = s->body_errors[i]};
    http->send_rc = s->send_rc[i]; http->send_error = s->causes[i];
    if (s->arm_dup_at_send && http->calls == s->arm_dup_at_send) dup_fail_after = 1;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; size_t i = http->releases;
    CHECK(i < 4 && s->out && active_result && !active_result->verified && !active_result->verification_error);
    if (response->headers) {
        CHECK(i < s->count && response->headers == &s->markers[i]);
        CHECK(!strcmp(s->auth[i] + 5, s->tokens[i]));
        char url[160]; snprintf(url, sizeof(url), "https://%s/api/v1/users/me", s->domains[i]); CHECK(!strcmp(s->urls[i], url));
        CHECK(active_token.len == 42 && !memcmp(active_token.data, s->tokens[i], 42));
        CHECK(active_domain.len == strlen(s->domains[i]) && !memcmp(active_domain.data, s->domains[i], active_domain.len));
        if (s->poison && response->body.len) memset((void *)response->body.data, 'x', response->body.len);
    } else CHECK(!response->status && !response->body.data && !response->body_error);
    s->release_len[i] = s->out->len; s->release_setters[i] = s->setters; s->release_calls[i] = http->calls;
    test_http_release(user, response);
}
static void setup(script *s, size_t count)
{
    *s = (script){.count = count};
    for (size_t i = 0; i < count; ++i) {
        s->tokens[i] = token; s->domains[i] = domain1; s->statuses[i] = 200; s->verified[i] = true;
        s->bodies[i] = (br_slice){marker, sizeof(marker) - 1}; s->body_errors[i] = "discarded read error";
    }
    s->http = (test_http){.inspect = inspect_request, .user = s}; s->transport = (br_transport){&s->http, test_http_send, release_response};
    s->ctx = (br_scan_ctx){.transport = &s->transport, .user_agent = "okta-offline"};
}
static int invoke(script *s, const br_scan_ctx *ctx, bool verify, br_slice input, br_results *out, char **error)
{
    capture_calls = 0; active_result = NULL; s->out = out; running = verify ? s : NULL;
    s->observable_release = ctx && ctx->transport == &s->transport;
    int rc = detector->scan(detector, ctx, verify, input, out, error);
    running = NULL; s->out = NULL; active_result = NULL; return rc;
}
static void fields(const br_result *r, const char *tok, const char *domain, bool verified, const char *cause)
{
    CHECK(r->detector_type == 21 && !r->detector_name && r->verified == verified);
    CHECK(r->raw.len == 42 && !memcmp(r->raw.data, tok, 42));
    size_t n = strlen(domain); CHECK(r->raw_v2.len == n + 43 && !memcmp(r->raw_v2.data, domain, n) && r->raw_v2.data[n] == ':' && !memcmp(r->raw_v2.data + n + 1, tok, 42));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "token", &part) && !strcmp(json_object_get_string(part), tok));
    CHECK(json_object_object_get_ex(r->secret_parts, "domain", &part) && !strcmp(json_object_get_string(part), domain));
    CHECK(!r->redacted && !r->extra_data && !r->structured_data && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK((r->verification_error == NULL) == (cause == NULL)); if (cause) CHECK(!strcmp(r->verification_error, cause));
}
static void extract(const void *input, size_t len, const char *tok, const char *domain, size_t count)
{
    script s; setup(&s, 0); br_results out = {0}; char *error = NULL; size_t before = setter_calls;
    CHECK(invoke(&s, NULL, false, (br_slice){input, len}, &out, &error) == 0 && !error && out.len == count && capture_calls == 2);
    CHECK(!s.http.calls && !s.http.releases && setter_calls == before);
    for (size_t i = 0; i < count; ++i) fields(&out.items[i], tok, domain, false, NULL);
    br_results_clear(&out);
}
static void extraction(void)
{
    char *error = NULL; const br_detector *again = NULL;
    compile_fail_call = 1; CHECK(br_okta_init(&again, &error) != 0 && !again && error); free(error); compile_calls = 0;
    compile_fail_call = 2; CHECK(br_okta_init(&again, &error) != 0 && !again && error); free(error); compile_fail_call = 0;
    CHECK(br_okta_init(&detector, &error) == 0 && detector && !error); CHECK(br_okta_init(&again, NULL) == 0 && again == detector);
    CHECK(br_okta_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(BR_ABI_REVISION == 1 && detector->type == 21 && detector->version == 0 && !strcmp(detector->name, "Okta") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Okta is an identity and access management service. Okta tokens can be used to authenticate and access various resources and APIs within an organization."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], ".okta") && detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(!detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    test_secret(token, 42, 0); test_secret(other, 42, 8); token[0] = token[1] = other[0] = other[1] = '0'; token[10] = '-'; token[20] = '_'; token[41] = 'Z'; other[41] = 'Q';
    char input[4096], changed[50], label[45];
    const char *good[] = {"a.okta.com", "tenant.oktapreview.com", "org.okta-emea.com", "a-b9.okta.com", "Z-alpha.okta.com", "a.okta.com-tail"};
    const char *expected[] = {"a.okta.com", "tenant.oktapreview.com", "org.okta-emea.com", "a-b9.okta.com", "-alpha.okta.com", "a.okta.com"};
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); ++i) { int n = snprintf(input, sizeof(input), "%s\n%s", token, good[i]); extract(input, (size_t)n, token, expected[i], 1); }
    const char *bad[] = {".okta.com", "Alpha.okta.com", "a.OKTA.com", "a.okta.COM", "a.oktaemea.com", "a.oktapreview-emea.com", "_alpha.okta.com", "a.okta.comX"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) { int n = snprintf(input, sizeof(input), "%s %s", token, bad[i]); extract(input, (size_t)n, NULL, NULL, 0); }
    for (size_t n = 40; n <= 41; ++n) { memset(label, 'a', n); label[n] = 0; char domain[80]; snprintf(domain, sizeof(domain), "%s.okta.com", label); int m = snprintf(input, sizeof(input), "%s %s", token, domain); extract(input, (size_t)m, token, domain, n == 40 ? 1 : 0); }
    const char *formats[] = {"_%s %s", "%sA %s", "X%s %s"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) { int n = snprintf(input, sizeof(input), formats[i], token, domain1); extract(input, (size_t)n, NULL, NULL, 0); }
    memcpy(changed, token, sizeof(token)); changed[41] = 0; int n = snprintf(input, sizeof(input), "%s %s", changed, domain1); extract(input, (size_t)n, NULL, NULL, 0);
    memcpy(changed, token, sizeof(token)); changed[0] = 'O'; n = snprintf(input, sizeof(input), "%s %s", changed, domain1); extract(input, (size_t)n, NULL, NULL, 0);
    memcpy(changed, token, sizeof(token)); changed[41] = '-';
    n = snprintf(input, sizeof(input), "%s %s", domain1, changed); extract(input, (size_t)n, NULL, NULL, 0); /* '-' at EOF has no boundary. */
    n = snprintf(input, sizeof(input), "%sX %s", changed, domain1); extract(input, (size_t)n, changed, domain1, 1);
    n = snprintf(input, sizeof(input), "%s\n%s", domain1, token); extract(input, (size_t)n, token, domain1, 1); /* No keyword prefix. */
    extract(token, 42, NULL, NULL, 0); extract(domain1, strlen(domain1), NULL, NULL, 0);
    memcpy(input, token, 42); memset(input + 42, ' ', 3000); memcpy(input + 3042, domain1, strlen(domain1)); extract(input, 3042 + strlen(domain1), token, domain1, 1);
    n = snprintf(input, sizeof(input), "%s %s", token, domain1); input[25] = 0; extract(input, (size_t)n, NULL, NULL, 0);
    n = snprintf(input, sizeof(input), "%s %s %s %s", token, token, domain1, domain1); extract(input, (size_t)n, token, domain1, 1);
    n = snprintf(input, sizeof(input), "%s %s %s %s", token, other, domain1, domain2);
    script s; setup(&s, 4); br_results out = {0}; size_t before = setter_calls;
    CHECK(invoke(&s, NULL, false, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 4 && setter_calls == before);
    /* First occurrence is a permitted deterministic unique enumeration, not a Go-map order promise. */
    for (size_t i = 0; i < 4; ++i) fields(&out.items[i], i < 2 ? token : other, i % 2 ? domain2 : domain1, false, NULL);
    br_results_clear(&out);
}
static void policy(void)
{
    static const unsigned char binary[] = {0xff, 0, '"','a','c','t','i','v','a','t','e','d','"',':',0xff};
    struct body_case { const unsigned char *data; size_t len; bool verified; } cases[] = {
        {marker, sizeof(marker) - 1, true}, {binary, sizeof(binary), true},
        {(const unsigned char *)"junk\"activated\":", 16, true},
        {(const unsigned char *)"\"activated\" :true", 17, false},
        {(const unsigned char *)"\"Activated\":true", 16, false}, {NULL, 0, false},
    };
    char input[300]; int n = snprintf(input, sizeof(input), "%s %s", token, domain1); script s; char *error = NULL;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        setup(&s, 1); s.bodies[0] = (br_slice){cases[i].data, cases[i].len}; s.verified[0] = cases[i].verified;
        br_results out = {0}; searches = 0;
        CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1 && searches == 1);
        fields(&out.items[0], token, domain1, cases[i].verified, NULL);
        CHECK(s.http.calls == 1 && s.http.releases == 1 && s.setters == 1 && !s.release_len[0] && !s.release_setters[0]); br_results_clear(&out);
    }
    unsigned char mutable[40]; memcpy(mutable, marker, sizeof(marker)); setup(&s, 1); s.poison = true; s.bodies[0] = (br_slice){mutable, sizeof(marker) - 1};
    br_results out = {0}; CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && out.len == 1); fields(&out.items[0], token, domain1, true, NULL); br_results_clear(&out);
    const int statuses[] = {401, 201, 403, 199, 0, -1, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected status code: %d", statuses[i]);
        setup(&s, 1); s.statuses[0] = statuses[i]; s.verified[0] = false; s.expected_errors[0] = statuses[i] == 401 ? NULL : cause; searches = 0;
        CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1 && !searches);
        fields(&out.items[0], token, domain1, false, s.expected_errors[0]); br_results_clear(&out);
    }
    char echo[250]; snprintf(echo, sizeof(echo), "unsupported: echo %s and %s", token, domain1);
    const char *causes[] = {echo, "out of memory in shared preparation", NULL};
    for (size_t i = 0; i < 3; ++i) {
        setup(&s, 1); s.send_rc[0] = i % 2 ? -1 : 7; s.causes[0] = causes[i]; s.expected_errors[0] = causes[i] ? causes[i] : "HTTP transport failed"; s.verified[0] = false;
        CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1);
        fields(&out.items[0], token, domain1, false, s.expected_errors[0]); br_results_clear(&out);
    }
    setup(&s, 1); s.verified[0] = false; s.expected_errors[0] = "net/http: nil Context"; size_t before = module_calls;
    CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1 && module_calls == before + 1);
    CHECK(!s.http.calls && !s.http.releases && s.setters == 1); fields(&out.items[0], token, domain1, false, s.expected_errors[0]); br_results_clear(&out);
    setup(&s, 1); s.ctx.user_agent = "bad\r\nagent"; s.verified[0] = false; s.expected_errors[0] = "invalid HTTP user agent";
    CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 1 && !s.http.calls && s.http.releases == 1);
    fields(&out.items[0], token, domain1, false, s.expected_errors[0]); br_results_clear(&out);
    n = snprintf(input, sizeof(input), "%s %s %s %s", token, other, domain1, domain2); setup(&s, 4);
    for (size_t i = 0; i < 4; ++i) { s.tokens[i] = i < 2 ? token : other; s.domains[i] = i % 2 ? domain2 : domain1; }
    CHECK(invoke(&s, &s.ctx, true, (br_slice){(const unsigned char *)input, (size_t)n}, &out, &error) == 0 && !error && out.len == 4 && s.http.calls == 4 && s.http.releases == 4 && s.setters == 4);
    for (size_t i = 0; i < 4; ++i) { CHECK(s.release_len[i] == i && s.release_setters[i] == i && s.release_calls[i] == i + 1); fields(&out.items[i], s.tokens[i], s.domains[i], true, NULL); }
    br_results_clear(&out); CHECK(null_setters > 0);
}
static void fatal(script *s, const br_scan_ctx *ctx, bool verify, const char *input, br_results *out, const br_result *saved)
{
    char *error = NULL;
    CHECK(invoke(s, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, out, &error) != 0 && error);
    CHECK(out->len == 1 && !memcmp(&out->items[0], saved, sizeof(*saved))); free(error);
}
static void failures(void)
{
    char input[400]; snprintf(input, sizeof(input), "%s %s", token, domain1);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 19, "caller-owned", "key") == 0); prior.verification_error = strdup("caller diagnostic"); prior.extra_data = json_object_new_object(); CHECK(br_results_push(&out, &prior) == 0);
    br_result saved = out.items[0]; script s; setup(&s, 1);
    capture_fail_call = 2; fatal(&s, NULL, false, domain1, &out, &saved); CHECK(capture_calls == 2); capture_fail_call = 0;
    capture_fail_call = 1; fatal(&s, NULL, false, input, &out, &saved); capture_fail_call = 0;
    arm_after_domain = 1; arm_module_failure = 1; fatal(&s, NULL, true, input, &out, &saved); CHECK(!module_fail_after && !s.setters && !s.http.calls);
    arm_after_domain = 1; arm_module_failure = 2; s.verified[0] = false; s.expected_errors[0] = "net/http: nil Context"; char *error = NULL;
    CHECK(invoke(&s, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error && out.len == 2 && module_fail_after == 1); module_fail_after = 0;
    br_result_clear(&out.items[--out.len]);
    setup(&s, 0); arm_after_domain = 1; arm_module_failure = 1;
    CHECK(invoke(&s, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error && out.len == 2 && module_fail_after == 1); module_fail_after = 0; br_result_clear(&out.items[--out.len]);
    setup(&s, 1); dup_fail_after = 1; fatal(&s, NULL, true, input, &out, &saved); CHECK(!dup_fail_after && !s.setters);
    snprintf(input, sizeof(input), "%s %s %s", token, other, domain1);
    for (size_t allocation = 1; allocation <= 2; ++allocation) {
        setup(&s, 2); s.tokens[1] = other; arm_after_domain = 2; arm_module_failure = allocation;
        fatal(&s, &s.ctx, true, input, &out, &saved); CHECK(!module_fail_after && s.http.calls == 1 && s.http.releases == 1 && s.setters == 1);
    }
    setup(&s, 2); s.tokens[1] = other; map_fail_after = 2; fatal(&s, &s.ctx, true, input, &out, &saved); CHECK(!map_fail_after && s.http.releases == 1);
    setup(&s, 2); s.tokens[1] = other; pair_fail_after = 2; fatal(&s, &s.ctx, true, input, &out, &saved); CHECK(!pair_fail_after && s.http.releases == 1);
    setup(&s, 2); s.tokens[1] = other; setter_fail_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved); CHECK(!setter_fail_after && s.http.releases == 2 && s.setters == 2 && s.release_len[1] == 2);
    setup(&s, 2); s.tokens[1] = other; push_fail_after = 2;
    fatal(&s, &s.ctx, true, input, &out, &saved); CHECK(!push_fail_after && s.http.releases == 2 && s.setters == 2 && s.release_len[1] == 2);
    setup(&s, 1); s.statuses[0] = 403; s.verified[0] = false; s.arm_dup_at_send = 1;
    fatal(&s, &s.ctx, true, input, &out, &saved); CHECK(!dup_fail_after && s.http.releases == 1 && !s.setters);
    setup(&s, 1); s.statuses[0] = 403; s.verified[0] = false; s.expected_errors[0] = "unexpected status code: 403"; fail_real_setter_copy = true;
    fatal(&s, &s.ctx, true, input, &out, &saved); CHECK(!fail_real_setter_copy && s.http.releases == 1 && s.setters == 1);
    br_results_clear(&out);
}
int main(void)
{
    extraction(); policy(); failures(); return test_finish("okta");
}
