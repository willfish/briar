/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <stdarg.h>

int br_posthog_init(const br_detector **out, char **error);
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static const char us_prefix[] = "https://app.posthog.com/api/event/?personal_api_key=";
static const char eu_prefix[] = "https://eu.posthog.com/api/event/?personal_api_key=";
static char k43[48], k48[53], other[48];
typedef enum { NONE, COMPILE, CAPTURE, FINDING, ALLOCATE, FORMAT_NEGATIVE, FORMAT_SHORT, FORMAT_TRUNCATED, PUSH } fault_kind;
static fault_kind fault, fault2;
static size_t nth, nth2, injected, freed_patterns, captures, findings, allocations, mallocs_this_key, url_frees, formats, sends, releases, pushes, setters;
static const br_regex *compiled;
static bool collected, verify_mode, watch, consume_null;
static br_result *active_result;
static char *live_us, *live_eu;
static size_t us_cap, eu_cap;
static const br_scan_ctx *scan_context;
static const br_http_request *provider_request;
static const char *expected_agent = "TruffleHog";
static char events[240];
static size_t nevents;
typedef struct { int us_status, eu_status, us_rc, eu_rc; const char *us_error, *eu_error, *body_error; } script;
static script *scripts;
static size_t script_len, script_i;

static bool hit_slot(fault_kind *slot, size_t *at, fault_kind kind)
{
    if (*slot != kind || (*at && --*at)) return false;
    *slot = NONE; ++injected; return true;
}
static bool hit(fault_kind kind) { return hit_slot(&fault, &nth, kind) || hit_slot(&fault2, &nth2, kind); }
static void event(char c)
{
    if (!watch) return;
    CHECK(nevents + 1 < sizeof(events)); events[nevents++] = c; events[nevents] = 0;
}
static int checked_compile(const char *pattern, br_regex **out, char **error)
{
    CHECK(!strcmp(pattern, "\\b(phx_[a-zA-Z0-9_]{43,48})\\b")); event('c');
    int rc = br_regex_compile(pattern, out, error);
    if (rc == 0) compiled = *out;
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static void checked_regex_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *pattern, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(pattern == compiled && !unique && !active_result && !live_us && !live_eu && !provider_request);
    ++captures; event('C'); collected = false;
    int rc = br_captures_find(pattern, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) return 1;
    collected = rc == 0; return rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice key, const char *part)
{
    CHECK(collected && !active_result && !live_us && !live_eu && type == 161 && !strcmp(part, "key"));
    active_result = r; mallocs_this_key = 0; ++findings; event('F');
    int rc = br_finding_key_bytes(r, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r)
{
    if (r == active_result) { CHECK(!live_us && !live_eu && !provider_request); active_result = NULL; }
    br_result_clear(r);
}
static void *checked_malloc(size_t size)
{
    CHECK(active_result && verify_mode && !provider_request && mallocs_this_key < 2);
    ++allocations; ++mallocs_this_key; event('A');
    CHECK(size == (mallocs_this_key == 1 ? 52u : 51u) + active_result->raw.len + 1);
    if (hit(ALLOCATE)) return NULL;
    char *p = malloc(size); CHECK(p);
    if (mallocs_this_key == 1) { live_us = p; us_cap = size; }
    else { live_eu = p; eu_cap = size; }
    return p;
}
static void checked_free(void *p)
{
    if (p && (p == live_us || p == live_eu)) {
        CHECK(!provider_request || provider_request->url != p);
        if (p == live_us) live_us = NULL; else live_eu = NULL;
        ++url_frees; event('X');
    }
    free(p);
}
static int checked_format(char *out, size_t capacity, const char *format, ...)
{
    bool eu = out == live_eu;
    const char *prefix = eu ? eu_prefix : us_prefix;
    size_t plen = eu ? 51 : 52;
    CHECK(active_result && verify_mode && (out == live_us || eu) && !provider_request);
    CHECK(!strcmp(format, "%s%.*s") && capacity == (eu ? eu_cap : us_cap) && capacity == plen + active_result->raw.len + 1);
    va_list args, inspect; va_start(args, format); va_copy(inspect, args);
    const char *got = va_arg(inspect, const char *); int klen = va_arg(inspect, int); const char *k = va_arg(inspect, const char *);
    va_end(inspect);
    CHECK(got && !strcmp(got, prefix) && klen > 0 && (size_t)klen == active_result->raw.len && !memcmp(k, active_result->raw.data, (size_t)klen));
    int n = vsnprintf(out, capacity, format, args); va_end(args);
    CHECK(n >= 0 && (size_t)n == capacity - 1 && !memcmp(out, prefix, plen) && !memcmp(out + plen, k, (size_t)klen) && !out[capacity - 1]);
    ++formats; event('B');
    if (hit(FORMAT_NEGATIVE)) return -1;
    if (hit(FORMAT_SHORT)) return 1;
    return hit(FORMAT_TRUNCATED) ? (int)capacity : n;
}
static void request_values(const br_http_request *r, bool effective)
{
    bool eu = r->url == live_eu;
    size_t plen = eu ? 51 : 52;
    CHECK(active_result && !active_result->verified && !active_result->verification_error && !active_result->extra_data);
    CHECK(r->url == live_us || eu);
    CHECK(!strcmp(r->method, "GET") && r->profile == BR_HTTP_SANE && r->detector_type == 161);
    CHECK(r->timeout_ms == (effective ? 5000u : 0u) && r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/json"));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(strlen(r->url) == plen + active_result->raw.len && !memcmp(r->url, eu ? eu_prefix : us_prefix, plen));
    CHECK(!memcmp(r->url + plen, active_result->raw.data, active_result->raw.len));
    if (effective) CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, expected_agent));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    bool eu = r->url == live_eu;
    CHECK(ctx && ctx == scan_context && verify_mode && live_us && live_eu && (r->url == live_us || eu));
    CHECK(eu ? provider_request == NULL && sends == releases && releases > 0 : !provider_request);
    request_values(r, false); provider_request = r; ++sends; event(eu ? 'e' : 'u');
    int rc = br_http_send(ctx, r, response, error);
    if (consume_null && rc != 0 && error && *error) { free(*error); *error = NULL; }
    return rc;
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == scan_context && (provider_request->url == live_us || provider_request->url == live_eu));
    event(provider_request->url == live_eu ? 'E' : 'U');
    br_http_release(ctx, response); ++releases; provider_request = NULL;
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(active_result == r && collected && !provider_request && !live_us && !live_eu && sends == releases);
    ++pushes; event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
static int forbidden_setter(br_result *r, const char *cause, const br_slice *keys, size_t n)
{
    (void)r; (void)cause; (void)keys; (void)n; ++setters; CHECK(false); return 1;
}
static int forbidden_prefixed(const char *const *keys, size_t count, const char *capture, br_regex **out, char **error)
{
    (void)keys; (void)count; (void)capture; (void)out; (void)error; CHECK(false); return 1;
}
static size_t forbidden_find(br_slice haystack, br_slice needle, size_t start)
{
    (void)haystack; (void)needle; (void)start; CHECK(false); return SIZE_MAX;
}
#define br_regex_compile checked_compile
#define br_regex_compile_prefixed forbidden_prefixed
#define br_regex_free checked_regex_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_result_clear checked_clear
#define malloc checked_malloc
#define free checked_free
#define snprintf checked_format
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#define br_slice_find forbidden_find
#include "../../src/detectors/posthog.c"
#undef br_regex_compile
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_result_clear
#undef malloc
#undef free
#undef snprintf
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_result_set_verification_error
#undef br_slice_find

static br_results scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input)
{
    collected = false; scan_context = ctx; verify_mode = verify; script_i = 0;
    return test_scan(d, ctx, verify, input.data, input.len);
}
static void result_is(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 161, key, "key"); CHECK(r->verified == verified && !r->verification_error);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(us_prefix) - 1 == 52 && sizeof(eu_prefix) - 1 == 51);
    CHECK(sizeof(posthog_us_prefix) - 1 == 52 && sizeof(posthog_eu_prefix) - 1 == 51);
    CHECK(!strcmp(posthog_pattern, "\\b(phx_[a-zA-Z0-9_]{43,48})\\b"));
    CHECK(br_posthog_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_posthog_init(NULL, NULL) == -1);
    fault = COMPILE; nth = 1; watch = true; nevents = 0; events[0] = 0;
    CHECK(br_posthog_init(&d, &error) == -1 && !d && error && !strcmp(events, "c") && freed_patterns == 1); free(error); error = NULL;
    nevents = 0; events[0] = 0; CHECK(!br_posthog_init(&d, &error) && d && !error && !strcmp(events, "c"));
    nevents = 0; events[0] = 0; CHECK(!br_posthog_init(&again, NULL) && again == d && !events[0] && fault == NONE); watch = false;
    CHECK(d->type == 161 && d->version == 0 && !strcmp(d->name, "PosthogApp") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "PostHog is an open-source product analytics platform. The phx_ keys are used to authenticate and track events in PostHog."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "phx_") && strcmp(d->keywords[0], "posthog"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1 && d->state && d->scan);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void expect_keys(const br_detector *d, const char *input, const char **keys, size_t n)
{
    size_t alloc = allocations, sent = sends;
    br_results out = scan(d, NULL, false, text(input));
    CHECK(out.len == n && allocations == alloc && sends == sent && captures && !setters);
    for (size_t i = 0; i < n; ++i) result_is(&out.items[i], keys[i], false);
    br_results_clear(&out);
}
static void fill_key(char *out, const char *prefix, size_t suffix, char fill)
{
    memcpy(out, prefix, 4); memset(out + 4, fill, suffix); out[4 + suffix] = 0;
}
static void grammar(const br_detector *d)
{
    char input[256], hyphen[64], short_key[47], folded[48], long_word[55];
    const char *one[] = {k43}, *wide[] = {k48}, *ordered[] = {k43, other, k43};
    expect_keys(d, k43, one, 1); expect_keys(d, k48, wide, 1); expect_keys(d, other, (const char *[]){other}, 1);
    snprintf(input, sizeof(input), "%s %s\n%s", k43, other, k43); expect_keys(d, input, ordered, 3);
    fill_key(short_key, "phx_", 42, 'A'); expect_keys(d, short_key, NULL, 0);
    fill_key(long_word, "phx_", 49, 'A'); expect_keys(d, long_word, NULL, 0);
    snprintf(input, sizeof(input), "%sA", k48); expect_keys(d, input, NULL, 0);
    snprintf(input, sizeof(input), "%s9", k48); expect_keys(d, input, NULL, 0);
    snprintf(input, sizeof(input), "%s_", k48); expect_keys(d, input, NULL, 0);
    snprintf(input, sizeof(input), "%s-", k48); expect_keys(d, input, wide, 1);
    snprintf(input, sizeof(input), "%s!", k43); expect_keys(d, input, one, 1);
    fill_key(folded, "PHX_", 43, 'B'); expect_keys(d, folded, NULL, 0);
    fill_key(folded, "Phx_", 43, 'B'); expect_keys(d, folded, NULL, 0);
    memcpy(hyphen, "phx_", 4); memset(hyphen + 4, 'C', 20); hyphen[24] = '-'; memset(hyphen + 25, 'D', 30); hyphen[55] = 0;
    expect_keys(d, hyphen, NULL, 0);
    const char *edges[] = {" ", "-", ".", "\n", "x", "9", "_"};
    for (size_t i = 0; i < sizeof(edges) / sizeof(*edges); ++i) {
        bool word = !strcmp(edges[i], "x") || !strcmp(edges[i], "9") || !strcmp(edges[i], "_");
        snprintf(input, sizeof(input), "%s%s", edges[i], k43); expect_keys(d, input, word ? NULL : one, word ? 0 : 1);
        /* A short suffix absorbs one more word byte. Only the 49th fails \b. */
        snprintf(input, sizeof(input), "%s%s", k43, edges[i]);
        const char *extended[] = {input};
        expect_keys(d, input, word ? extended : one, 1);
    }
    expect_keys(d, "posthog", NULL, 0); expect_keys(d, "", NULL, 0); expect_keys(d, (char[]){0}, NULL, 0);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)ctx; request_values(r, true);
    if (!scripts) return;
    bool eu = r->url == live_eu;
    size_t i = eu ? script_i - 1 : script_i++;
    CHECK(i < script_len && (!eu || script_i));
    static const unsigned char junk[] = "not-json\0\"code\":\"SUCCESS\"";
    http->response = (br_http_response){.status = eu ? scripts[i].eu_status : scripts[i].us_status,
        .body = {junk, sizeof(junk) - 1}, .body_error = scripts[i].body_error};
    http->send_rc = eu ? scripts[i].eu_rc : scripts[i].us_rc;
    http->send_error = eu ? scripts[i].eu_error : scripts[i].us_error;
}
static void verify_one(const br_detector *d, const char *key, script s, bool verified, bool eu, const char *order)
{
    char input[80]; snprintf(input, sizeof(input), " %s\n", key);
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &(br_endpoints){.configured = (const char *[]){"https://ignored.invalid"}, .nconfigured = 1}};
    scripts = &s; script_len = 1; script_i = 0; nevents = 0; events[0] = 0; watch = true;
    size_t sent = sends, rel = releases, alloc = allocations, freed = url_frees;
    br_results out = scan(d, &ctx, true, text(input)); watch = false; scripts = NULL;
    CHECK(out.len == 1 && sends == sent + 1 + eu && releases == rel + 1 + eu && http.calls == 1u + eu && http.releases == http.calls);
    CHECK(allocations == alloc + 2 && url_frees == freed + 2 && !strcmp(events, order) && !setters);
    result_is(&out.items[0], key, verified); br_results_clear(&out);
}
static void statuses(const br_detector *d)
{
    const int no_eu[] = {0, 199, 400, 402, 403, 500};
    for (size_t i = 0; i < sizeof(no_eu) / sizeof(*no_eu); ++i)
        verify_one(d, k43, (script){.us_status = no_eu[i], .eu_status = 200, .body_error = "read failure"}, false, false, "CFABABuUXXP");
    verify_one(d, other, (script){.us_status = 200, .body_error = ""}, true, false, "CFABABuUXXP");
    verify_one(d, k48, (script){.us_status = 204, .eu_status = 500, .body_error = "completed body"}, true, false, "CFABABuUXXP");
    verify_one(d, k43, (script){.us_status = 299}, true, false, "CFABABuUXXP");
    verify_one(d, k43, (script){.us_status = 401, .eu_status = 200, .body_error = ""}, true, true, "CFABABuUeEXXP");
    verify_one(d, other, (script){.us_status = 401, .eu_status = 204, .body_error = "ignored"}, true, true, "CFABABuUeEXXP");
    verify_one(d, k48, (script){.us_status = 401, .eu_status = 299}, true, true, "CFABABuUeEXXP");
    const int eu_false[] = {0, 199, 300, 400, 401, 500};
    for (size_t i = 0; i < sizeof(eu_false) / sizeof(*eu_false); ++i)
        verify_one(d, k43, (script){.us_status = 401, .eu_status = eu_false[i], .body_error = "still ignored"}, false, true, "CFABABuUeEXXP");
    verify_one(d, k43, (script){.us_status = 200, .us_rc = 1, .us_error = "timeout", .eu_status = 200}, false, false, "CFABABuUXXP");
    verify_one(d, k43, (script){.us_status = 401, .us_rc = -4, .us_error = "", .eu_status = 200, .body_error = "ignored because Do failed"}, false, false, "CFABABuUXXP");
    verify_one(d, k43, (script){.us_status = 401, .us_rc = 1, .eu_status = 200}, false, false, "CFABABuUXXP");
    consume_null = true; verify_one(d, k43, (script){.us_status = 200, .us_rc = 1, .us_error = "consumed component leaf", .eu_status = 200}, false, false, "CFABABuUXXP"); consume_null = false;
    verify_one(d, k43, (script){.us_status = 401, .eu_status = 200, .eu_rc = 1, .eu_error = "eu timeout"}, false, true, "CFABABuUeEXXP");
    verify_one(d, other, (script){.us_status = 401, .eu_rc = -2, .eu_error = NULL, .body_error = ""}, false, true, "CFABABuUeEXXP");
}
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void nil_and_continuation(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "%s\n%s", k43, other);
    size_t alloc = allocations, built = formats, freed = url_frees, sent = sends, made = findings;
    nevents = 0; events[0] = 0; watch = true;
    br_results out = scan(d, NULL, true, text(input)); watch = false;
    CHECK(!out.len && allocations == alloc + 4 && formats == built + 4 && url_frees == freed + 4 && sends == sent);
    CHECK(findings == made + 2 && !strcmp(events, "CFABABXXFABABXX") && !setters); br_results_clear(&out);
    alloc = allocations; sent = sends; out = scan(d, NULL, false, text(input));
    CHECK(out.len == 2 && allocations == alloc && sends == sent); result_is(&out.items[0], k43, false); result_is(&out.items[1], other, false); br_results_clear(&out);
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http);
    const char *configured[] = {"https://ignored.invalid", "https://eu.posthog.com/api/event/?personal_api_key=nope"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 2, .cloud = "https://cloud.invalid", .use_cloud = true, .use_found = true};
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "posthog-offline"};
    expected_agent = "TruffleHog posthog-offline";
    script rows[] = {{.us_status = 401, .eu_status = 500, .body_error = ""}, {.us_status = 201, .body_error = "read"}, {.us_status = 401, .eu_status = 200, .body_error = "x"}};
    scripts = rows; script_len = 3; snprintf(input, sizeof(input), "%s %s %s", k43, other, k43);
    sent = sends; out = scan(d, &ctx, true, text(input)); scripts = NULL; expected_agent = "TruffleHog";
    CHECK(out.len == 3 && sends == sent + 5 && http.calls == 5 && http.releases == 5 && script_i == 3);
    result_is(&out.items[0], k43, false); result_is(&out.items[1], other, true); result_is(&out.items[2], k43, true); br_results_clear(&out);
    size_t cancellations = 0;
    br_scan_ctx guards[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(guards) / sizeof(*guards); ++i) {
        sent = sends; http.calls = http.releases = 0;
        out = scan(d, &guards[i], true, text(k43));
        CHECK(out.len == 1 && sends == sent + 1 && releases == sends && http.calls == 0 && http.releases == (i ? 1u : 0u));
        result_is(&out.items[0], k43, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void owned_failures(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "%s\n%s", k43, other);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t which; bool nil; int us_rc; } cases[] = {
        {CAPTURE, 1, true, 0}, {FINDING, 1, true, 0}, {FINDING, 2, false, 0},
        {ALLOCATE, 1, true, 0}, {ALLOCATE, 2, false, 0}, {FORMAT_NEGATIVE, 1, true, 0},
        {FORMAT_SHORT, 2, false, 0}, {FORMAT_TRUNCATED, 1, false, 1}, {PUSH, 1, false, 0}, {PUSH, 2, false, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.inspect = inspect, .response = {.status = 200}, .send_rc = cases[i].us_rc, .send_error = cases[i].us_rc ? "opaque" : NULL};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        scripts = NULL; script_len = 0; scan_context = cases[i].nil ? NULL : &ctx; verify_mode = true; collected = false;
        fault = cases[i].kind; nth = cases[i].which; fault2 = NONE; nth2 = 0;
        size_t failed = injected, sent = sends, alloc = allocations, freed = url_frees, built = formats; char *error = NULL;
        CHECK(d->scan(d, scan_context, true, text(cases[i].kind == CAPTURE ? "posthog" : input), &out, &error) == -1);
        CHECK(error && fault == NONE && injected == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(!live_us && !live_eu && !provider_request && !active_result && sends == releases && !setters);
        if (cases[i].kind == CAPTURE || (cases[i].kind == FINDING && cases[i].which == 1)) CHECK(allocations == alloc && sends == sent);
        if (cases[i].kind == FINDING && cases[i].which == 2) CHECK(allocations == alloc + 2 && sends == sent + 1 && url_frees == freed + 2);
        if (cases[i].kind == ALLOCATE || cases[i].kind == FORMAT_NEGATIVE || cases[i].kind == FORMAT_SHORT || cases[i].kind == FORMAT_TRUNCATED)
            CHECK(sends == sent && allocations >= alloc + 1 && url_frees == freed + (allocations - alloc - (cases[i].kind == ALLOCATE)) && formats >= built + (cases[i].kind == ALLOCATE ? 0 : 1));
        free(error);
    }
    scripts = NULL; fault = FORMAT_NEGATIVE; nth = 1; fault2 = ALLOCATE; nth2 = 2; scan_context = NULL; verify_mode = true; collected = false;
    size_t alloc = allocations, built = formats, freed = url_frees, failed = injected; char *error = NULL;
    CHECK(d->scan(d, NULL, true, text(k43), &out, &error) == -1 && error && strstr(error, "cannot format PostHog URL"));
    CHECK(injected == failed + 2 && allocations == alloc + 2 && formats == built + 1 && url_frees == freed + 1 && fault == NONE && fault2 == NONE);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); free(error); error = NULL;
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    script row = {.us_status = 200}; scripts = &row; script_len = 1; fault = ALLOCATE; nth = 3; scan_context = &ctx; verify_mode = true; collected = false;
    CHECK(d->scan(d, &ctx, true, text(input), &out, &error) == -1 && error && fault == NONE);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)) && sends == releases && !live_us && !live_eu); free(error); error = NULL; scripts = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
    char *url = NULL; error = NULL; size_t before = allocations;
    CHECK(posthog_url(us_prefix, 52, (br_slice){(const unsigned char *)"x", SIZE_MAX}, &url, &error) == -1 && error && !url && allocations == before); free(error); error = NULL;
    CHECK(posthog_url(eu_prefix, 51, (br_slice){0}, &url, &error) == -1 && error && !url && allocations == before); free(error); error = NULL;
    CHECK(posthog_url(us_prefix, 52, (br_slice){NULL, 4}, &url, &error) == -1 && error && !url); free(error);
}
static void raw_url_bytes(void)
{
    const char raw[] = "a b%\"\\?#&";
    br_result dummy = {.raw = {(unsigned char *)raw, sizeof(raw) - 1}};
    active_result = &dummy; verify_mode = true; mallocs_this_key = 0;
    char *url = NULL, *error = NULL;
    CHECK(!posthog_url(posthog_us_prefix, 52, text(raw), &url, &error) && !error && url);
    CHECK(strlen(url) == 52 + sizeof(raw) - 1 && !memcmp(url, us_prefix, 52) && !memcmp(url + 52, raw, sizeof(raw) - 1));
    checked_free(url); active_result = NULL; verify_mode = false;
    CHECK(!live_us && !live_eu);
}
int main(void)
{
    (void)forbidden_setter; (void)forbidden_prefixed; (void)forbidden_find;
    memcpy(k43, "phx_", 4); test_secret(k43 + 4, 43, 0);
    memcpy(k48, "phx_", 4); test_secret(k48 + 4, 48, 5);
    memcpy(other, "phx_", 4); test_secret(other + 4, 43, 11); other[4] = 'A'; other[12] = '_'; other[30] = 'Z';
    const br_detector *d = descriptor();
    grammar(d); raw_url_bytes(); statuses(d); nil_and_continuation(d); owned_failures(d);
    CHECK(fault == NONE && fault2 == NONE && sends == releases && !live_us && !live_eu && !provider_request && !active_result && !setters && !consume_null && !watch && !scripts);
    return test_finish("PostHog");
}
