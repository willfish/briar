/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <json-c/json.h>
#include <stdarg.h>

int br_postmark_init(const br_detector **out, char **error);
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
static const char server_url[] = "https://api.postmarkapp.com/deliverystats";
static const char account_url[] = "https://api.postmarkapp.com/domains?count=10&offset=0";
static const char capture[] = "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b";
typedef enum { NONE, COMPILE, CAPTURE, FINDING, FORMAT_NEGATIVE, FORMAT_SHORT, FORMAT_PLUS, ALLOC, EXTRA_OBJECT, EXTRA_STRING, EXTRA_ADD, SETTER, PUSH } fault_kind;
static fault_kind fault;
static size_t nth, injected, freed_patterns, captures, findings, formats, allocations, sends, releases, pushes, setters, extras;
static const br_regex *compiled;
static bool collected, verify_mode, watch;
static int consume_nulls;
static br_result *active_result;
static const char *active_token;
static const br_scan_ctx *scan_context;
static const br_http_request *provider_request;
static const char *expected_agent = "TruffleHog";
static char events[320];
static size_t nevents;
typedef struct { int status, rc; const char *error, *body_error; } hop;
static hop *hops;
static size_t hop_len, hop_i;

static bool hit(fault_kind kind)
{
    if (fault != kind || (nth && --nth)) return false;
    fault = NONE; ++injected; return true;
}
static void event(char c)
{
    if (!watch) return;
    CHECK(nevents + 1 < sizeof(events)); events[nevents++] = c; events[nevents] = 0;
}
static int checked_prefixed(const char *const *keywords, size_t count, const char *pattern, br_regex **out, char **error)
{
    CHECK(count == 1 && keywords && !strcmp(keywords[0], "postmark") && !strcmp(pattern, capture)); event('c');
    int rc = br_regex_compile_prefixed(keywords, count, pattern, out, error);
    if (rc == 0) compiled = *out;
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static int forbidden_raw(const char *pattern, br_regex **out, char **error)
{
    (void)pattern; (void)out; (void)error; CHECK(false); return 1;
}
static void checked_regex_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *pattern, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(pattern == compiled && !unique && !active_result && !provider_request);
    ++captures; event('C'); collected = false;
    int rc = br_captures_find(pattern, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) return 1;
    collected = rc == 0; return rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice value, const char *part)
{
    CHECK(collected && !active_result && !provider_request && type == 81 && !strcmp(part, "key") && value.len == 36);
    active_result = r; active_token = (const char *)value.data; ++findings; event('F');
    int rc = br_finding_key_bytes(r, type, value, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r)
{
    if (r == active_result) { CHECK(!provider_request); active_result = NULL; active_token = NULL; }
    br_result_clear(r);
}
static int checked_format(char *out, size_t capacity, const char *format, ...)
{
    CHECK(verify_mode && !strcmp(format, "unexpected status code: %d") && (!out || capacity == 48));
    va_list args, inspect; va_start(args, format); va_copy(inspect, args);
    (void)va_arg(inspect, int); va_end(inspect);
    int n = vsnprintf(out, capacity, format, args); va_end(args);
    ++formats; event('B');
    if (hit(FORMAT_NEGATIVE)) return -1;
    if (hit(FORMAT_SHORT)) return 1;
    return hit(FORMAT_PLUS) ? n + 1 : n;
}
static void *checked_malloc(size_t size)
{
    CHECK(verify_mode && active_result && size > 0); ++allocations; event('M');
    if (hit(ALLOC)) return NULL;
    return malloc(size);
}
static br_json *checked_object(void)
{
    CHECK(verify_mode && active_result && !provider_request && sends == releases); ++extras; event('X');
    return hit(EXTRA_OBJECT) ? NULL : json_object_new_object();
}
static br_json *checked_string(const char *value)
{
    CHECK(value && (!strcmp(value, "server") || !strcmp(value, "account")));
    return hit(EXTRA_STRING) ? NULL : json_object_new_string(value);
}
static int checked_add(br_json *object, const char *name, br_json *value)
{
    CHECK(object && value && !strcmp(name, "type"));
    if (hit(EXTRA_ADD)) return -1;
    return json_object_object_add(object, name, value);
}
static void request_values(const br_http_request *r, bool effective)
{
    bool account = r->url && !strcmp(r->url, account_url);
    CHECK(active_result && active_token && !strcmp(r->method, "GET") && r->profile == BR_HTTP_SANE && r->detector_type == 81);
    CHECK(!strcmp(r->url, account ? account_url : server_url));
    CHECK(r->timeout_ms == (effective ? 5000u : 0u) && r->nheaders == (effective ? 4u : 3u));
    CHECK(!strcmp(r->headers[0].name, "Accept") && !strcmp(r->headers[0].value, "application/json"));
    CHECK(!strcmp(r->headers[1].name, "Content-Type") && !strcmp(r->headers[1].value, "application/json"));
    CHECK(!strcmp(r->headers[2].name, account ? "X-Postmark-Account-Token" : "X-Postmark-Server-Token"));
    CHECK(r->headers[2].value && !strcmp(r->headers[2].value, active_token));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    if (effective) CHECK(!strcmp(r->headers[3].name, "User-Agent") && !strcmp(r->headers[3].value, expected_agent));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    bool account = r->url && !strcmp(r->url, account_url);
    CHECK(ctx && ctx == scan_context && verify_mode && active_result && (account ? provider_request == NULL && sends == releases && releases > 0 : !provider_request));
    request_values(r, false); provider_request = r; ++sends; event(account ? 'a' : 'u');
    int rc = br_http_send(ctx, r, response, error);
    if (consume_nulls && rc != 0 && error && *error) { free(*error); *error = NULL; --consume_nulls; }
    return rc;
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == scan_context);
    event(!strcmp(provider_request->url, account_url) ? 'A' : 'U');
    br_http_release(ctx, response); ++releases; provider_request = NULL;
}
static int checked_setter(br_result *r, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    CHECK(r == active_result && cause && !secrets && !nsecrets && !provider_request && sends == releases);
    ++setters; event('S');
    if (hit(SETTER)) return 1;
    return br_result_set_verification_error(r, cause, secrets, nsecrets);
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(active_result == r && collected && !provider_request && sends == releases); ++pushes; event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
static size_t forbidden_find(br_slice haystack, br_slice needle, size_t start)
{
    (void)haystack; (void)needle; (void)start; CHECK(false); return SIZE_MAX;
}
#define br_regex_compile forbidden_raw
#define br_regex_compile_prefixed checked_prefixed
#define br_regex_free checked_regex_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_result_clear checked_clear
#define snprintf checked_format
#define malloc checked_malloc
#define json_object_new_object checked_object
#define json_object_new_string checked_string
#define json_object_object_add checked_add
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_slice_find forbidden_find
#include "../../src/detectors/postmark.c"
#undef br_regex_compile
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_result_clear
#undef snprintf
#undef malloc
#undef json_object_new_object
#undef json_object_new_string
#undef json_object_object_add
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push
#undef br_slice_find

static br_results scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input)
{
    collected = false; scan_context = ctx; verify_mode = verify; hop_i = 0;
    return test_scan(d, ctx, verify, input.data, input.len);
}
static void result_base(const br_result *r, const char *value)
{
    CHECK(r->detector_type == 81 && r->raw.len == 36 && !memcmp(r->raw.data, value, 36));
    CHECK(!r->detector_name && !r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(!strcmp(json_object_get_string(part), value));
    CHECK(!r->verification_from_cache && !r->primary_secret.data && !r->primary_line && !r->chunk_offset_set);
}
static void expect_false(const br_result *r, const char *value, const char *cause)
{
    result_base(r, value); CHECK(!r->verified && !r->extra_data);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}
static void expect_type(const br_result *r, const char *value, const char *type)
{
    result_base(r, value); CHECK(r->verified && !r->verification_error && r->extra_data && json_object_object_length(r->extra_data) == 1);
    br_json *got = NULL;
    CHECK(json_object_object_get_ex(r->extra_data, "type", &got) && json_object_is_type(got, json_type_string));
    CHECK(!strcmp(json_object_get_string(got), type));
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(strlen(postmark_nil_context) == 21 && !strcmp(postmark_server_url, server_url) && !strcmp(postmark_account_url, account_url));
    CHECK(br_postmark_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_postmark_init(NULL, NULL) == -1);
    fault = COMPILE; nth = 1; watch = true; nevents = 0; events[0] = 0;
    CHECK(br_postmark_init(&d, &error) == -1 && !d && error && !strcmp(events, "c") && freed_patterns == 1); free(error); error = NULL;
    nevents = 0; events[0] = 0; CHECK(!br_postmark_init(&d, &error) && d && !error && !strcmp(events, "c"));
    nevents = 0; events[0] = 0; CHECK(!br_postmark_init(&again, NULL) && again == d && !events[0] && fault == NONE); watch = false;
    CHECK(d->type == 81 && d->version == 0 && !strcmp(d->name, "Postmark") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Postmark is an email delivery service. Postmark server tokens can be used to access and manage email delivery and statistics."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "postmark") && d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void expect_keys(const br_detector *d, const char *input, const char **values, size_t n)
{
    size_t sent = sends, made = allocations, extra = extras, set = setters;
    br_results out = scan(d, NULL, false, text(input));
    CHECK(out.len == n && sends == sent && allocations == made && extras == extra && setters == set && captures && !setters);
    for (size_t i = 0; i < n; ++i) expect_false(&out.items[i], values[i], NULL);
    br_results_clear(&out);
}
static void grammar(const br_detector *d)
{
    char input[256], upper[37], bad[37];
    const char *one[] = {key}, *ordered[] = {key, other}, *same[] = {key, key};
    expect_keys(d, key, NULL, 0);
    snprintf(input, sizeof(input), "postmark %s", key); expect_keys(d, input, one, 1);
    snprintf(input, sizeof(input), "POSTMARK\n%s", key); expect_keys(d, input, one, 1);
    snprintf(input, sizeof(input), "PostMark-%s", key); expect_keys(d, input, one, 1);
    snprintf(input, sizeof(input), "postmark%s", key); expect_keys(d, input, NULL, 0);
    snprintf(input, sizeof(input), "%s postmark", key); expect_keys(d, input, NULL, 0);
    memcpy(upper, key, 37); upper[0] = 'A'; snprintf(input, sizeof(input), "postmark %s", upper); expect_keys(d, input, NULL, 0);
    memcpy(bad, key, 37); bad[8] = '?'; snprintf(input, sizeof(input), "postmark %s", bad); expect_keys(d, input, NULL, 0);
    memcpy(bad, key, 37); memmove(bad + 8, bad + 9, 28); snprintf(input, sizeof(input), "postmark %s", bad); expect_keys(d, input, NULL, 0);
    snprintf(input, sizeof(input), "postmark %sx", key); expect_keys(d, input, NULL, 0);
    snprintf(input, sizeof(input), "postmark %s!", key); expect_keys(d, input, one, 1);
    snprintf(input, sizeof(input), "xpostmark %s", key); expect_keys(d, input, one, 1);
    memset(input, ' ', 8 + 40); memcpy(input, "postmark", 8); memcpy(input + 48, key, 37); expect_keys(d, input, one, 1);
    memset(input, ' ', 8 + 41); memcpy(input, "postmark", 8); memcpy(input + 49, key, 37); expect_keys(d, input, NULL, 0);
    snprintf(input, sizeof(input), "postmark %s %s", key, other); expect_keys(d, input, one, 1);
    snprintf(input, sizeof(input), "postmark %s postmark %s", key, key); expect_keys(d, input, same, 2);
    snprintf(input, sizeof(input), "postmark %s\npostmark %s", key, other); expect_keys(d, input, ordered, 2);
    expect_keys(d, "", NULL, 0); expect_keys(d, "postmark", NULL, 0);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)ctx; request_values(r, true);
    if (!hops) return;
    CHECK(hop_i < hop_len);
    static const unsigned char junk[] = "not-json\0token";
    http->response = (br_http_response){.status = hops[hop_i].status, .body = {junk, sizeof(junk) - 1}, .body_error = hops[hop_i].body_error};
    http->send_rc = hops[hop_i].rc; http->send_error = hops[hop_i].error; ++hop_i;
}
static void verify_one(const br_detector *d, hop server, hop account, bool use_account, bool verified, const char *type, const char *cause, const char *order)
{
    char input[80]; snprintf(input, sizeof(input), "postmark %s", key);
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &(br_endpoints){.configured = (const char *[]){"https://ignored.invalid"}, .nconfigured = 1}};
    hop rows[2] = {server, account}; hops = rows; hop_len = 1u + use_account; hop_i = 0; nevents = 0; events[0] = 0; watch = true;
    size_t sent = sends, rel = releases, set = setters, extra = extras;
    br_results out = scan(d, &ctx, true, text(input)); watch = false; hops = NULL;
    CHECK(out.len == 1 && sends == sent + 1 + use_account && releases == rel + 1 + use_account && http.calls == 1u + use_account && http.releases == http.calls);
    CHECK(hop_i == hop_len && setters == set + (cause != NULL) && extras == extra + verified && !strcmp(events, order));
    if (verified) expect_type(&out.items[0], key, type); else expect_false(&out.items[0], key, cause);
    br_results_clear(&out);
}
static void statuses(const br_detector *d)
{
    const int other_status[] = {0, 201, 204, 299, 300, 400, 403, 500};
    verify_one(d, (hop){.status = 200, .body_error = "read failure"}, (hop){.status = 200}, false, true, "server", NULL, "CFuUXP");
    verify_one(d, (hop){.status = 200, .body_error = ""}, (hop){.status = 500}, false, true, "server", NULL, "CFuUXP");
    for (size_t i = 0; i < sizeof(other_status) / sizeof(*other_status); ++i) {
        char cause[48]; snprintf(cause, sizeof(cause), "unexpected status code: %d", other_status[i]);
        verify_one(d, (hop){.status = other_status[i], .body_error = "ignored"}, (hop){.status = 401, .body_error = "also ignored"}, true, false, NULL, cause, "CFuBBMUaASP");
    }
    verify_one(d, (hop){.status = 401, .body_error = "no error"}, (hop){.status = 401}, true, false, NULL, NULL, "CFuUaAP");
    verify_one(d, (hop){.status = 401}, (hop){.status = 200, .body_error = ""}, true, true, "account", NULL, "CFuUaAXP");
    verify_one(d, (hop){.status = 500, .body_error = "x"}, (hop){.status = 200}, true, true, "account", NULL, "CFuBBMUaAXP");
    verify_one(d, (hop){.status = 401}, (hop){.status = 201}, true, false, NULL, "unexpected status code: 201", "CFuUaBBMASP");
    verify_one(d, (hop){.status = 204}, (hop){.status = 299}, true, false, NULL, "unexpected status code: 204\nunexpected status code: 299", "CFuBBMUaBBMAMSP");
    char leaked[80]; snprintf(leaked, sizeof(leaked), "rejected %s", key);
    verify_one(d, (hop){.status = 401, .rc = 1, .error = leaked}, (hop){.status = 401}, true, false, NULL, leaked, "CFuUaASP");
    verify_one(d, (hop){.status = 200, .rc = -4, .error = "server down"}, (hop){.status = 200, .rc = 1, .error = "account down"}, true, false, NULL, "server down\naccount down", "CFuUaAMSP");
    verify_one(d, (hop){.status = 401, .rc = 1, .error = ""}, (hop){.status = 401}, true, false, NULL, "", "CFuUaASP");
    consume_nulls = 2; verify_one(d, (hop){.status = 200, .rc = 1, .error = "consumed"}, (hop){.status = 401, .rc = 1, .error = "also consumed"}, true, false, NULL, NULL, "CFuUaAP");
    consume_nulls = 1; verify_one(d, (hop){.status = 401, .rc = 1, .error = "consumed"}, (hop){.status = 500, .rc = 1, .error = "account leaf"}, true, false, NULL, "account leaf", "CFuUaASP");
}
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void nil_and_continuation(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "postmark %s postmark %s", key, other);
    size_t sent = sends, rel = releases, set = setters; nevents = 0; events[0] = 0; watch = true;
    br_results out = scan(d, NULL, true, text(input)); watch = false;
    CHECK(out.len == 2 && sends == sent && releases == rel && setters == set + 2 && !strcmp(events, "CFMSPFMSP"));
    expect_false(&out.items[0], key, "net/http: nil Context\nnet/http: nil Context");
    expect_false(&out.items[1], other, "net/http: nil Context\nnet/http: nil Context");
    br_results_clear(&out);
    sent = sends; out = scan(d, NULL, false, text(input));
    CHECK(out.len == 2 && sends == sent && !out.items[0].verification_error && !out.items[1].verification_error); br_results_clear(&out);
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http);
    const char *configured[] = {"https://ignored.invalid", "https://api.postmarkapp.com/deliverystats"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 2, .cloud = "https://cloud.invalid", .use_cloud = true, .use_found = true};
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "postmark-offline"};
    expected_agent = "TruffleHog postmark-offline";
    hop rows[] = {{.status = 401, .body_error = ""}, {.status = 500, .body_error = "x"}, {.status = 200, .body_error = "read"}};
    hops = rows; hop_len = 3; snprintf(input, sizeof(input), "postmark %s postmark %s", key, other);
    sent = sends; out = scan(d, &ctx, true, text(input)); hops = NULL; expected_agent = "TruffleHog";
    CHECK(out.len == 2 && sends == sent + 3 && http.calls == 3 && http.releases == 3 && hop_i == 3);
    expect_false(&out.items[0], key, "unexpected status code: 500"); expect_type(&out.items[1], other, "server"); br_results_clear(&out);
    size_t cancellations = 0;
    br_scan_ctx guards[] = {{.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    const char *guard_errors[] = {"context canceled\ncontext canceled", "context deadline exceeded\ncontext deadline exceeded", "invalid HTTP user agent\ninvalid HTTP user agent"};
    for (size_t i = 0; i < sizeof(guards) / sizeof(*guards); ++i) {
        sent = sends; http.calls = http.releases = 0; out = scan(d, &guards[i], true, text("postmark " "01234567-89ab-cdef-0123-456789abcdef"));
        CHECK(out.len == 1 && sends == sent + 2 && releases == sends && http.calls == 0 && http.releases == 2);
        expect_false(&out.items[0], key, guard_errors[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 2);
    br_scan_ctx bare = {0}; sent = sends; out = scan(d, &bare, true, text("postmark " "01234567-89ab-cdef-0123-456789abcdef"));
    CHECK(out.len == 1 && sends == sent + 2 && releases == sends);
    expect_false(&out.items[0], key, "HTTP transport not installed\nHTTP transport not installed"); br_results_clear(&out);
}
static void owned_failures(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "postmark %s\npostmark %s", key, other);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t which; int status; bool account; } cases[] = {
        {CAPTURE, 1, 200, false}, {FINDING, 1, 200, false}, {FINDING, 2, 200, false},
        {FORMAT_NEGATIVE, 1, 500, false}, {FORMAT_SHORT, 1, 201, false}, {FORMAT_PLUS, 2, 204, false}, {ALLOC, 1, 403, false},
        {EXTRA_OBJECT, 1, 200, false}, {EXTRA_STRING, 1, 401, true}, {EXTRA_ADD, 1, 500, true},
        {SETTER, 1, 500, true}, {PUSH, 1, 200, false}, {PUSH, 2, 401, true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        hop rows[] = {{.status = cases[i].status, .body_error = "ignored"}, {.status = cases[i].account && cases[i].status == 401 ? 200 : 401, .body_error = "ignored"}};
        if (cases[i].kind == EXTRA_ADD) rows[0].status = 401, rows[1].status = 200;
        if (cases[i].kind == SETTER) rows[1].status = 500;
        if (cases[i].kind == PUSH && cases[i].which == 2) rows[0].status = rows[1].status = 200;
        test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        hops = rows; hop_len = 2; hop_i = 0; scan_context = &ctx; verify_mode = true; collected = false; fault = cases[i].kind; nth = cases[i].which;
        size_t failed = injected, sent = sends; char *error = NULL;
        CHECK(d->scan(d, &ctx, true, text(cases[i].kind == CAPTURE ? "postmark" : input), &out, &error) == -1);
        CHECK(error && fault == NONE && injected == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(!provider_request && !active_result && sends == releases && (cases[i].kind == CAPTURE || (cases[i].kind == FINDING && cases[i].which == 1) ? sends == sent : sends > sent));
        free(error);
    }
    hops = NULL; fault = NONE;
    test_http http = {.inspect = inspect}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    hop rows[] = {{.status = 500, .rc = 1, .error = "server"}, {.status = 500, .rc = 1, .error = "account"}};
    hops = rows; hop_len = 2; hop_i = 0; fault = ALLOC; nth = 1; scan_context = &ctx; verify_mode = true; collected = false;
    size_t set = setters, extra = extras, failed = injected; char *error = NULL;
    CHECK(d->scan(d, &ctx, true, text("postmark " "01234567-89ab-cdef-0123-456789abcdef"), &out, &error) == -1 && error && fault == NONE);
    CHECK(injected == failed + 1 && setters == set && extras == extra && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)) && sends == releases);
    free(error); error = NULL; hops = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
int main(void)
{
    (void)forbidden_raw; (void)forbidden_find;
    const br_detector *d = descriptor();
    grammar(d); statuses(d); nil_and_continuation(d); owned_failures(d);
    CHECK(fault == NONE && sends == releases && !provider_request && !active_result && !consume_nulls && !watch && !hops);
    return test_finish("Postmark");
}
