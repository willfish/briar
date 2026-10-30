/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <stdarg.h>

int br_nylas_init(const br_detector **out, char **error);
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static char key[31], other[31];
typedef enum { NONE, COMPILE, CAPTURE, FINDING, FORMAT_NEGATIVE, FORMAT_SHORT, FORMAT_TRUNCATED, PUSH } fault_kind;
static fault_kind fault;
static size_t fail_nth, injected, freed_patterns, captures, findings, formats, sends, releases, pushes, setters;
static bool collected, verify_mode, consume_null, watch;
static br_result *active_result;
static const br_scan_ctx *scan_context, *provider_context;
static const br_http_request *provider_request;
static const char *expected_agent = "TruffleHog";
static char events[160];
static size_t nevents;
static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE; ++injected; return true;
}
static void event(char c)
{
    if (!watch) return;
    CHECK(nevents + 1 < sizeof(events)); events[nevents++] = c; events[nevents] = 0;
}
static int checked_compile(const char *const *keywords, size_t count, const char *capture, br_regex **out, char **error)
{
    CHECK(count == 1 && !strcmp(keywords[0], "nylas") && !strcmp(capture, "\\b([0-9A-Za-z]{30})\\b"));
    int rc = br_regex_compile_prefixed(keywords, count, capture, out, error);
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static void checked_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *pattern, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && !active_result && !provider_request); ++captures; event('C'); collected = false;
    int rc = br_captures_find(pattern, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) return 1;
    collected = rc == 0; return rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice token, const char *part)
{
    CHECK(collected && !active_result && !provider_request && type == 617 && token.len == 30);
    active_result = r; ++findings; event('F');
    int rc = br_finding_key_bytes(r, type, token, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r) { if (active_result == r) active_result = NULL; br_result_clear(r); }
static int checked_format(char *out, size_t capacity, const char *format, ...)
{
    CHECK(active_result && collected && verify_mode && scan_context && !provider_request);
    CHECK(capacity == 38 && !strcmp(format, "Bearer %.*s")); ++formats; event('A');
    va_list args; va_start(args, format); int n = vsnprintf(out, capacity, format, args); va_end(args);
    if (hit(FORMAT_NEGATIVE)) return -1;
    if (hit(FORMAT_SHORT)) return 1;
    return hit(FORMAT_TRUNCATED) ? (int)capacity : n;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && active_result->raw.len == 30 && !active_result->verified && !active_result->verification_error && !active_result->extra_data);
    CHECK(r->detector_type == 617 && r->profile == BR_HTTP_SANE && !strcmp(r->method, "GET"));
    CHECK(!strcmp(r->url, "https://api.nylas.com/account") && r->timeout_ms == (effective ? 5000u : 0u));
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len && r->nheaders == (effective ? 3u : 2u));
    CHECK(!strcmp(r->headers[0].name, "Accept") && !strcmp(r->headers[0].value, "application/vnd.nylas+json; version=3"));
    CHECK(!strcmp(r->headers[1].name, "Authorization") && strlen(r->headers[1].value) == 37 && !memcmp(r->headers[1].value, "Bearer ", 7));
    CHECK(!memcmp(r->headers[1].value + 7, active_result->raw.data, 30));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(ctx && ctx == scan_context && verify_mode && !provider_request); request_values(request, false);
    provider_request = request; provider_context = ctx; ++sends; event('H');
    int rc = br_http_send(ctx, request, response, error);
    /* Explicit consumed component tuple, separate from the real shared backend
     * fallback. Provider suppression must not depend on nullable diagnostics. */
    if (consume_null && rc != 0) { free(*error); *error = NULL; }
    return rc;
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_context); request_values(provider_request, false);
    /* ORIGINAL provider request/Bearer/header/key only; no expired prepared
     * header array or synthesized UA is retained after ordinary send return. */
    br_http_release(ctx, response); ++releases; event('R'); provider_request = NULL; provider_context = NULL;
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(active_result == r && collected && !provider_request && sends == releases); ++pushes; event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
static int forbidden_setter(br_result *r, const char *cause, const br_slice *secrets, size_t count)
{
    (void)r; (void)cause; (void)secrets; (void)count; ++setters; CHECK(false); return 1;
}
#define br_regex_compile_prefixed checked_compile
#define br_regex_free checked_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_result_clear checked_clear
#define snprintf checked_format
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#include "../../src/detectors/nylas.c"
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_result_clear
#undef snprintf
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_result_set_verification_error

static br_results scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input)
{
    verify_mode = verify; scan_context = ctx; return test_scan(d, ctx, verify, input.data, input.len);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 30 && strlen(other) == 30);
    CHECK(br_nylas_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_nylas_init(NULL, NULL) == -1); fault = COMPILE; fail_nth = 1;
    CHECK(br_nylas_init(&d, &error) == -1 && !d && error && fault == NONE && freed_patterns == 1); free(error); error = NULL;
    CHECK(!br_nylas_init(&d, &error) && d && !error && !br_nylas_init(&again, NULL) && again == d);
    CHECK(d->type == 617 && d->version == 0 && !strcmp(d->name, "Nylas") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Nylas is a platform providing email, calendar, and contacts APIs. Nylas API keys can be used to access and manage these services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nylas") && d->state && d->scan);
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result_is(const br_result *r, const char *token, bool verified)
{
    test_key_result(r, 617, token, "key"); CHECK(r->verified == verified && !r->verification_error);
}
static void extract(const br_detector *d, br_slice input, const char *token)
{
    size_t sent = sends, auth = formats, set = setters;
    br_results out = scan(d, NULL, false, input);
    CHECK(out.len == (token ? 1u : 0u) && sends == sent && formats == auth && setters == set);
    if (token) result_is(&out.items[0], token, false);
    CHECK(!active_result); br_results_clear(&out);
}
static void grammar(const br_detector *d)
{
    char input[500], changed[31];
    const char *good[] = {"nylas %s", "NYLAS = '%s'", "xnylas:%s-", "nylas é%sé", "nylas nylas %s"};
    const char *bad[] = {"%s", "nylas%s", "nylas x%s", "nylas _%s", "nylas %s_", "nylas %sZ", "nylas %.29s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extract(d, text(input), key); }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extract(d, text(input), NULL); }
    const char invalid[] = "_-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { strcpy(changed, key); changed[15] = invalid[i]; snprintf(input, sizeof(input), "nylas %s", changed); extract(d, text(input), NULL); }
    memset(changed, 'A', 30); changed[30] = 0; snprintf(input, sizeof(input), "nylas %s", changed); extract(d, text(input), changed);
    memset(changed, '0', 30); snprintf(input, sizeof(input), "nylas %s", changed); extract(d, text(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "nylas", 5); memset(input + 5, '.', gap); memcpy(input + 5 + gap, key, 30);
        extract(d, (br_slice){(const unsigned char *)input, 5 + gap + 30}, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) { input[5 + 2 * i] = (char)0xc3; input[6 + 2 * i] = (char)0xa9; }
        memcpy(input + 5 + gap * 2, key, 30);
        extract(d, (br_slice){(const unsigned char *)input, 5 + gap * 2 + 30}, gap == 40 ? key : NULL);
    }
    memcpy(input, "nylas", 5); memset(input + 5, '.', 37); input[42] = '\r'; input[43] = '\n'; input[44] = 0; memcpy(input + 45, key, 30);
    extract(d, (br_slice){(const unsigned char *)input, 75}, key);
    snprintf(input, sizeof(input), "nylas %s %s", key, other); extract(d, text(input), key);
    extract(d, (br_slice){0}, NULL);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; CHECK(ctx == provider_context && provider_request); request_values(r, true);
    CHECK(!strcmp(r->headers[2].name, "User-Agent") && !strcmp(r->headers[2].value, expected_agent));
}
static void occurrences_nil_options(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "nylas %s\nnylas %s\nnylas %s", key, other, key);
    const char *expected[] = {key, other, key}; size_t sent = sends, auth = formats, published = pushes, made = findings;
    br_results out = scan(d, NULL, false, text(input)); CHECK(out.len == 3 && sends == sent && formats == auth);
    for (size_t i = 0; i < out.len; ++i) result_is(&out.items[i], expected[i], false);
    br_results_clear(&out); CHECK(pushes == published + 3 && findings == made + 3);
    made = findings; published = pushes; nevents = 0; events[0] = 0; watch = true;
    out = scan(d, NULL, true, text(input)); watch = false;
    CHECK(!out.len && findings == made + 3 && pushes == published && sends == sent && formats == auth && !strcmp(events, "CFFF")); br_results_clear(&out);
    /* Unreached header failures MUST NOT turn nil constructor drops into
     * formatting, HTTP work or failure. */
    fault = FORMAT_SHORT; fail_nth = 1; out = scan(d, NULL, true, text(input));
    CHECK(!out.len && fault == FORMAT_SHORT && formats == auth); br_results_clear(&out); fault = NONE;
    const char *configured[] = {"https://ignored.invalid"}; br_endpoints endpoints = {.configured = configured, .nconfigured = 1};
    test_http http = {.inspect = inspect, .response = {.status = 299}}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "nylas-offline"}; expected_agent = "TruffleHog nylas-offline";
    nevents = 0; events[0] = 0; watch = true; out = scan(d, &ctx, true, text(input)); watch = false;
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3 && !strcmp(events, "CFAHRPFAHRPFAHRP"));
    for (size_t i = 0; i < out.len; ++i) result_is(&out.items[i], expected[i], true);
    br_results_clear(&out); expected_agent = "TruffleHog";
}
static br_results response(const br_detector *d, int status, br_slice body, const char *read,
                            int send_rc, const char *send_error, bool consumed)
{
    test_http http = {.inspect = inspect, .response = {.status = status, .body = body, .body_error = read}, .send_rc = send_rc, .send_error = send_error};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; char input[40]; snprintf(input, sizeof(input), "nylas %s", key);
    size_t sent = sends, released = releases, auth = formats; consume_null = consumed;
    nevents = 0; events[0] = 0; watch = true; br_results out = scan(d, &ctx, true, text(input)); watch = false; consume_null = false;
    CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && formats == auth + 1 && http.calls == 1 && http.releases == 1);
    CHECK(!strcmp(events, "CFAHRP") && !setters); return out;
}
static void statuses_and_errors(const br_detector *d)
{
    const int statuses[] = {-1, 0, 199, 200, 201, 202, 204, 250, 299, 300, 400, 401, 403, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        br_results out = response(d, statuses[i], (br_slice){NULL, SIZE_MAX}, "ignored read/close failure", 0, "ignored success diagnostic", false);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *leaves[] = {"timeout", "out of memory constructing HTTP headers", "cannot format Nylas authorization", "Post synthetic: explicit leaf", "", NULL};
    for (size_t i = 0; i < sizeof(leaves) / sizeof(*leaves); ++i) {
        br_results out = response(d, 204, TEXT("{bad"), "ignored", i % 2 ? -7 : 1, leaves[i], false);
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    br_results out = response(d, 200, TEXT("{}"), NULL, 1, "explicitly consumed cause", true);
    result_is(&out.items[0], key, false); br_results_clear(&out);
}
static bool cancelled(void *u) { ++*(size_t *)u; return true; }
static void preparation(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    char input[40]; snprintf(input, sizeof(input), "nylas %s", key);
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t sent = sends, auth = formats, released = releases; http.calls = http.releases = 0;
        br_results out = scan(d, &contexts[i], false, text(input)); CHECK(out.len == 1 && sends == sent && formats == auth); br_results_clear(&out);
        out = scan(d, &contexts[i], true, text(input));
        CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && formats == auth + 1 && !http.calls && http.releases == (i ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1 && !setters);
}
static void owned_failures(const br_detector *d)
{
    char input[100]; snprintf(input, sizeof(input), "nylas %s\nnylas %s", key, other);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t nth; bool nil, nov; int send_rc; } cases[] = {
        {CAPTURE,1,true,false,0}, {CAPTURE,1,true,true,0}, {FINDING,1,true,false,0}, {FINDING,2,true,false,0},
        {FINDING,2,true,true,0}, {FINDING,2,false,false,1},
        {FORMAT_NEGATIVE,1,false,false,0}, {FORMAT_NEGATIVE,2,false,false,0},
        {FORMAT_SHORT,1,false,false,0}, {FORMAT_SHORT,2,false,false,1}, {FORMAT_TRUNCATED,2,false,false,0},
        {PUSH,1,false,false,0}, {PUSH,2,false,false,0}, {PUSH,2,false,false,1}, {PUSH,2,true,true,0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.inspect = inspect, .response = {.status = 204}, .send_rc = cases[i].send_rc, .send_error = cases[i].send_rc ? "opaque preparation/Do error" : NULL};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        scan_context = cases[i].nil ? NULL : &ctx; verify_mode = !cases[i].nov;
        fault = cases[i].kind; fail_nth = cases[i].nth;
        size_t failed = injected, sent = sends, released = releases, made = findings, auth = formats; char *error = NULL;
        CHECK(d->scan(d, scan_context, verify_mode, text(input), &out, &error) == -1);
        CHECK(error && fault == NONE && injected == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !active_result && !provider_request && !setters);
        if (cases[i].nil || cases[i].nov) CHECK(sends == sent && formats == auth);
        if (cases[i].kind == CAPTURE) CHECK(findings == made);
        free(error);
    }
    fault = FINDING; fail_nth = 1; verify_mode = false; scan_context = NULL;
    CHECK(d->scan(d, NULL, false, text(input), &out, NULL) == -1 && fault == NONE);
    char *error = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL,1}, &out, &error) == -1 && error); free(error); error = NULL;
    br_detector invalid = *d; invalid.state = NULL;
    CHECK(d->scan(&invalid, NULL, false, text(input), &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
int main(void)
{
    (void)forbidden_setter;
    test_secret(key, 30, 0); key[0] = 'A'; key[9] = 'X'; key[29] = 'Z'; test_secret(other, 30, 7); other[0] = 'Q';
    const br_detector *d = descriptor(); grammar(d); occurrences_nil_options(d); statuses_and_errors(d); preparation(d); owned_failures(d);
    CHECK(fault == NONE && sends == releases && !active_result && !provider_request && !setters && !consume_null && !watch);
    return test_finish("Nylas");
}
