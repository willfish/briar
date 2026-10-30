/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <stdarg.h>

int br_nvapi_init(const br_detector **out, char **error);
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static char key[71], other[71];
typedef enum { NONE, COMPILE, CAPTURE, FINDING, CAUSE, FORMAT, TRUNCATE, SETTER, PUSH } fault_kind;
static fault_kind fault;
static size_t fail_nth, failures, freed_patterns, captures, findings, sends, releases, setters, null_setters, causes, formats;
static bool collection_done, verify_mode, current_set, wanted_verified, consume_null, watch;
static br_result *active_result;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_ctx;
static const char *expected_agent = "TruffleHog";
static char events[160];
static size_t nevents;
static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE; ++failures; return true;
}
static void event(char c)
{
    if (!watch) return;
    CHECK(nevents + 1 < sizeof(events)); events[nevents++] = c; events[nevents] = 0;
}
/* Existing named-test local seams: synthetic raw responses and explicit
 * component statuses, never an SDK/provider verdict or native test backend. */
static int checked_compile(const char *pattern, br_regex **out, char **error)
{
    CHECK(!strcmp(pattern, "\\b(nvapi-[a-zA-Z0-9_-]{64})\\b"));
    int rc = br_regex_compile(pattern, out, error);
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static void checked_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *pattern, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(unique && !active_result && !provider_request); ++captures; event('C'); collection_done = false;
    int rc = br_captures_find(pattern, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) return 1;
    collection_done = rc == 0; return rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice token, const char *part)
{
    CHECK(collection_done && !active_result && !provider_request && token.len == 70);
    active_result = r; current_set = false; ++findings; event('F');
    int rc = br_finding_key_bytes(r, type, token, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r) { if (r == active_result) active_result = NULL; br_result_clear(r); }
static char *checked_strdup(const char *message)
{
    if (!strcmp(message, "net/http: nil Context")) CHECK(active_result && verify_mode && !provider_request);
    if (!strncmp(message, "unexpected HTTP response status ", 32)) CHECK(active_result && provider_request);
    ++causes; event('D'); return hit(CAUSE) ? NULL : strdup(message);
}
static int checked_format(char *out, size_t capacity, const char *format, ...)
{
    CHECK(active_result && provider_request && !strcmp(format, "unexpected HTTP response status %d")); ++formats; event('T');
    va_list args; va_start(args, format); int n = vsnprintf(out, capacity, format, args); va_end(args);
    if (hit(FORMAT)) return -1;
    return hit(TRUNCATE) ? (int)capacity : n;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && active_result->raw.len == 70 && !active_result->verified && !active_result->extra_data && !active_result->verification_error);
    CHECK(r->detector_type == 997 && r->profile == BR_HTTP_SANE && !strcmp(r->method, "POST"));
    CHECK(!strcmp(r->url, "https://api.ngc.nvidia.com/v3/keys/get-caller-info") && r->timeout_ms == (effective ? 5000u : 0u));
    CHECK(!r->dedup_key.data && !r->dedup_key.len && r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(r->body.data && r->body.len == 82 && !memcmp(r->body.data, "credentials=", 12));
    CHECK(!memcmp(r->body.data + 12, active_result->raw.data, 70));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(ctx && !provider_request && verify_mode); request_values(request, false);
    provider_request = request; provider_ctx = ctx; ++sends; event('H');
    int rc = br_http_send(ctx, request, response, error);
    /* Explicit consumed component tuple, after the actual shared adapter. Its
     * ordinary backend fallback is a DIFFERENT tested case, not provider policy. */
    if (consume_null && rc != 0) { free(*error); *error = NULL; }
    return rc;
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_ctx && !current_set); request_values(provider_request, false);
    /* ORIGINAL provider request/body/type/URL/key only. Prepared headers/UA
     * have already expired at ordinary send return and are never retained. */
    br_http_release(ctx, response); ++releases; event('R'); provider_request = NULL; provider_ctx = NULL;
}
static int checked_setter(br_result *r, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(verify_mode && r == active_result && !provider_request && sends == releases && !current_set);
    CHECK(r->verified == wanted_verified && !r->extra_data && secrets && count == 1 && secrets[0].len == 70);
    CHECK(!memcmp(secrets[0].data, r->raw.data, 70)); current_set = true; ++setters; if (!cause) ++null_setters; event('S');
    return hit(SETTER) ? 1 : br_result_set_verification_error(r, cause, secrets, count);
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(r == active_result && !provider_request && sends == releases && current_set == verify_mode); event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
#define br_regex_compile checked_compile
#define br_regex_free checked_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_result_clear checked_clear
#define strdup checked_strdup
#define snprintf checked_format
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#include "../../src/detectors/nvapi.c"
#undef br_regex_compile
#undef br_regex_free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_result_clear
#undef strdup
#undef snprintf
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push

static br_results scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input)
{
    verify_mode = verify; return test_scan(d, ctx, verify, input.data, input.len);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 70 && strlen(other) == 70);
    CHECK(br_nvapi_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_nvapi_init(NULL, NULL) == -1); fault = COMPILE; fail_nth = 1;
    CHECK(br_nvapi_init(&d, &error) == -1 && !d && error && fault == NONE && freed_patterns == 1); free(error); error = NULL;
    CHECK(!br_nvapi_init(&d, &error) && d && !error && !br_nvapi_init(&again, NULL) && again == d);
    CHECK(d->type == 997 && d->version == 0 && !strcmp(d->name, "NVAPI") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "NVAPI keys are used to authenticate API requests to NVIDIA's NGC API. They allow access to NVIDIA's NGC API to manage user data and perform actions on behalf of users."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nvapi-") && d->state && d->scan);
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result_is(const br_result *r, const char *token, bool verified, const char *cause)
{
    test_key_result(r, 997, token, "key"); CHECK(r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}
static void extract(const br_detector *d, br_slice input, const char *token)
{
    size_t sent = sends, set = setters, dup = causes, fmt = formats;
    br_results out = scan(d, NULL, false, input);
    CHECK(out.len == (token ? 1u : 0u) && sends == sent && setters == set && causes == dup && formats == fmt);
    if (token) result_is(&out.items[0], token, false, NULL);
    CHECK(!active_result); br_results_clear(&out);
}
static void grammar(const br_detector *d)
{
    char input[300], changed[72];
    const char *good[] = {"%s", "'%s'", "-%s-", "x %s y", "é%sé", "%s-"};
    const char *bad[] = {"x%s", "_%s", "%s_", "%sZ", "%.69s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extract(d, text(input), key); }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extract(d, text(input), NULL); }
    strcpy(changed, key); changed[0] = 'N'; extract(d, text(changed), NULL);
    const char invalid[] = "+/=. ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { strcpy(changed, key); changed[30] = invalid[i]; extract(d, text(changed), NULL); }
    strcpy(changed, key); changed[69] = '-'; extract(d, text(changed), NULL);
    snprintf(input, sizeof(input), "%sX", changed); extract(d, text(input), changed);
    snprintf(input, sizeof(input), "%s_", changed); extract(d, text(input), changed);
    snprintf(input, sizeof(input), "%s ", changed); extract(d, text(input), NULL);
    memcpy(changed, "nvapi-", 6); memset(changed + 6, '-', 64); changed[70] = 0;
    snprintf(input, sizeof(input), "%sX", changed); extract(d, text(input), changed);
    memset(changed + 6, '_', 64); extract(d, text(changed), changed);
    memcpy(input, key, 70); input[70] = 0; input[71] = 'x'; extract(d, (br_slice){(const unsigned char *)input, 72}, key);
    extract(d, (br_slice){0}, NULL);
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; CHECK(provider_request && ctx == provider_ctx); request_values(r, true);
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, expected_agent));
}
static br_results response(const br_detector *d, int status, br_slice body, const char *read, int send_rc,
                            const char *send_error, bool consumed, bool verified)
{
    wanted_verified = verified; consume_null = consumed;
    test_http http = {.inspect = inspect, .response = {.status = status, .body = body, .body_error = read}, .send_rc = send_rc, .send_error = send_error};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t sent = sends, released = releases, set = setters;
    nevents = 0; events[0] = 0; watch = true; br_results out = scan(d, &ctx, true, text(key)); watch = false; consume_null = false;
    CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && setters == set + 1 && http.calls == 1 && http.releases == 1);
    CHECK(!strcmp(events, send_rc || status == 200 || status == 401 ? "CFHRSP" : "CFHTDRSP"));
    return out;
}
static void statuses_and_errors(const br_detector *d)
{
    const int statuses[] = {-1, 0, 199, 200, 201, 202, 204, 299, 300, 400, 401, 403, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char cause[100]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        size_t nulls = null_setters; bool ordinary_null = statuses[i] == 200 || statuses[i] == 401;
        br_results out = response(d, statuses[i], (br_slice){NULL, SIZE_MAX}, "ignored read/drain failure", 0, "ignored success diagnostic", false, statuses[i] == 200);
        result_is(&out.items[0], key, statuses[i] == 200, ordinary_null ? NULL : cause);
        CHECK(null_setters == nulls + (ordinary_null ? 1u : 0u)); br_results_clear(&out);
    }
    const char *leaves[] = {"timeout", "out of memory constructing HTTP headers", "cannot allocate NVAPI verification cause", "Post synthetic: literal leaf prefix", "", NULL};
    for (size_t i = 0; i < sizeof(leaves) / sizeof(*leaves); ++i) {
        br_results out = response(d, 200, TEXT("{bad"), "ignored", i % 2 ? -7 : 1, leaves[i], false, false);
        result_is(&out.items[0], key, false, leaves[i] ? leaves[i] : "HTTP transport failed"); br_results_clear(&out);
    }
    size_t nulls = null_setters;
    br_results out = response(d, 200, TEXT("{}"), NULL, 1, "consumed component cause", true, false);
    result_is(&out.items[0], key, false, NULL); CHECK(null_setters == nulls + 1); br_results_clear(&out);
    char message[300], expected[200];
    snprintf(message, sizeof(message), "full=%s twice=%s suffix=%s", key, key, key + 6);
    snprintf(expected, sizeof(expected), "full=[REDACTED] twice=[REDACTED] suffix=%s", key + 6);
    out = response(d, 401, TEXT(""), NULL, 1, message, false, false); result_is(&out.items[0], key, false, expected); br_results_clear(&out);
}
static void unique_nil_and_options(const br_detector *d)
{
    char input[400]; snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", key, other, key, other);
    br_results out = scan(d, NULL, false, text(input)); CHECK(out.len == 2);
    bool found[2] = {false,false};
    for (size_t i = 0; i < out.len; ++i) { size_t at = !memcmp(out.items[i].raw.data, key, 70) ? 0 : 1; CHECK(!found[at]); found[at] = true; result_is(&out.items[i], at ? other : key, false, NULL); }
    CHECK(found[0] && found[1]); br_results_clear(&out);
    size_t sent = sends, released = releases, set = setters; wanted_verified = false;
    nevents = 0; events[0] = 0; watch = true; out = scan(d, NULL, true, text(input)); watch = false;
    CHECK(out.len == 2 && sends == sent && releases == released && setters == set + 2 && !strcmp(events, "CFDSPFDSP"));
    for (size_t i = 0; i < out.len; ++i) result_is(&out.items[i], !memcmp(out.items[i].raw.data, key, 70) ? key : other, false, "net/http: nil Context");
    br_results_clear(&out);
    const char *configured[] = {"https://ignored.invalid"}; br_endpoints endpoints = {.configured = configured, .nconfigured = 1};
    test_http http = {.inspect = inspect, .response = {.status = 200}}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "nvapi-offline"}; expected_agent = "TruffleHog nvapi-offline"; wanted_verified = true;
    out = scan(d, &ctx, true, text(input)); CHECK(out.len == 2 && http.calls == 2 && http.releases == 2);
    for (size_t i = 0; i < out.len; ++i) CHECK(out.items[i].verified && !out.items[i].verification_error);
    br_results_clear(&out);
    char tail[71]; strcpy(tail, key); tail[69] = '-'; snprintf(input, sizeof(input), "%sX", tail);
    out = scan(d, &ctx, true, text(input)); CHECK(out.len == 1 && http.calls == 3 && http.releases == 3);
    result_is(&out.items[0], tail, true, NULL); br_results_clear(&out); expected_agent = "TruffleHog";
}
static bool cancelled(void *u) { ++*(size_t *)u; return true; }
static void preparation(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    wanted_verified = false;
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t sent = sends, released = releases, set = setters; http.calls = http.releases = 0;
        br_results out = scan(d, &contexts[i], false, text(key)); CHECK(out.len == 1 && sends == sent && setters == set); br_results_clear(&out);
        out = scan(d, &contexts[i], true, text(key));
        CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && setters == set + 1 && !http.calls && http.releases == (i ? 1u : 0u));
        result_is(&out.items[0], key, false, causes[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void owned_failures(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "%s\n%s", key, other);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t nth; int status, send_rc; bool consumed, nil, nov; } cases[] = {
        {CAPTURE,1,200,0,false,true,true}, {CAPTURE,1,200,0,false,true,false},
        {FINDING,1,200,0,false,true,false}, {FINDING,2,200,0,false,false,false},
        {FINDING,2,200,0,false,true,true}, {CAUSE,1,200,0,false,true,false}, {CAUSE,2,200,0,false,true,false},
        {CAUSE,1,500,0,false,false,false}, {CAUSE,2,500,0,false,false,false},
        {FORMAT,1,500,0,false,false,false}, {FORMAT,2,500,0,false,false,false}, {TRUNCATE,1,500,0,false,false,false},
        {SETTER,1,200,0,false,false,false}, {SETTER,2,200,0,false,false,false}, {SETTER,2,401,0,false,false,false},
        {SETTER,2,200,1,true,false,false}, {SETTER,2,200,1,false,false,false}, {SETTER,2,200,0,false,true,false},
        {SETTER,2,500,0,false,false,false},
        {PUSH,1,200,0,false,false,false}, {PUSH,2,200,0,false,false,false}, {PUSH,2,200,0,false,true,true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.inspect = inspect, .response = {.status = cases[i].status}, .send_rc = cases[i].send_rc, .send_error = cases[i].send_rc ? "opaque leaf" : NULL};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        wanted_verified = !cases[i].nil && !cases[i].send_rc && cases[i].status == 200; consume_null = cases[i].consumed;
        verify_mode = !cases[i].nov; fault = cases[i].kind; fail_nth = cases[i].nth;
        size_t sent = sends, released = releases, failed = failures, made = findings, set = setters; char *error = NULL;
        CHECK(d->scan(d, cases[i].nil ? NULL : &ctx, verify_mode, text(input), &out, &error) == -1);
        CHECK(error && fault == NONE && failures == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !provider_request && !active_result);
        if (cases[i].nil || cases[i].nov) CHECK(sends == sent);
        if (cases[i].kind == CAPTURE) CHECK(findings == made && setters == set);
        free(error); consume_null = false;
    }
    fault = FINDING; fail_nth = 1; verify_mode = false;
    CHECK(d->scan(d, NULL, false, text(key), &out, NULL) == -1 && fault == NONE);
    char *error = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL,1}, &out, &error) == -1 && error); free(error); error = NULL;
    br_detector invalid = *d; invalid.state = NULL;
    CHECK(d->scan(&invalid, NULL, false, text(key), &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
int main(void)
{
    memcpy(key, "nvapi-", 6); test_secret(key + 6, 64, 0); key[6] = 'A'; key[23] = '_'; key[35] = '-'; key[69] = 'Z';
    memcpy(other, "nvapi-", 6); test_secret(other + 6, 64, 7); other[6] = 'Q';
    const br_detector *d = descriptor(); grammar(d); statuses_and_errors(d); unique_nil_and_options(d); preparation(d); owned_failures(d);
    CHECK(fault == NONE && sends == releases && !active_result && !provider_request && !consume_null && !watch);
    return test_finish("NVAPI");
}
