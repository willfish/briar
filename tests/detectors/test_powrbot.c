/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <stdarg.h>

int br_powrbot_init(const br_detector **out, char **error);
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static char key[41], other[41], mixed[41];
typedef enum { NONE, COMPILE, CAPTURE, FINDING, FORMAT_NEGATIVE, FORMAT_SHORT, FORMAT_PLUS, FORMAT_TRUNCATED, PUSH } fault_kind;
static fault_kind fault;
static size_t fail_nth, injected, captures, findings, formats, sends, releases, pushes, setters;
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
    CHECK(count == 1 && keywords && !strcmp(keywords[0], "powrbot"));
    CHECK(!strcmp(capture, "\\b([a-z0-9A-Z]{40})\\b"));
    int rc = br_regex_compile_prefixed(keywords, count, capture, out, error);
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static int checked_capture(const br_regex *pattern, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && !active_result && !provider_request); ++captures; event('C'); collected = false;
    int rc = br_captures_find(pattern, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) return 1;
    collected = rc == 0; return rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice token, const char *part)
{
    CHECK(collected && !active_result && !provider_request && type == 243 && token.len == 40 && !strcmp(part, "key"));
    active_result = r; ++findings; event('F');
    int rc = br_finding_key_bytes(r, type, token, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r) { if (active_result == r) active_result = NULL; br_result_clear(r); }
static int checked_format(char *out, size_t capacity, const char *format, ...)
{
    CHECK(verify_mode && scan_context && active_result && collected && !provider_request);
    CHECK(capacity == 52 && !strcmp(format, "secret-key %.*s")); ++formats; event('A');
    va_list args; va_start(args, format); int n = vsnprintf(out, capacity, format, args); va_end(args);
    if (hit(FORMAT_NEGATIVE)) return -1;
    if (hit(FORMAT_SHORT)) return 1;
    if (hit(FORMAT_PLUS)) return n + 1;
    return hit(FORMAT_TRUNCATED) ? (int)capacity : n;
}
static int forbidden_setter(br_result *r, const char *message, const char *redacted, size_t n)
{
    (void)r; (void)message; (void)redacted; (void)n; ++setters; CHECK(false); return 1;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && active_result->raw.len == 40 && !active_result->verified);
    CHECK(!active_result->verification_error && !active_result->extra_data && !active_result->raw_v2.data);
    CHECK(r->detector_type == 243 && r->profile == BR_HTTP_SANE && !strcmp(r->method, "GET"));
    CHECK(!strcmp(r->url, "https://powrbot.com/api/v1/search/single/?company=Apple") && strlen(r->url) == 55);
    CHECK(!strstr(r->url, (const char *)active_result->raw.data));
    CHECK(strstr(r->url, "?company=Apple") == r->url + strlen(r->url) - strlen("?company=Apple"));
    CHECK(r->timeout_ms == (effective ? 5000u : 0u) && !r->body.data && !r->body.len);
    CHECK(!r->dedup_key.data && !r->dedup_key.len && r->nheaders == (effective ? 2u : 1u));
    CHECK(!strcmp(r->headers[0].name, "Authorization") && r->headers[0].value && strlen(r->headers[0].value) == 51);
    CHECK(!memcmp(r->headers[0].value, "secret-key ", 11) && !strchr(r->headers[0].value, ':'));
    CHECK(!memcmp(r->headers[0].value + 11, active_result->raw.data, 40));
    if (effective) CHECK(r->nheaders == 2 && !strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, expected_agent));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(ctx && ctx == scan_context && verify_mode && !provider_request); request_values(request, false);
    provider_request = request; provider_context = ctx; ++sends; event('H');
    int rc = br_http_send(ctx, request, response, error);
    if (consume_null && rc != 0) { free(*error); *error = NULL; }
    return rc;
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_context); request_values(provider_request, false);
    br_http_release(ctx, response); ++releases; event('R'); provider_request = NULL; provider_context = NULL;
}
static int checked_push(br_results *results, br_result *owned)
{
    CHECK(active_result == owned && collected && !provider_request && !owned->verification_error && !owned->extra_data);
    int rc = br_results_push(results, owned); ++pushes; event('P');
    return rc == 0 && hit(PUSH) ? 1 : rc;
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; CHECK(ctx == scan_context); request_values(r, true);
}

#define br_regex_compile_prefixed checked_compile
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_result_clear checked_clear
#define snprintf checked_format
#define br_result_set_verification_error forbidden_setter
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#include "../../src/detectors/powrbot.c"
#undef br_regex_compile_prefixed
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_result_clear
#undef snprintf
#undef br_result_set_verification_error
#undef br_http_send
#undef br_http_release
#undef br_results_push

static void result_is(const br_result *r, const char *token, bool verified)
{
    test_key_result(r, 243, token, "key");
    CHECK(r->verified == verified && !r->verification_error && !r->extra_data && !r->raw_v2.data);
}
static br_results scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input)
{
    collected = false; scan_context = ctx; verify_mode = verify; return test_scan(d, ctx, verify, input.data, input.len);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL; char *error = NULL;
    fault = COMPILE; fail_nth = 1;
    CHECK(br_powrbot_init(&d, &error) == -1 && error && !strcmp(error, "synthetic compile failure") && !d && fault == NONE);
    free(error); error = NULL;
    CHECK(br_powrbot_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_powrbot_init(&d, &error) == 0 && !error && d && d->state);
    CHECK(d->type == 243 && d->version == 0 && !strcmp(d->name, "Powrbot") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Powrbot is a service that provides company information. Powrbot API keys can be used to access and retrieve data from their database."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "powrbot"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    const br_detector *again = NULL; CHECK(br_powrbot_init(&again, &error) == 0 && again == d && !error);
    return d;
}
static void expect_none(const br_detector *d, const char *input)
{
    br_results out = scan(d, NULL, false, text(input)); CHECK(!out.len); br_results_clear(&out);
}
static void expect_one(const br_detector *d, const char *input, const char *token)
{
    br_results out = scan(d, NULL, false, text(input));
    CHECK(out.len == 1); result_is(&out.items[0], token, false); br_results_clear(&out);
}
static void grammar(const br_detector *d)
{
    char input[160], forty[41], short_key[40], long_key[42];
    test_secret(forty, 40, 3);
    snprintf(input, sizeof(input), "powrbot %s", key); expect_one(d, input, key);
    snprintf(input, sizeof(input), "POWRBOT\t%s", mixed); expect_one(d, input, mixed);
    snprintf(input, sizeof(input), "powrbot %s-", key); expect_one(d, input, key);
    snprintf(input, sizeof(input), "powrbot %s?", key); expect_one(d, input, key);
    memcpy(short_key, key, 39); short_key[39] = 0;
    snprintf(input, sizeof(input), "powrbot %s", short_key); expect_none(d, input);
    memcpy(long_key, key, 40); long_key[40] = 'A'; long_key[41] = 0;
    snprintf(input, sizeof(input), "powrbot %s", long_key); expect_none(d, input);
    long_key[40] = '9'; snprintf(input, sizeof(input), "powrbot %s", long_key); expect_none(d, input);
    long_key[40] = '_'; snprintf(input, sizeof(input), "powrbot %s", long_key); expect_none(d, input);
    snprintf(input, sizeof(input), "powrbot %.*s-%s", 20, key, key + 20); expect_none(d, input);
    snprintf(input, sizeof(input), "powrbot %.*s?%s", 20, key, key + 19); expect_none(d, input);
    snprintf(input, sizeof(input), "powrbot%*s%s", 40, "", key); expect_one(d, input, key);
    snprintf(input, sizeof(input), "powrbot%*s%s", 41, "", key); expect_none(d, input);
    snprintf(input, sizeof(input), "powrbot %s %s", key, other); expect_one(d, input, key);
    snprintf(input, sizeof(input), "powrbot %s powrbot %s", key, other);
    br_results out = scan(d, NULL, false, text(input));
    CHECK(out.len == 2); result_is(&out.items[0], key, false); result_is(&out.items[1], other, false); br_results_clear(&out);
    snprintf(input, sizeof(input), "powrbot %s\npowrbot %s", key, key);
    out = scan(d, NULL, false, text(input));
    CHECK(out.len == 2); result_is(&out.items[0], key, false); result_is(&out.items[1], key, false); br_results_clear(&out);
    (void)forty;
}
static void nil_and_request(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "powrbot %s powrbot %s", key, mixed);
    size_t sent = sends, auth = formats, published = pushes, made = findings;
    br_results out = scan(d, NULL, false, text(input));
    CHECK(out.len == 2 && sends == sent && formats == auth && !out.items[0].verified && !out.items[1].verified);
    result_is(&out.items[0], key, false); result_is(&out.items[1], mixed, false); br_results_clear(&out);
    CHECK(pushes == published + 2 && findings == made + 2);
    nevents = 0; events[0] = 0; watch = true; made = findings; published = pushes;
    out = scan(d, NULL, true, text(input)); watch = false;
    CHECK(!out.len && findings == made + 2 && pushes == published && sends == sent && formats == auth && !strcmp(events, "CFF"));
    br_results_clear(&out);
    fault = FORMAT_PLUS; fail_nth = 1;
    out = scan(d, NULL, true, text(input));
    CHECK(!out.len && fault == FORMAT_PLUS && formats == auth && sends == sent); br_results_clear(&out); fault = NONE;
    const char *configured[] = {"https://ignored.invalid"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .cloud = "https://cloud.invalid", .use_cloud = true, .use_found = true};
    test_http http = {.inspect = inspect, .response = {.status = 204, .body = TEXT("ignored"), .body_error = "ignored"}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "powrbot-offline"};
    expected_agent = "TruffleHog powrbot-offline";
    nevents = 0; events[0] = 0; watch = true; out = scan(d, &ctx, true, text(input)); watch = false;
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2 && !strcmp(events, "CFAHRPFAHRP"));
    result_is(&out.items[0], key, true); result_is(&out.items[1], mixed, true); br_results_clear(&out);
    expected_agent = "TruffleHog";
}
static br_results response(const br_detector *d, int status, br_slice body, const char *read, int send_rc, const char *send_error, bool consumed)
{
    test_http http = {.inspect = inspect, .response = {.status = status, .body = body, .body_error = read}, .send_rc = send_rc, .send_error = send_error};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    char input[64]; snprintf(input, sizeof(input), "powrbot %s", key);
    size_t sent = sends, released = releases, auth = formats; consume_null = consumed;
    nevents = 0; events[0] = 0; watch = true; br_results out = scan(d, &ctx, true, text(input)); watch = false; consume_null = false;
    CHECK(out.len == 1 && sends == sent + 1 && releases == released + 1 && formats == auth + 1 && http.calls == 1 && http.releases == 1);
    CHECK(!strcmp(events, "CFAHRP") && !setters); return out;
}
static void statuses_and_errors(const br_detector *d)
{
    const int statuses[] = {-1, 0, 199, 200, 201, 204, 250, 299, 300, 400, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        br_results out = response(d, statuses[i], TEXT("{\"ok\":false}"), "ignored body error", 0, NULL, false);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const char *leaves[] = {"timeout", "Post synthetic: explicit leaf", "", NULL};
    for (size_t i = 0; i < sizeof(leaves) / sizeof(*leaves); ++i) {
        br_results out = response(d, 204, TEXT("{bad"), "ignored", 1, leaves[i], false);
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
    char input[64]; snprintf(input, sizeof(input), "powrbot %s", key);
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
    char input[120]; snprintf(input, sizeof(input), "powrbot %s\npowrbot %s", key, other);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t nth; bool nil, nov; int send_rc; } cases[] = {
        {CAPTURE, 1, true, false, 0}, {FINDING, 1, true, false, 0}, {FINDING, 2, false, false, 0},
        {FORMAT_NEGATIVE, 1, false, false, 0}, {FORMAT_SHORT, 1, false, false, 0}, {FORMAT_PLUS, 1, false, false, 0},
        {FORMAT_TRUNCATED, 2, false, false, 0}, {PUSH, 1, false, false, 0}, {PUSH, 2, false, false, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.inspect = inspect, .response = {.status = 204}, .send_rc = cases[i].send_rc, .send_error = cases[i].send_rc ? "opaque preparation error" : NULL};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        scan_context = cases[i].nil ? NULL : &ctx; verify_mode = !cases[i].nov;
        fault = cases[i].kind; fail_nth = cases[i].nth;
        size_t failed = injected, sent = sends, released = releases, auth = formats; char *error = NULL;
        CHECK(d->scan(d, scan_context, verify_mode, text(input), &out, &error) == -1);
        CHECK(error && fault == NONE && injected == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !active_result && !provider_request && !setters);
        if (cases[i].nil || cases[i].kind == CAPTURE || (cases[i].kind == FINDING && cases[i].nth == 1)) CHECK(formats == auth);
        if (cases[i].kind == FORMAT_NEGATIVE || cases[i].kind == FORMAT_SHORT || cases[i].kind == FORMAT_PLUS) CHECK(sends == sent && releases == released);
        free(error);
    }
    fault = FINDING; fail_nth = 1; verify_mode = false; scan_context = NULL;
    CHECK(d->scan(d, NULL, false, text(input), &out, NULL) == -1 && fault == NONE);
    char *error = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error); error = NULL;
    br_detector invalid = *d; invalid.state = NULL;
    CHECK(d->scan(&invalid, NULL, false, text(input), &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
int main(void)
{
    (void)forbidden_setter;
    test_secret(key, 40, 1); key[0] = 'a'; key[39] = 'Z';
    test_secret(other, 40, 9); other[1] = 'Q';
    memcpy(mixed, key, sizeof(mixed)); mixed[2] = 'M'; mixed[10] = 'x'; mixed[20] = '7';
    const br_detector *d = descriptor(); grammar(d); nil_and_request(d); statuses_and_errors(d); preparation(d); owned_failures(d);
    CHECK(fault == NONE && sends == releases && !active_result && !provider_request && !setters && !consume_null && !watch);
    return test_finish("Powrbot");
}
