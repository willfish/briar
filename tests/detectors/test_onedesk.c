/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/email_pattern.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>
#include <stdarg.h>

int br_onedesk_init(const br_detector **out, char **error);
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static const char email[] = "Case.User@Example.COM";
static char password[17], second[17];
static const unsigned char marker[] = "\"code\":\"SUCCESS\"";
typedef enum { NONE, COMPILE_EMAIL, COMPILE_PASSWORD, CAPTURE, FINDING, ALLOCATE, FORMAT_NEGATIVE, FORMAT_SHORT, FORMAT_TRUNCATED, PUSH } fault_kind;
static fault_kind fault;
static size_t nth, injected, freed_patterns, capture_step, captures, findings, allocations, payload_frees, formats, sends, releases, pushes, setters, searches;
static const br_regex *email_regex, *password_regex;
static bool collected, verify_mode, watch, consume_null, record;
static br_result *active_result;
static unsigned char *live_payload;
static size_t payload_capacity, current_email_len, current_password_len;
static const char *current_email, *current_password;
static const br_scan_ctx *scan_context, *provider_context;
static const br_http_request *provider_request;
static br_http_response observed;
static int observed_send;
static const char *expected_agent = "TruffleHog";
static char events[200], seen_email[16][256], seen_password[16][65];
static size_t nevents, nseen;
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
static int checked_email_compile(const char *pattern, br_regex **out, char **error)
{
    CHECK(strlen(pattern) == 462 && !strcmp(pattern, br_email_pattern)); event('e');
    int rc = br_regex_compile(pattern, out, error);
    if (rc == 0) email_regex = *out;
    if (rc == 0 && hit(COMPILE_EMAIL)) { if (error) *error = strdup("synthetic email compile failure"); return 1; }
    return rc;
}
static int checked_password_compile(const char *const *keys, size_t count, const char *capture, br_regex **out, char **error)
{
    CHECK(email_regex && count == 1 && !strcmp(keys[0], "onedesk") && !strcmp(capture, "\\b([a-zA-Z0-9!=@#$%^]{8,64})")); event('w');
    int rc = br_regex_compile_prefixed(keys, count, capture, out, error);
    if (rc == 0) password_regex = *out;
    if (rc == 0 && hit(COMPILE_PASSWORD)) { if (error) *error = strdup("synthetic password compile failure"); return 1; }
    return rc;
}
static void checked_regex_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *r, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!active_result && !live_payload && !provider_request && capture_step < 2);
    CHECK(capture_step ? r == email_regex && unique : r == password_regex && !unique);
    event(capture_step ? 'E' : 'W'); ++capture_step; ++captures; collected = false;
    int rc = br_captures_find(r, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) return 1;
    collected = rc == 0 && capture_step == 2; return rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice key, const char *part)
{
    CHECK(collected && capture_step == 2 && !active_result && !live_payload && !provider_request && type == 601);
    active_result = r; ++findings; event('F');
    int rc = br_finding_key_bytes(r, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static void checked_clear(br_result *r)
{
    if (r == active_result) { CHECK(!live_payload && !provider_request); active_result = NULL; current_email = current_password = NULL; }
    br_result_clear(r);
}
static void *checked_malloc(size_t size)
{
    CHECK(active_result && verify_mode && collected && !live_payload && !provider_request); ++allocations; event('A');
    if (hit(ALLOCATE)) return NULL;
    live_payload = malloc(size); CHECK(live_payload); payload_capacity = size; return live_payload;
}
static void checked_free(void *p)
{
    if (p && p == live_payload) { CHECK(!provider_request && active_result); ++payload_frees; event('X'); live_payload = NULL; }
    free(p);
}
static int checked_format(char *out, size_t capacity, const char *format, ...)
{
    CHECK(active_result && verify_mode && collected && (unsigned char *)out == live_payload && capacity == payload_capacity && !provider_request);
    CHECK(!strcmp(format, "{\"email\": \"%.*s\", \"password\": \"%.*s\"}")); ++formats; event('B');
    va_list args, inspect; va_start(args, format); va_copy(inspect, args);
    int elen = va_arg(inspect, int); const char *e = va_arg(inspect, const char *);
    int plen = va_arg(inspect, int); const char *p = va_arg(inspect, const char *); va_end(inspect);
    CHECK(elen > 0 && (size_t)elen == active_result->raw.len && plen >= 8 && plen <= 64);
    CHECK(!memcmp(e, active_result->raw.data, (size_t)elen) && capacity == 30 + (size_t)elen + (size_t)plen);
    int n = vsnprintf(out, capacity, format, args); va_end(args);
    CHECK(n >= 0 && (size_t)n == capacity - 1 && !memcmp(out, "{\"email\": \"", 11));
    CHECK(!memcmp(out + 11, e, (size_t)elen) && !memcmp(out + 11 + elen, "\", \"password\": \"", 16));
    CHECK(!memcmp(out + 27 + elen, p, (size_t)plen) && !memcmp(out + 27 + elen + plen, "\"}", 2) && !out[capacity - 1]);
    current_email = e; current_email_len = (size_t)elen; current_password = p; current_password_len = (size_t)plen;
    if (record) {
        CHECK(nseen < 16 && (size_t)elen < sizeof(seen_email[0]));
        memcpy(seen_email[nseen], e, (size_t)elen); seen_email[nseen][elen] = 0;
        memcpy(seen_password[nseen], p, (size_t)plen); seen_password[nseen++][plen] = 0;
    }
    if (hit(FORMAT_NEGATIVE)) return -1;
    if (hit(FORMAT_SHORT)) return 1;
    return hit(FORMAT_TRUNCATED) ? (int)capacity : n;
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && !active_result->verified && !active_result->verification_error && !active_result->extra_data);
    CHECK(r->detector_type == 601 && r->profile == BR_HTTP_SANE && !strcmp(r->method, "POST"));
    CHECK(!strcmp(r->url, "https://app.onedesk.com/rest/2.0/login/loginUser") && r->timeout_ms == (effective ? 5000u : 0u));
    CHECK(r->nheaders == (effective ? 2u : 1u) && !strcmp(r->headers[0].name, "Content-Type") && !strcmp(r->headers[0].value, "application/json"));
    CHECK(!r->dedup_key.data && !r->dedup_key.len && r->body.data == live_payload && r->body.len + 1 == payload_capacity);
    CHECK(current_email_len == active_result->raw.len && !memcmp(current_email, active_result->raw.data, current_email_len));
    CHECK(!memcmp(r->body.data + 11, current_email, current_email_len) && !memcmp(r->body.data + 27 + current_email_len, current_password, current_password_len));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(ctx && ctx == scan_context && verify_mode && !provider_request); request_values(r, false);
    provider_request = r; provider_context = ctx; ++sends; event('H');
    int rc = br_http_send(ctx, r, response, error);
    if (consume_null && rc != 0) { free(*error); *error = NULL; }
    observed = *response; observed_send = rc; return rc;
}
static size_t checked_find(br_slice haystack, br_slice needle, size_t start)
{
    CHECK(provider_request && observed_send == 0 && !observed.body_error && observed.status >= 200 && observed.status < 300);
    CHECK(haystack.data == observed.body.data && haystack.len == observed.body.len && !start && needle.len == 16 && !memcmp(needle.data, marker, 16));
    ++searches; event('S'); return br_slice_find(haystack, needle, start);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && ctx == provider_context); request_values(provider_request, false);
    br_http_release(ctx, response); ++releases; event('R'); provider_request = NULL; provider_context = NULL;
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(active_result == r && collected && !provider_request && !live_payload && sends == releases); ++pushes; event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}
static int forbidden_setter(br_result *r, const char *cause, const br_slice *keys, size_t n)
{
    (void)r; (void)cause; (void)keys; (void)n; ++setters; CHECK(false); return 1;
}
#define br_regex_compile checked_email_compile
#define br_regex_compile_prefixed checked_password_compile
#define br_regex_free checked_regex_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_result_clear checked_clear
#define malloc checked_malloc
#define free checked_free
#define snprintf checked_format
#define br_http_send checked_send
#define br_slice_find checked_find
#define br_http_release checked_release
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#include "../../src/detectors/onedesk.c"
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
#undef br_slice_find
#undef br_http_release
#undef br_results_push
#undef br_result_set_verification_error

static br_results scan(const br_detector *d, const br_scan_ctx *ctx, bool verify, br_slice input)
{
    capture_step = 0; collected = false; scan_context = ctx; verify_mode = verify;
    return test_scan(d, ctx, verify, input.data, input.len);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(marker) - 1 == 16);
    CHECK(br_onedesk_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_onedesk_init(NULL, NULL) == -1);
    fault = COMPILE_EMAIL; nth = 1; watch = true; nevents = 0; events[0] = 0;
    CHECK(br_onedesk_init(&d, &error) == -1 && !d && error && !strcmp(events, "e") && freed_patterns == 1); free(error); error = NULL;
    fault = COMPILE_PASSWORD; nth = 1; nevents = 0; events[0] = 0;
    CHECK(br_onedesk_init(&d, &error) == -1 && !d && error && !strcmp(events, "ew") && freed_patterns == 3); free(error); error = NULL;
    nevents = 0; events[0] = 0; CHECK(!br_onedesk_init(&d, &error) && d && !error && !strcmp(events, "ew")); watch = false;
    CHECK(!br_onedesk_init(&again, NULL) && again == d && fault == NONE);
    CHECK(d->type == 601 && d->version == 0 && !strcmp(d->name, "Onedesk") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Onedesk is a customer service and project management software. Onedesk credentials can be used to access and manage customer service tickets and project tasks."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "onedesk") && d->state && d->scan);
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result_is(const br_result *r, const char *e, bool verified)
{
    test_key_result(r, 601, e, "key"); CHECK(r->verified == verified && !r->verification_error);
}
static void input_for(char *out, size_t cap, const char *e, const char *p)
{
    /* Distant email cannot become an alternate password after a short/bad one.
     * Quoted/bracketed addresses need the source's actual ASCII boundaries. */
    int n = snprintf(out, cap, "onedesk:%s\n................................................................\n%s%s%s", p,
                     e[0] == '"' ? "x" : "", e, e[strlen(e) - 1] == ']' ? "x" : "");
    CHECK(n >= 0 && (size_t)n < cap);
}
static void extract(const br_detector *d, br_slice input, const char *e)
{
    size_t alloc = allocations, sent = sends, made = findings;
    br_results out = scan(d, NULL, false, input);
    CHECK(capture_step == 2 && out.len == (e ? 1u : 0u) && allocations == alloc && sends == sent && !setters);
    if (e) { result_is(&out.items[0], e, false); CHECK(findings == made + 1); }
    br_results_clear(&out);
}
typedef enum { STEADY, FIRST_READ_ERROR, SECOND_READ_ERROR, SECOND_BAD_SLICE } response_mode;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    CHECK(ctx == provider_context && provider_request); request_values(r, true);
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, expected_agent));
    if (http->user) {
        response_mode mode = *(response_mode *)http->user;
        http->response = (br_http_response){.status = 201, .body = {marker, 16}};
        if ((mode == FIRST_READ_ERROR && http->calls == 1) || (mode == SECOND_READ_ERROR && http->calls == 2)) http->response.body_error = "";
        if (mode == SECOND_BAD_SLICE && http->calls == 2) http->response = (br_http_response){.status = 500, .body = {NULL, 1}};
    }
}
static void grammar_and_raw_payload(const br_detector *d)
{
    char input[1024], p[72];
    const char *emails[] = {email, "User@[127.0.0.1]", "\"a\\\"b\"@Example.COM", "\"a\\ b\"@Example.COM", "\"a\001B\177\"@Example.COM", "aKb@Example.COM"};
    test_http http = {.inspect = inspect, .response = {.status = 200, .body = {marker, 16}}}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    for (size_t i = 0; i < sizeof(emails) / sizeof(*emails); ++i) {
        input_for(input, sizeof(input), emails[i], password); extract(d, text(input), emails[i]);
        record = true; nseen = 0; br_results out = scan(d, &ctx, true, text(input)); record = false;
        CHECK(out.len == 1 && nseen == 1 && !strcmp(seen_email[0], emails[i]) && !strcmp(seen_password[0], password));
        result_is(&out.items[0], emails[i], true); br_results_clear(&out);
        size_t sent = sends, built = formats, freed = payload_frees; record = true; nseen = 0;
        out = scan(d, NULL, true, text(input)); record = false;
        CHECK(!out.len && nseen == 1 && !strcmp(seen_email[0], emails[i]) && !strcmp(seen_password[0], password));
        CHECK(sends == sent && formats == built + 1 && payload_frees == freed + 1); br_results_clear(&out);
    }
    const size_t lengths[] = {7,8,64,65};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
        memset(p, 'A', lengths[i]); p[lengths[i]] = 0; input_for(input, sizeof(input), email, p);
        extract(d, text(input), lengths[i] >= 8 ? email : NULL);
        if (lengths[i] >= 8) { record = true; nseen = 0; br_results out = scan(d, &ctx, true, text(input)); record = false; CHECK(out.len == 1 && nseen == 1 && strlen(seen_password[0]) == (lengths[i] > 64 ? 64u : lengths[i])); br_results_clear(&out); }
    }
    input_for(input, sizeof(input), email, "A!=@#$%^"); record = true; nseen = 0;
    br_results out = scan(d, &ctx, true, text(input)); record = false; CHECK(out.len == 1 && !strcmp(seen_password[0], "A!=@#$%^")); br_results_clear(&out);
    input_for(input, sizeof(input), email, "AAA_AAAA"); extract(d, text(input), NULL);
    snprintf(input, sizeof(input), "onedesk:!!!!!!!!\n................................................................\n%s", email); extract(d, text(input), NULL);
    snprintf(input, sizeof(input), "onedeskx!!!!!!!!\n................................................................\n%s", email); record = true; nseen = 0;
    out = scan(d, &ctx, true, text(input)); record = false; CHECK(out.len == 1 && !strcmp(seen_password[0], "!!!!!!!!")); br_results_clear(&out);
    input_for(input, sizeof(input), email, password); memcpy(input, "ONEDESK", 7); extract(d, text(input), email);
    input_for(input, sizeof(input), "\"aXb\"@Example.COM", password); char *inside = strstr(input, "aXb"); CHECK(inside); inside[1] = 0;
    extract(d, (br_slice){(const unsigned char *)input, strlen("onedesk:") + strlen(password) + 1 + 64 + 1 + 1 + strlen("\"aXb\"@Example.COM")}, NULL);
    extract(d, text(email), NULL); extract(d, (br_slice){0}, NULL);
}
static void hidden_products_and_nil(const br_detector *d)
{
    char input[5000]; size_t at = (size_t)snprintf(input, sizeof(input), "%s\nOther@Example.COM\n%s\ncase.user@example.com\n", email, email);
    memset(input + at, '.', 2048); at += 2048;
    int n = snprintf(input + at, sizeof(input) - at, "\nonedesk:%s\nonedesk:%s\nonedesk:%s", password, password, second); CHECK(n > 0); at += (size_t)n;
    const char *known[] = {email,"Other@Example.COM","case.user@example.com"};
    size_t alloc = allocations, sent = sends; br_results out = scan(d, NULL, false, (br_slice){(const unsigned char *)input, at});
    CHECK(out.len == 9 && allocations == alloc && sends == sent); bool groups[3] = {false,false,false};
    for (size_t i = 0; i < out.len; i += 3) {
        size_t k = 0; while (k < 3 && (out.items[i].raw.len != strlen(known[k]) || memcmp(out.items[i].raw.data, known[k], strlen(known[k])))) ++k;
        CHECK(k < 3 && !groups[k]); groups[k] = true; for (size_t j = 0; j < 3; ++j) result_is(&out.items[i+j], known[k], false);
    }
    CHECK(groups[0] && groups[1] && groups[2]); br_results_clear(&out);
    size_t made = findings, published = pushes, freed = payload_frees; record = true; nseen = 0;
    out = scan(d, NULL, true, (br_slice){(const unsigned char *)input, at}); record = false;
    CHECK(!out.len && nseen == 9 && findings == made + 9 && pushes == published && allocations == alloc + 9 && payload_frees == freed + 9 && sends == sent);
    for (size_t i = 0; i < nseen; i += 3) CHECK(!strcmp(seen_email[i], seen_email[i+1]) && !strcmp(seen_email[i], seen_email[i+2]) && !strcmp(seen_password[i], password) && !strcmp(seen_password[i+1], password) && !strcmp(seen_password[i+2], second));
    br_results_clear(&out);
}
static br_results response(const br_detector *d, int status, br_slice body, const char *read, int send_rc, const char *cause, bool consumed)
{
    char input[256]; input_for(input, sizeof(input), email, password);
    test_http http = {.inspect = inspect, .response = {.status = status, .body = body, .body_error = read}, .send_rc = send_rc, .send_error = cause};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t sent = sends, freed = payload_frees, searched = searches; consume_null = consumed;
    nevents = 0; events[0] = 0; watch = true; br_results out = scan(d, &ctx, true, text(input)); watch = false; consume_null = false;
    CHECK(sends == sent + 1 && sends == releases && payload_frees == freed + 1 && http.calls == 1 && http.releases == 1 && !setters);
    bool search = send_rc == 0 && !read && status >= 200 && status < 300;
    CHECK(searches == searched + (search ? 1u : 0u));
    CHECK(!strcmp(events, send_rc ? "WEFABHRXP" : read ? "WEFABHRX" : search ? "WEFABHSRXP" : "WEFABHRXP")); return out;
}
static void statuses_and_reads(const br_detector *d)
{
    const int statuses[] = {0,199,200,201,204,299,300,401,500};
    const unsigned char binary[] = "junk\0before\"code\":\"SUCCESS\"after";
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        br_results out = response(d, statuses[i], (br_slice){binary,sizeof(binary)-1}, NULL, 0, "ignored success diagnostic", false);
        CHECK(out.len == 1); result_is(&out.items[0], email, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
        const char *errors[] = {"read failure",""};
        for (size_t e = 0; e < 2; ++e) { out = response(d, statuses[i], (br_slice){marker,16}, errors[e], 0, NULL, false); CHECK(!out.len); br_results_clear(&out); }
    }
    const char *misses[] = {"", "{\"code\": \"SUCCESS\"}", "\"code\":\"success\"", "\"code\":\"SUCCES\""};
    for (size_t i = 0; i < sizeof(misses) / sizeof(*misses); ++i) { br_results out = response(d, 200, text(misses[i]), NULL, 0, NULL, false); CHECK(out.len == 1); result_is(&out.items[0], email, false); br_results_clear(&out); }
    br_results out = response(d, 500, (br_slice){NULL,SIZE_MAX}, "", 0, NULL, false); CHECK(!out.len); br_results_clear(&out);
    const char *causes[] = {"timeout", "out of memory constructing HTTP headers", "cannot allocate Onedesk payload", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        out = response(d, 200, (br_slice){NULL,SIZE_MAX}, "ignored because Do failed", i % 2 ? -7 : 1, causes[i], false);
        CHECK(out.len == 1); result_is(&out.items[0], email, false); br_results_clear(&out);
    }
    out = response(d, 200, (br_slice){marker,16}, NULL, 1, "consumed component leaf", true); CHECK(out.len == 1); result_is(&out.items[0], email, false); br_results_clear(&out);
}
static bool cancelled(void *u) { ++*(size_t *)u; return true; }
static void preparation_and_continuation(const br_detector *d)
{
    char input[300]; input_for(input, sizeof(input), email, password);
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t alloc = allocations, sent = sends; http.calls = http.releases = 0;
        br_results out = scan(d, &contexts[i], false, text(input)); CHECK(out.len == 1 && allocations == alloc && sends == sent); br_results_clear(&out);
        out = scan(d, &contexts[i], true, text(input)); CHECK(out.len == 1 && allocations == alloc + 1 && sends == sent + 1 && !http.calls && http.releases == (i ? 1u : 0u)); result_is(&out.items[0], email, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    snprintf(input, sizeof(input), "onedesk:%s\nonedesk:%s\n%s", password, second, email);
    const char *configured[] = {"https://ignored.invalid"}; br_endpoints endpoints = {.configured = configured, .nconfigured = 1};
    for (response_mode mode = FIRST_READ_ERROR; mode <= SECOND_READ_ERROR; ++mode) {
        http = (test_http){.inspect = inspect, .user = &mode}; transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .endpoints = &endpoints, .user_agent = "onedesk-offline"}; expected_agent = "TruffleHog onedesk-offline";
        record = true; nseen = 0; br_results out = scan(d, &ctx, true, text(input)); record = false;
        CHECK(out.len == 1 && http.calls == 2 && http.releases == 2 && nseen == 2 && !strcmp(seen_password[0], password) && !strcmp(seen_password[1], second));
        result_is(&out.items[0], email, true); br_results_clear(&out); expected_agent = "TruffleHog";
    }
}
static void owned_failures(const br_detector *d)
{
    char input[300]; snprintf(input, sizeof(input), "onedesk:%s\nonedesk:%s\n%s", password, second, email);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t which; bool nil, nov, empty_passwords; int send_rc; const char *read; } cases[] = {
        {CAPTURE,1,true,true,false,0,NULL}, {CAPTURE,2,true,true,false,0,NULL}, {CAPTURE,2,true,true,true,0,NULL},
        {FINDING,1,true,false,false,0,NULL}, {FINDING,2,true,false,false,0,NULL}, {FINDING,2,true,true,false,0,NULL},
        {ALLOCATE,1,true,false,false,0,NULL}, {ALLOCATE,2,true,false,false,0,NULL},
        {FORMAT_NEGATIVE,1,true,false,false,0,NULL}, {FORMAT_SHORT,2,true,false,false,0,NULL}, {FORMAT_TRUNCATED,1,true,false,false,0,NULL},
        {ALLOCATE,2,false,false,false,0,NULL}, {FORMAT_SHORT,2,false,false,false,1,NULL}, {FORMAT_NEGATIVE,2,false,false,false,0,""},
        {PUSH,1,false,false,false,0,NULL}, {PUSH,2,false,false,false,0,NULL}, {PUSH,2,false,false,false,1,NULL}, {PUSH,2,true,true,false,0,NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.inspect = inspect, .response = {.status = 201, .body = {marker,16}, .body_error = cases[i].read}, .send_rc = cases[i].send_rc, .send_error = cases[i].send_rc ? "opaque error" : NULL};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        scan_context = cases[i].nil ? NULL : &ctx; verify_mode = !cases[i].nov; capture_step = 0; collected = false;
        fault = cases[i].kind; nth = cases[i].which;
        size_t failed = injected, sent = sends, freed = payload_frees, alloc = allocations, made = findings; char *error = NULL;
        CHECK(d->scan(d, scan_context, verify_mode, text(cases[i].empty_passwords ? email : input), &out, &error) == -1);
        CHECK(error && fault == NONE && injected == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends == releases && !provider_request && !active_result && !live_payload && !setters);
        if (cases[i].nil || cases[i].nov) CHECK(sends == sent);
        if (cases[i].kind == CAPTURE) CHECK(findings == made && allocations == alloc);
        size_t successful_allocs = allocations - alloc - (cases[i].kind == ALLOCATE ? 1u : 0u); CHECK(payload_frees == freed + successful_allocs);
        free(error);
    }
    response_mode mode = SECOND_BAD_SLICE; test_http http = {.inspect = inspect, .user = &mode}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    scan_context = &ctx; verify_mode = true; capture_step = 0; collected = false; char *error = NULL;
    CHECK(d->scan(d, &ctx, true, text(input), &out, &error) == -1 && error && http.calls == 2 && http.releases == 2); free(error); error = NULL;
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    fault = FINDING; nth = 1; verify_mode = false; scan_context = NULL; capture_step = 0; collected = false;
    CHECK(d->scan(d, NULL, false, text(input), &out, NULL) == -1 && fault == NONE);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL,1}, &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
    br_bytes body = {0}; error = NULL; size_t alloc = allocations;
    CHECK(onedesk_payload((br_slice){(const unsigned char *)"x",SIZE_MAX}, text(password), &body, &error) == -1 && error && !body.data && allocations == alloc); free(error); error = NULL;
    CHECK(onedesk_payload(text(email), (br_slice){(const unsigned char *)"x",SIZE_MAX}, &body, &error) == -1 && error && !body.data && allocations == alloc); free(error); error = NULL;
    CHECK(onedesk_payload((br_slice){(const unsigned char *)"x",INT_MAX}, text(password), &body, &error) == -1 && error && !body.data && allocations == alloc); free(error);
}
int main(void)
{
    (void)forbidden_setter; test_secret(password, 16, 0); password[0] = 'A'; password[8] = '!'; test_secret(second, 16, 7); second[0] = 'Z';
    const br_detector *d = descriptor(); grammar_and_raw_payload(d); hidden_products_and_nil(d); statuses_and_reads(d); preparation_and_continuation(d); owned_failures(d);
    CHECK(fault == NONE && sends == releases && !live_payload && !provider_request && !active_result && !setters && !consume_null && !watch && !record);
    return test_finish("Onedesk");
}
