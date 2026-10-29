/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <limits.h>
#include <stdarg.h>

typedef int (*factory)(const br_detector **, char **);
static const char v1_key[] = "A1a2b3c4-1234-abcd-5678-012345abcdef";
static const char v1_other[] = "f9e8d7c6-abcd-0123-4567-fedcba987654";
static char v2_key[66], v2_other[66];

/* Follow the existing named tests' module-local hooks. Normal fixtures call the
 * library factories; these hooks check positive resource failures and the
 * helper-release/caller-publication boundary without changing the shared ABI. */
typedef enum {
    NO_FAULT, CAPTURE, FINDING, ALLOCATE, AUTH_FORMAT, STATUS_MEASURE,
    STATUS_FORMAT, CONSTRUCTOR_CAUSE, TRANSPORT_CAUSE, SETTER, PUSH
} fault_site;
static fault_site fault;
static size_t fault_nth, fault_size;
static bool oversized_format, omit_send_cause;
static br_result *candidate;
static const br_http_request *provider_request;
static size_t send_attempts, release_attempts, setter_calls;
static bool source_verified;

static bool hit(fault_site site)
{
    if (fault != site || (fault_nth && --fault_nth)) return false;
    fault = NO_FAULT;
    return true;
}

static void *checked_malloc(size_t size)
{
    return size == fault_size && hit(ALLOCATE) ? NULL : malloc(size);
}

static char *checked_strdup(const char *text)
{
    if ((!strcmp(text, "net/http: nil Context") && hit(CONSTRUCTOR_CAUSE)) ||
        (!strcmp(text, "HTTP transport failed") && hit(TRANSPORT_CAUSE))) return NULL;
    return strdup(text);
}

static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    fault_site site = !strcmp(format, "Bearer %.*s") ? AUTH_FORMAT :
                      out ? STATUS_FORMAT : STATUS_MEASURE;
    if (hit(site)) return oversized_format ? (int)size : -1;
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, size, format, args);
    va_end(args);
    return rc;
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out,
                             bool unique, char **error)
{
    CHECK(!unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure"); CHECK(*error);
        return 1;
    }
    return rc;
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    candidate = result;
    source_verified = false;
    return hit(FINDING) ? 1 : br_finding_key_bytes(result, type, key, part);
}

static void original_request(const br_http_request *request)
{
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.heroku.com/account"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.heroku+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(strlen(request->headers[1].value) == 7 + candidate->raw.len);
    CHECK(!memcmp(request->headers[1].value, "Bearer ", 7));
    CHECK(!memcmp(request->headers[1].value + 7, candidate->raw.data, candidate->raw.len));
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                         br_http_response *response, char **error)
{
    CHECK(!provider_request && send_attempts == release_attempts);
    original_request(request);
    provider_request = request;
    ++send_attempts;
    int rc = br_http_send(ctx, request, response, error);
    source_verified = rc == 0 && response->status == 200;
    if (rc != 0 && omit_send_cause) { free(*error); *error = NULL; }
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && send_attempts == release_attempts + 1);
    original_request(provider_request);
    br_http_release(ctx, response);
    provider_request = NULL;
    ++release_attempts;
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(!provider_request && send_attempts == release_attempts && result == candidate);
    CHECK(!secrets && !count && result->verified == source_verified);
    ++setter_calls;
    return hit(SETTER) ? 1 : br_result_set_verification_error(result, cause, secrets, count);
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!provider_request && send_attempts == release_attempts);
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

#define malloc checked_malloc
#define strdup checked_strdup
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_heroku_v1_init observed_heroku_v1_init
#define br_heroku_v2_init observed_heroku_v2_init
#include "../../src/detectors/heroku.c"
#undef malloc
#undef strdup
#undef snprintf
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push
#undef br_heroku_v1_init
#undef br_heroku_v2_init

static const char *key(size_t version) { return version == 1 ? v1_key : v2_key; }
static const char *other(size_t version) { return version == 1 ? v1_other : v2_other; }

static const br_detector *descriptor(factory init, size_t version)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, version == 1 ? "invalid Heroku v1 detector output" : "invalid Heroku v2 detector output"));
    free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 19 && d->version == (int32_t)version && !strcmp(d->name, "Heroku") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Heroku is a cloud platform that lets companies build, deliver, monitor and scale apps. Heroku API keys can be used to access and manage Heroku applications and services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], version == 1 ? "heroku" : "HRKU-AA"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 19, expected, "key");
    CHECK(result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
}

static void extract(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}

static void v1_grammar(const br_detector *d)
{
    char input[512], changed[37];
    const char *good[] = {"heroku '%s'", "HeRoKu\r\n%s", "xHEROKUsuffix:%s", "heroku-%s", "heroku\r%s", "heroku\n%s", "heroku \t%s\t "};
    const char *bad[] = {"%s", "%s heroku", "hero ku %s", "heroku%s", "heroku x%s", "heroku _%s", "heroku %s_", "heroku %sf", "heroku %.35s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], v1_key); extract(d, input, strlen(input), v1_key);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], v1_key); extract(d, input, strlen(input), NULL);
    }
    const char first_block[] = "09AabcdefBCDEFg_";
    for (size_t i = 0; i < sizeof(first_block) - 1; ++i) {
        memcpy(changed, v1_key, sizeof(changed)); changed[4] = first_block[i];
        snprintf(input, sizeof(input), "heroku %s", changed);
        extract(d, input, strlen(input), i < 9 ? changed : NULL);
    }
    const size_t lower_positions[] = {9, 14, 19, 24};
    for (size_t i = 0; i < sizeof(lower_positions) / sizeof(*lower_positions); ++i) {
        memcpy(changed, v1_key, sizeof(changed)); changed[lower_positions[i]] = 'A';
        snprintf(input, sizeof(input), "heroku %s", changed); extract(d, input, strlen(input), NULL);
    }
    memcpy(changed, v1_key, sizeof(changed)); changed[8] = '_';
    snprintf(input, sizeof(input), "heroku %s", changed); extract(d, input, strlen(input), NULL);
    const char zeros[] = "00000000-0000-0000-0000-000000000000";
    snprintf(input, sizeof(input), "heroku %s", zeros); extract(d, input, strlen(input), zeros);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "heroku", 6); memset(input + 6, ':', gap); memcpy(input + 6 + gap, v1_key, 36);
        extract(d, input, 42 + gap, gap == 40 ? v1_key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 4 * i, "\xf0\x9f\x92\xa1", 4);
        memcpy(input + 6 + 4 * gap, v1_key, 36);
        extract(d, input, 42 + 4 * gap, gap == 40 ? v1_key : NULL);
    }
    memcpy(input, "heroku\0", 7); memcpy(input + 7, v1_key, 36);
    extract(d, input, 43, v1_key);
    snprintf(input, sizeof(input), "heroku %s %s", v1_key, v1_other);
    extract(d, input, strlen(input), v1_key); /* A consumed prefix is not reused. */
    extract(d, NULL, 0, NULL);
}

static void v2_grammar(const br_detector *d)
{
    char input[512], changed[66];
    const char *good[] = {"%s", "'%s'", " \t%s\r\n", "-%s-", "heroku %s", "%s/more"};
    const char *bad[] = {"x%s", "_%s", "%s_", "%sX", "%.64s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) {
        snprintf(input, sizeof(input), good[i], v2_key); extract(d, input, strlen(input), v2_key);
    }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) {
        snprintf(input, sizeof(input), bad[i], v2_key); extract(d, input, strlen(input), NULL);
    }
    const size_t prefix_positions[] = {0, 1, 2, 3, 5, 6};
    for (size_t i = 0; i < sizeof(prefix_positions) / sizeof(*prefix_positions); ++i) {
        memcpy(changed, v2_key, sizeof(changed)); changed[prefix_positions[i]] += 'a' - 'A';
        extract(d, changed, 65, NULL);
    }
    const char allowed[] = "09azAZ_-", disallowed[] = "/+=.:@ ";
    for (size_t i = 0; i < sizeof(allowed) - 1; ++i) {
        memcpy(changed, v2_key, sizeof(changed)); changed[30] = allowed[i]; extract(d, changed, 65, changed);
    }
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, v2_key, sizeof(changed)); changed[30] = disallowed[i]; extract(d, changed, 65, NULL);
    }
    memcpy(changed, v2_key, sizeof(changed)); changed[64] = '-';
    extract(d, changed, 65, NULL); /* Nonword '-' needs a following word byte for \b. */
    snprintf(input, sizeof(input), "%sX", changed); extract(d, input, strlen(input), changed);
    changed[64] = '_'; extract(d, changed, 65, changed);
    memcpy(changed, "HRKU-AA", 7); memset(changed + 7, 'a', 58); changed[65] = 0;
    extract(d, changed, 65, changed); /* No entropy/semantic filtering. */
    memset(input, ':', 100); memcpy(input + 100, v2_key, 65); extract(d, input, 165, v2_key);
    extract(d, NULL, 0, NULL);
}

typedef struct {
    const char *keys[3], *agent;
    size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth, *borrowed_url;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && at < 3 && ctx == s->ctx && http->releases == at && !s->borrowed_auth);
    CHECK(request->detector_type == 19 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.heroku.com/account"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.heroku+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(strlen(request->headers[1].value) == 7 + strlen(s->keys[at]));
    CHECK(!memcmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, s->keys[at]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, s->agent));
    /* Borrow only provider-original values, never prepared headers or UA. */
    s->borrowed_auth = request->headers[1].value; s->borrowed_url = request->url;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user;
    if (s->borrowed_auth) {
        CHECK(http->calls == http->releases + 1 && !memcmp(s->borrowed_auth, "Bearer ", 7));
        CHECK(!strcmp(s->borrowed_auth + 7, s->keys[http->calls - 1]));
        CHECK(!strcmp(s->borrowed_url, "https://api.heroku.com/account"));
        s->borrowed_auth = s->borrowed_url = NULL;
    } else {
        CHECK(!response->status && !response->headers && !response->nheaders);
        CHECK(!response->body.data && !response->body.len && !response->body_error);
    }
    test_http_release(user, response);
}

static size_t make_input(char *input, size_t size, size_t version, bool repeated)
{
    int n = repeated ? snprintf(input, size, version == 1 ? "heroku %s\nheroku %s\nheroku %s" : "%s\n%s\n%s", key(version), other(version), key(version)) :
                       snprintf(input, size, version == 1 ? "heroku %s" : "%s", key(version));
    CHECK(n >= 0 && (size_t)n < size);
    return (size_t)n;
}

static void occurrences_and_verification(const br_detector *d)
{
    char input[300]; size_t version = (size_t)d->version;
    size_t len = make_input(input, sizeof(input), version, true);
    script s = {.keys = {key(version), other(version), key(version)}, .count = 3, .agent = "TruffleHog heroku-offline"};
    test_http http = {.user = &s, .inspect = inspect, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "heroku-offline"}; s.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, len);
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], s.keys[i], pass != 0, NULL);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    br_results out = test_scan(d, NULL, true, input, len);
    CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], s.keys[i], false, "net/http: nil Context");
    br_results_clear(&out);

    len = make_input(input, sizeof(input), version, false); s.count = 1; s.agent = "TruffleHog"; ctx.user_agent = NULL;
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 500, INT_MIN, INT_MAX};
    static const unsigned char body[] = {0xff, 0, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = "ignored body read failure"};
        out = test_scan(d, &ctx, true, input, len);
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected status code: %d", statuses[i]);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key(version), statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : cause);
        br_results_clear(&out);
    }
    char whole_cause[220]; snprintf(whole_cause, sizeof(whole_cause), "outer cause: %s / %s", key(version), key(version));
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "context canceled"}, {1, "net/http: nil Context"},
        {-1, "cannot allocate Heroku authorization"}, {1, "out of memory constructing HTTP headers"},
        {1, "unexpected status code: 401"}, {-7, whole_cause}, {1, ""}, {1, NULL},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i % 2 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        out = test_scan(d, &ctx, true, input, len);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key(version), false, failures[i].cause ? failures[i].cause : "HTTP transport failed");
        br_results_clear(&out);
    }
    CHECK(!s.borrowed_auth && !s.borrowed_url);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void shared_setup(const br_detector *d)
{
    char input[100]; size_t len = make_input(input, sizeof(input), (size_t)d->version, false);
    script s = {0}; test_http http = {.user = &s};
    br_transport transport = {&http, test_http_send, release_response}, missing_send = {&http, NULL, release_response};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        http.calls = http.releases = 0; send_attempts = release_attempts = setter_calls = 0;
        br_results out = test_scan(d, &contexts[i], true, input, len);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(send_attempts == 1 && release_attempts == 1 && setter_calls == 1);
        finding(&out.items[0], key((size_t)d->version), false, causes[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures(const br_detector *d)
{
    size_t version = (size_t)d->version;
    char input[300]; size_t len = make_input(input, sizeof(input), version, true);
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    CHECK(br_result_set_verification_error(&out.items[0], NULL, NULL, 0) == 0); prior_unchanged(&out, &prior);
    script s = {.keys = {key(version), other(version), key(version)}, .count = 3, .agent = "TruffleHog"};
    test_http http = {.user = &s, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    const struct {
        fault_site site; size_t nth, size, attempts; int status; bool nil, do_error, no_cause, oversized;
        const char *error;
    } cases[] = {
        {CAPTURE, 1, 0, 0, 200, false, false, false, false, "synthetic capture failure"},
        {FINDING, 1, 0, 0, 200, true, false, false, false, "cannot create Heroku finding"},
        {FINDING, 2, 0, 1, 200, false, true, false, false, "cannot create Heroku finding"},
        {ALLOCATE, 2, 8 + strlen(key(version)), 1, 200, false, true, false, false, "cannot allocate Heroku authorization"},
        {AUTH_FORMAT, 1, 0, 0, 200, false, false, false, false, "cannot format Heroku authorization"},
        {AUTH_FORMAT, 1, 0, 0, 200, false, false, false, true, "cannot format Heroku authorization"},
        {ALLOCATE, 2, sizeof("unexpected status code: 503"), 2, 503, false, false, false, false, "cannot allocate Heroku status cause"},
        {STATUS_MEASURE, 2, 0, 2, 503, false, false, false, false, "cannot format Heroku status cause"},
        {STATUS_FORMAT, 2, 0, 2, 503, false, false, false, true, "cannot format Heroku status cause"},
        {CONSTRUCTOR_CAUSE, 2, 0, 0, 200, true, false, false, false, "cannot create Heroku constructor cause"},
        {TRANSPORT_CAUSE, 2, 0, 2, 200, false, true, true, false, "cannot create Heroku transport cause"},
        {SETTER, 2, 0, 2, 200, false, false, false, false, "cannot set Heroku verification error"},
        {SETTER, 2, 0, 2, 401, false, false, false, false, "cannot set Heroku verification error"},
        {SETTER, 2, 0, 2, 200, false, true, false, false, "cannot set Heroku verification error"},
        {PUSH, 2, 0, 2, 200, false, false, false, false, "cannot append Heroku finding"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        fault = cases[i].site; fault_nth = cases[i].nth; fault_size = cases[i].size;
        oversized_format = cases[i].oversized; omit_send_cause = cases[i].no_cause;
        http.calls = http.releases = 0; http.send_rc = cases[i].do_error ? 7 : 0;
        http.send_error = cases[i].do_error ? "cannot create Heroku finding" : NULL;
        http.response = (br_http_response){.status = cases[i].status};
        send_attempts = release_attempts = setter_calls = 0;
        char *error = NULL;
        CHECK(d->scan(d, cases[i].nil ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, len}, &out, &error) == -1);
        CHECK(error && !strcmp(error, cases[i].error)); free(error);
        CHECK(fault == NO_FAULT && !fault_nth && !provider_request && !s.borrowed_auth && !s.borrowed_url);
        CHECK(http.calls == cases[i].attempts && http.releases == http.calls);
        CHECK(send_attempts == cases[i].attempts && release_attempts == send_attempts);
        prior_unchanged(&out, &prior);
    }
    oversized_format = omit_send_cause = false;
    fault = ALLOCATE; fault_nth = 1; fault_size = 8 + strlen(key(version));
    send_attempts = release_attempts = setter_calls = 0;
    br_results nil = test_scan(d, NULL, true, input, len);
    CHECK(nil.len == 3 && fault == ALLOCATE && fault_nth == 1 && !send_attempts && !release_attempts && setter_calls == 3);
    for (size_t i = 0; i < 3; ++i) finding(&nil.items[i], s.keys[i], false, "net/http: nil Context");
    br_results_clear(&nil);
    nil = test_scan(d, NULL, false, input, len);
    CHECK(nil.len == 3 && fault == ALLOCATE && fault_nth == 1 && !send_attempts && !release_attempts && setter_calls == 3);
    for (size_t i = 0; i < 3; ++i) finding(&nil.items[i], s.keys[i], false, NULL);
    br_results_clear(&nil);
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, len}, &out, NULL) == -1);
    CHECK(fault == NO_FAULT && !fault_nth); prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    prior_unchanged(&out, &prior); br_results_clear(&out);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(v1_key) == 36 && strlen(v1_other) == 36);
    memcpy(v2_key, "HRKU-AA", 7); test_secret(v2_key + 7, 58, 0);
    v2_key[16] = '_'; v2_key[25] = '-'; v2_key[32] = 'Z';
    memcpy(v2_other, "HRKU-AA", 7); test_secret(v2_other + 7, 58, 9); v2_other[20] = 'A';
    CHECK(strlen(v2_key) == 65 && strlen(v2_other) == 65);
    const br_detector *v1 = descriptor(br_heroku_v1_init, 1), *v2 = descriptor(br_heroku_v2_init, 2);
    CHECK(v1 != v2 && v1->state != v2->state && v1->keywords != v2->keywords);
    v1_grammar(v1); v2_grammar(v2);
    char mixed[150]; snprintf(mixed, sizeof(mixed), "heroku %s\n%s", v1_key, v2_key);
    extract(v1, mixed, strlen(mixed), v1_key); extract(v2, mixed, strlen(mixed), v2_key);
    occurrences_and_verification(v1); occurrences_and_verification(v2);
    const br_detector *observed_v1 = descriptor(observed_heroku_v1_init, 1), *observed_v2 = descriptor(observed_heroku_v2_init, 2);
    shared_setup(observed_v1); shared_setup(observed_v2);
    owned_failures(observed_v1); owned_failures(observed_v2);
    CHECK(fault == NO_FAULT && !fault_nth && !provider_request && !oversized_format && !omit_send_cause);
    return test_finish("Heroku v1/v2 grammar/occurrences/metadata/request/status/read/whole-cause/zero-secret-setter/release/resources/rollback");
}
