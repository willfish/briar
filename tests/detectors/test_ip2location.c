/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

/* The existing named-test inclusion seam observes owned failures and ordering
 * without replacing shared preparation, transport, result or regex helpers. */
static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_snprintf(char *, size_t, const char *, ...);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_setter(br_result *, const char *, const br_slice *, size_t);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define snprintf checked_snprintf
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_ip2location_init observed_ip2location_init
#include "../../src/detectors/ip2location.c"
#undef malloc
#undef free
#undef snprintf
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push
#undef br_ip2location_init

static const char key_a[] = "G7H9J2K5L6M8N3P4Q1R0S2T4U6V8W1X3";
static const char key_b[] = "Z9Y8X7W6V5U4T3S2R1Q0P9N8M7L6K5J4";
static const char url_prefix[] = "https://api.ip2location.io/?key=";
enum { URL_SIZE = sizeof(url_prefix) + 32 };
typedef enum { NONE, CAPTURE, FINDING, URL, STATUS_ALLOC, STATUS_MEASURE, STATUS_FORMAT, SETTER, PUSH } fault_site;
static fault_site fault;
static size_t nth, urls, url_frees, sends, releases, setters, pushes;
static bool fault_hit, omit_cause, should_verify, should_set, did_set, did_push;
static br_captures *original_keys;
static br_result *candidate;
static br_results *published;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static char *original_url, *status_cause;
static const char *original_cause;
static char saved_cause[256];

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_context && !original_url && !status_cause);
    fault = NONE; nth = 0; fault_hit = omit_cause = false;
    urls = url_frees = sends = releases = setters = pushes = 0;
    original_keys = NULL; candidate = NULL; published = NULL; original_cause = NULL;
}

static void original_values(void)
{
    CHECK(original_keys && original_url && urls && urls <= original_keys->len);
    CHECK(original_keys->lengths[urls - 1] == 32);
    CHECK(!memcmp(original_url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(original_url + sizeof(url_prefix) - 1, original_keys->items[urls - 1], 33));
    if (original_request) {
        CHECK(original_request->url == original_url && !strcmp(original_request->method, "GET"));
        CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms);
        CHECK(original_request->detector_type == 940 && !original_request->headers && !original_request->nheaders);
        CHECK(!original_request->body.data && !original_request->body.len);
        CHECK(!original_request->dedup_key.data && !original_request->dedup_key.len);
    }
}

static void *checked_malloc(size_t size)
{
    if (size == URL_SIZE) {
        CHECK(candidate && candidate->raw.len == 32 && candidate->secret_parts);
        CHECK(!candidate->verified && !candidate->verification_error && !original_url);
        ++urls;
        if (hit(URL)) return NULL;
        original_url = malloc(size);
        return original_url;
    }
    CHECK(original_request && !status_cause);
    if (hit(STATUS_ALLOC)) return NULL;
    status_cause = malloc(size);
    return status_cause;
}

static void checked_free(void *value)
{
    CHECK(!original_request && !original_context);
    if (value && value == original_url) {
        original_values(); original_url = NULL; ++url_frees;
    }
    if (value && value == status_cause) status_cause = NULL;
    free(value);
}

static int checked_snprintf(char *out, size_t size, const char *format, ...)
{
    CHECK(original_request && !strcmp(format, "unexpected HTTP response status %d"));
    if (!out && hit(STATUS_MEASURE)) return -1;
    va_list args; va_start(args, format);
    int rc = vsnprintf(out, out ? size : 0, format, args);
    va_end(args);
    if (out && hit(STATUS_FORMAT)) return (int)size;
    return rc;
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && !original_keys);
    original_keys = out;
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
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    CHECK(!original_request && !original_context && sends == releases);
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    original_request = request; original_context = ctx; original_values(); ++sends;
    did_set = did_push = false; published = NULL;
    int rc = br_http_send(ctx, request, response, error);
    if (rc != 0 && omit_cause) { free(*error); *error = NULL; }
    should_verify = rc == 0 && response->status >= 200 && response->status < 300;
    should_set = rc != 0 || (!should_verify && response->status != 401);
    original_cause = *error;
    if (original_cause) {
        CHECK(strlen(original_cause) < sizeof(saved_cause));
        strcpy(saved_cause, original_cause);
    }
    return rc;
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(original_request && result == candidate && should_set && !did_set && !did_push);
    original_values();
    CHECK(count == 1 && secrets && secrets[0].len == 32);
    CHECK(secrets[0].data == (const unsigned char *)original_keys->items[urls - 1]);
    CHECK(!result->verified && !result->verification_error);
    original_cause = cause;
    if (cause) { CHECK(strlen(cause) < sizeof(saved_cause)); strcpy(saved_cause, cause); }
    did_set = true; ++setters;
    return hit(SETTER) ? 1 : br_result_set_verification_error(result, cause, secrets, count);
}

static int checked_push(br_results *out, br_result *result)
{
    ++pushes;
    if (original_request) {
        original_values();
        CHECK(result == candidate && result->verified == should_verify && did_set == should_set && !did_push);
        did_push = true;
    }
    if (hit(PUSH)) return 1;
    int rc = br_results_push(out, result);
    if (rc == 0 && original_request) published = out;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && ctx == original_context && sends == releases + 1);
    original_values();
    if (original_cause) CHECK(!strcmp(original_cause, saved_cause));
    if (!fault_hit) CHECK(did_push && did_set == should_set);
    const br_result *r = published ? &published->items[published->len - 1] : candidate;
    CHECK(r && r->verified == should_verify && r->raw.len == 32);
    CHECK(!memcmp(r->raw.data, original_keys->items[urls - 1], 32));
    if (published) CHECK(!original_cause || r->verification_error);
    br_http_release(ctx, response);
    original_values();
    original_request = NULL; original_context = NULL; original_cause = NULL; ++releases;
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error); free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 940 && !d->version && !strcmp(d->name, "Ip2location") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Ip2location is a service that provides IP geolocation data. Ip2location keys can be used to access this geolocation data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ip2location"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/default/native integration belongs to the parent. */
}

static void finding(const br_result *r, const char *key, bool verified, const char *cause)
{
    test_key_result(r, 940, key, "key");
    CHECK(r->raw.len == 32 && r->verified == verified);
    CHECK(cause ? r->verification_error && !strcmp(r->verification_error, cause) : !r->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) finding(&out.items[0], key, false, NULL);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[256], changed[33];
    const struct { const char *format; bool match; } cases[] = {
        {"ip2location '%s'", true}, {"Ip2LoCaTiOn:%s", true}, {"myIP2LOCATIONsuffix:%s", true},
        {"ip2location\r\n%s", true}, {"ip2location\r%s", true}, {"ip2location\n%s", true},
        {"ip2location\t  %s  ", true}, {"ip2location-%s-", true},
        {"%s", false}, {"%s ip2location", false}, {"ip2 location %s", false},
        {"ip2location%s", false}, {"ip2location X%s", false}, {"ip2location _%s", false},
        {"ip2location %s_", false}, {"ip2location %s9", false}, {"ip2location %.31s", false},
        {"ip2location %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a, key_b);
        extract_case(d, input, strlen(input), cases[i].match ? key_a : NULL);
    }
    const char invalid[] = "agz_-/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "ip2location %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "0AGZ"; /* No hex-only, randomness or FP filter. */
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 32); changed[32] = '\0';
        snprintf(input, sizeof(input), "ip2location %s", changed);
        extract_case(d, input, strlen(input), changed);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ip2location", 11); memset(input + 11, '.', gap);
        memcpy(input + 11 + gap, key_a, 32);
        extract_case(d, input, 43 + gap, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 11 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 11 + 2 * gap, key_a, 32);
        extract_case(d, input, 43 + 2 * gap, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "ip2location%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("Ip2location uppercase-alphanumeric/nonhex/prefix/rune gap/boundaries/TrimSpace/binary input: 0 failures");
}

typedef struct { const char *const *keys; size_t count; const char *agent; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == URL_SIZE - 1);
    CHECK(!memcmp(request->url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!strcmp(request->url + sizeof(url_prefix) - 1, script->keys[at]));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 940);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, script->agent));
    /* Do not retain effective request/header-array/synthesized UA storage. */
}

static void occurrences(const br_detector *d)
{
    char input[192]; snprintf(input, sizeof(input), "ip2location %s\nIP2LOCATION %s\nip2location %s", key_a, key_b, key_a);
    const char *keys[] = {key_a, key_b, key_a};
    request_script script = {keys, 3, "TruffleHog ip2location-offline"};
    test_http http = {.inspect = inspect, .user = &script, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "ip2location-offline"};
    for (size_t pass = 0; pass < 2; ++pass) {
        reset_observation();
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], pass != 0, NULL);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    puts("Ip2location original occurrences/duplicates/Raw-key-only metadata/exact GET/common UA: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "ip2location %s", key_a);
    const char *keys[] = {key_a}; request_script script = {keys, 1, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0xff, 0, '{', '!'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored partial read"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        bool ok = statuses[i] >= 200 && statuses[i] < 300;
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key_a, ok, ok || statuses[i] == 401 ? NULL : cause); br_results_clear(&out);
    }
    char cause[160]; snprintf(cause, sizeof(cause), "key=%s; other=public; again=%s", key_a, key_a);
    const struct { int rc; const char *cause, *expected; } errors[] = {
        {1, cause, "key=[REDACTED]; other=public; again=[REDACTED]"}, {-7, "context canceled", "context canceled"},
        {1, "context deadline exceeded", "context deadline exceeded"}, {-1, "cannot construct Ip2location URL", "cannot construct Ip2location URL"},
        {1, "out of memory constructing HTTP headers", "out of memory constructing HTTP headers"},
        {7, "net/http: nil Context", "net/http: nil Context"}, {1, "", ""}, {-1, NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); http.calls = http.releases = 0; http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = i % 2 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key_a, false, errors[i].expected); br_results_clear(&out);
    }
    puts("Ip2location all-2xx/401/unexpected status/ignored bodies and read errors/whole mixed Do/token redaction: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void setup_and_null(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "ip2location %s", key_a);
    test_http http = {0}; br_transport transport = test_transport(&http), missing_send = {&http, NULL, test_http_release};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    const char *causes[] = {"HTTP transport not installed", "HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(sends == 1 && releases == 1 && setters == 1 && pushes == 1 && url_frees == 1);
        finding(&out.items[0], key_a, false, causes[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && urls == 1 && url_frees == 1 && !sends && !setters && !pushes); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !urls && !sends && !setters); finding(&out.items[0], key_a, false, NULL); br_results_clear(&out);
    br_scan_ctx ctx = {.transport = &transport}; http.send_rc = 1;
    reset_observation(); omit_cause = true;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && setters == 1 && sends == 1 && releases == 1);
    finding(&out.items[0], key_a, false, NULL); br_results_clear(&out);
    puts("Ip2location shared setup/NULL setter/nil constructor/full URL before drop/verdict and setter before release: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify, bool nil,
                        int send_rc, bool no_cause, const char *message, size_t attempts)
{
    char input[128]; snprintf(input, sizeof(input), "ip2location %s\nip2location %s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot create Ip2location finding" : NULL,
        .response = {.status = site == PUSH ? 200 : 503, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence; omit_cause = no_cause;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, message)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_url && !status_cause);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(url_frees + (site == URL ? 1u : 0u) == urls);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 0, false, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 0, false, "cannot create Ip2location finding", 0);
    own_failure(d, FINDING, 2, true, false, 0, false, "cannot create Ip2location finding", 1);
    own_failure(d, URL, 1, true, true, 0, false, "cannot construct Ip2location URL", 0);
    own_failure(d, URL, 2, true, false, 0, false, "cannot construct Ip2location URL", 1);
    own_failure(d, STATUS_MEASURE, 2, true, false, 0, false, "cannot format Ip2location status cause", 2);
    own_failure(d, STATUS_ALLOC, 2, true, false, 0, false, "cannot allocate Ip2location status cause", 2);
    own_failure(d, STATUS_FORMAT, 2, true, false, 0, false, "cannot format Ip2location status cause", 2);
    own_failure(d, SETTER, 2, true, false, 0, false, "cannot set Ip2location verification error", 2);
    own_failure(d, SETTER, 2, true, false, -7, false, "cannot set Ip2location verification error", 2);
    own_failure(d, SETTER, 2, true, false, 1, true, "cannot set Ip2location verification error", 2);
    own_failure(d, PUSH, 2, true, false, 0, false, "cannot append Ip2location finding", 2);
    own_failure(d, PUSH, 2, false, false, 0, false, "cannot append Ip2location finding", 0);
    reset_observation(); br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(!out.len && !urls && !sends);
    puts("Ip2location owned nonzero failures/+1 setter fatal/one release on fatal/invocation-only caller-preserving rollback: 0 failures");
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 32 && strlen(key_b) == 32);
    const br_detector *d = descriptor(br_ip2location_init);
    grammar(d); occurrences(d); response_policy(d);
    const br_detector *observed = descriptor(observed_ip2location_init);
    reset_observation(); occurrences(observed); response_policy(observed);
    setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_context && !original_url && !status_cause && fault == NONE);
    return test_finish("Ip2location ABI1 focused checks");
}
