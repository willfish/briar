/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Reuse the named-test inclusion seam for owned failures and provider lifetimes;
 * shared preparation, regex, findings and the injected transport remain real. */
static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static size_t checked_find(br_slice, br_slice, size_t);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_slice_find checked_find
#define br_results_push checked_push
#define br_ipapi_init observed_ipapi_init
#include "../../src/detectors/ipapi.c"
#undef malloc
#undef free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_slice_find
#undef br_results_push
#undef br_ipapi_init

#define BYTES(s) {(const unsigned char *)(s), sizeof(s) - 1}
static const char key_a[] = "g7h9j2k5l6m8n3p4q1r0s2t4u6v8w1x3";
static const char key_b[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7l6k5j4";
static const char url_prefix[] = "https://api.ipapi.com/49.146.239.251?access_key=";
static const char restricted[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
enum { URL_SIZE = sizeof(url_prefix) + 32 };
typedef enum { NONE, CAPTURE, FINDING, URL, BODY, PUSH } fault_site;
static fault_site fault;
static size_t nth, urls, url_frees, sends, releases, projections, pushes;
static bool fault_hit, project_body;
static br_captures *original_keys;
static br_result *candidate;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static char *original_url;
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
    CHECK(!original_request && !original_context && !original_url && !original_cause);
    fault = NONE; nth = 0; fault_hit = project_body = false;
    urls = url_frees = sends = releases = projections = pushes = 0;
    original_keys = NULL; candidate = NULL;
}

static void original_values(void)
{
    CHECK(original_keys && original_url && urls && urls <= original_keys->len);
    CHECK(original_keys->lengths[urls - 1] == 32);
    CHECK(!memcmp(original_url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(original_url + sizeof(url_prefix) - 1, original_keys->items[urls - 1], 33));
    CHECK(candidate && candidate->raw.len == 32 && candidate->secret_parts && !candidate->verification_error);
    CHECK(!memcmp(candidate->raw.data, original_keys->items[urls - 1], 32));
    if (original_request) {
        CHECK(original_request->url == original_url && !strcmp(original_request->method, "GET"));
        CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms);
        CHECK(original_request->detector_type == 362 && !original_request->headers && !original_request->nheaders);
        CHECK(!original_request->body.data && !original_request->body.len);
        CHECK(!original_request->dedup_key.data && !original_request->dedup_key.len);
    }
}

static void *checked_malloc(size_t size)
{
    CHECK(size == URL_SIZE && candidate && candidate->raw.len == 32 && candidate->secret_parts);
    CHECK(!candidate->verified && !candidate->verification_error && !original_url);
    ++urls;
    if (hit(URL)) return NULL;
    original_url = malloc(size);
    return original_url;
}

static void checked_free(void *value)
{
    CHECK(!original_request && !original_context);
    if (value && value == original_url) {
        original_values(); original_url = NULL; ++url_frees;
    }
    if (value && value == original_cause) {
        CHECK(!strcmp(original_cause, saved_cause)); original_cause = NULL;
    }
    free(value);
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
    original_request = request; original_context = ctx; original_values(); ++sends;
    CHECK(!candidate->verified);
    int rc = br_http_send(ctx, request, response, error);
    if (rc == 0 && hit(BODY)) response->body = (br_slice){NULL, 1};
    projections = 0;
    project_body = rc == 0 && !response->body_error && (response->body.data || !response->body.len);
    original_cause = *error;
    if (original_cause) {
        CHECK(strlen(original_cause) < sizeof(saved_cause)); strcpy(saved_cause, original_cause);
    }
    return rc;
}

static size_t checked_find(br_slice body, br_slice needle, size_t start)
{
    CHECK(original_request && project_body && !candidate->verified && !start);
    original_values();
    CHECK(projections < 2);
    const char *expected = projections ? restricted : "continent_code";
    CHECK(needle.len == strlen(expected) && !memcmp(needle.data, expected, needle.len));
    ++projections;
    return br_slice_find(body, needle, start);
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && ctx == original_context && sends == releases + 1);
    original_values();
    CHECK(project_body ? projections >= 1 && projections <= 2 : !projections);
    if (original_cause) CHECK(!strcmp(original_cause, saved_cause));
    br_http_release(ctx, response);
    original_values();
    original_request = NULL; original_context = NULL; ++releases;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !original_context && sends == releases && result == candidate);
    ++pushes;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error); free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 362 && !d->version && !strcmp(d->name, "Ipapi") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Ipapi provides an API for IP address lookup and geolocation. Ipapi keys can be used to access this service and retrieve geolocation data for IP addresses."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ipapi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Enabled default/registry/native integration belongs to the parent. */
}

static void finding(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 362, key, "key");
    CHECK(r->raw.len == 32 && r->verified == verified && !r->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) finding(&out.items[0], key, false);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[256], changed[33];
    const struct { const char *format; bool match; } cases[] = {
        {"ipapi '%s'", true}, {"IpApI:%s", true}, {"myIPAPIsuffix:%s", true},
        {"ipapi\r\n%s", true}, {"ipapi\r%s", true}, {"ipapi\n%s", true},
        {"ipapi\t  %s  ", true}, {"ipapi-%s-", true},
        {"%s", false}, {"%s ipapi", false}, {"ip api %s", false},
        {"ipapi%s", false}, {"ipapi x%s", false}, {"ipapi _%s", false},
        {"ipapi %s_", false}, {"ipapi %s9", false}, {"ipapi %.31s", false},
        {"ipapi %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a, key_b);
        extract_case(d, input, strlen(input), cases[i].match ? key_a : NULL);
    }
    const char invalid[] = "AGZ_-/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "ipapi %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "0agz"; /* Neither hex-only nor a local FP/entropy filter. */
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 32); changed[32] = '\0';
        snprintf(input, sizeof(input), "ipapi %s", changed);
        extract_case(d, input, strlen(input), changed);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ipapi", 5); memset(input + 5, '.', gap);
        memcpy(input + 5 + gap, key_a, 32);
        extract_case(d, input, 37 + gap, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 5 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 5 + 2 * gap, key_a, 32);
        extract_case(d, input, 37 + 2 * gap, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "ipapi%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("Ipapi lower-alphanumeric/nonhex/prefix/rune gap/boundaries/TrimSpace/binary input: 0 failures");
}

typedef struct { const char *const *keys; size_t count; const char *agent; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == URL_SIZE - 1);
    CHECK(!memcmp(request->url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!strcmp(request->url + sizeof(url_prefix) - 1, script->keys[at]));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 362);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, script->agent));
    /* Effective request/header-array/synthesized UA are borrowed only in send. */
}

static void occurrences(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "ipapi %s\nIPAPI %s\nipapi %s", key_a, key_b, key_a);
    const char *keys[] = {key_a, key_b, key_a};
    request_script script = {keys, 3, "TruffleHog ipapi-offline"};
    test_http http = {.inspect = inspect, .user = &script,
        .response = {.status = 204, .body = BYTES("notJSON:continent_code!")}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "ipapi-offline"};
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    puts("Ipapi original occurrences/duplicates/Raw-key-only metadata/exact bodyless GET/common UA: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "ipapi %s", key_a);
    const char *keys[] = {key_a}; request_script script = {keys, 1, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; br_slice body; const char *read_error; bool valid; } cases[] = {
        {0, BYTES("continent_code"), NULL, false}, {199, BYTES("continent_code"), NULL, false},
        {200, BYTES("continent_code"), NULL, true}, {201, BYTES("!notcontinent_codeword!"), NULL, true},
        {204, BYTES(restricted), NULL, true}, {299, BYTES("\xff\0junkcontinent_code!"), NULL, true},
        {300, BYTES(restricted), NULL, false}, {401, BYTES("continent_code"), NULL, false},
        {403, BYTES(restricted), NULL, false}, {429, BYTES("continent_code"), NULL, false},
        {500, BYTES(restricted), NULL, false},
        {200, BYTES("broken\0!\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"!"), NULL, true},
        {200, BYTES("CONTINENT_CODE"), NULL, false}, {200, BYTES("continent code"), NULL, false},
        {200, BYTES("{\"info\": \"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"}"), NULL, false},
        {200, BYTES("info:\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, false},
        {200, BYTES("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."), NULL, false},
        {200, BYTES("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption\""), NULL, false},
        {200, BYTES("\"info\":\"access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, false},
        {200, BYTES("\"info\":\"Access  Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, false},
        {200, BYTES("Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."), NULL, false},
        {200, {0}, NULL, false},
        {200, BYTES("continent_code"), "", false}, {204, BYTES(restricted), "partial read", false},
        {500, {NULL, 1}, "", false}, {200, {NULL, 1}, "read failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && sends == 1 && releases == 1);
        finding(&out.items[0], key_a, cases[i].valid); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } errors[] = {
        {1, "context canceled"}, {-7, "context deadline exceeded"},
        {1, "cannot create Ipapi finding"}, {-1, "invalid Ipapi response body slice"},
        {1, "out of memory constructing HTTP headers"}, {7, "net/http: nil Context"},
        {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = (br_http_response){.status = 200, .body = {NULL, 1}};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !projections);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    puts("Ipapi every-status read/exact binary markers before status/only 2xx/any read-error pointer keeps false/no setter: 0 failures");
    puts("Ipapi whole mixed setup/Do errors kept false without diagnostic classification or body projection: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void setup_and_null(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "ipapi %s", key_a);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_transport missing_send = {&http, NULL, test_http_release}, missing_release = {&http, test_http_send, NULL};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &missing_send}, {.transport = &missing_release},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i == 0 || i == 2 ? 0u : 1u));
        CHECK(sends == 1 && releases == 1 && pushes == 1 && url_frees == 1 && !projections);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && urls == 1 && url_frees == 1 && !sends && !pushes); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !urls && !sends); finding(&out.items[0], key_a, false); br_results_clear(&out);
    puts("Ipapi shared preparation/guard failures release once/full finding and URL before nil drop/NoV zero I/O: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify, bool nil,
                        int status, const char *read_error, int send_rc, const char *message, size_t attempts)
{
    char input[96]; snprintf(input, sizeof(input), "ipapi %s\nipapi %s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot append Ipapi finding" : NULL,
        .response = {.status = status, .body = BYTES("continent_code"), .body_error = read_error}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, message)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_url && !original_cause);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(url_frees + (site == URL ? 1u : 0u) == urls);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 200, NULL, 0, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 200, NULL, 0, "cannot create Ipapi finding", 0);
    own_failure(d, FINDING, 2, true, false, 200, NULL, 0, "cannot create Ipapi finding", 1);
    own_failure(d, URL, 1, true, true, 200, NULL, 0, "cannot construct Ipapi URL", 0);
    own_failure(d, URL, 2, true, false, 200, NULL, 0, "cannot construct Ipapi URL", 1);
    own_failure(d, BODY, 2, true, false, 200, NULL, 0, "invalid Ipapi response body slice", 2);
    own_failure(d, BODY, 2, true, false, 503, NULL, 0, "invalid Ipapi response body slice", 2);
    own_failure(d, PUSH, 2, true, false, 200, NULL, 0, "cannot append Ipapi finding", 2);
    own_failure(d, PUSH, 2, true, false, 503, NULL, 0, "cannot append Ipapi finding", 2);
    own_failure(d, PUSH, 2, true, false, 200, "", 0, "cannot append Ipapi finding", 2);
    own_failure(d, PUSH, 2, true, false, 200, NULL, 7, "cannot append Ipapi finding", 2);
    own_failure(d, PUSH, 2, false, false, 200, NULL, 0, "cannot append Ipapi finding", 0);
    reset_observation(); br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !urls && !sends);
    puts("Ipapi owned nonzero capture/finding/URL/body/push fatal before outcomes/invocation-only caller-preserving rollback: 0 failures");
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 32 && strlen(key_b) == 32);
    const br_detector *d = descriptor(br_ipapi_init);
    grammar(d); occurrences(d);
    const br_detector *observed = descriptor(observed_ipapi_init);
    response_policy(observed); setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_context && !original_url && !original_cause && fault == NONE);
    return test_finish("Ipapi ABI1 focused checks");
}
