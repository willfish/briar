/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Existing named-test seams observe provider-owned failures and originals,
 * while leaving shared regex, HTTP preparation and transport policy intact. */
#define br_result_set_verification_error ipgeolocation_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static void *checked_malloc(size_t);
static void checked_free(void *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define free checked_free
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_ipgeolocation_init observed_ipgeolocation_init
#include "../../src/detectors/ipgeolocation.c"
#undef malloc
#undef free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_ipgeolocation_init

static const char key_a[] = "g7h9j2k5l6m8n3p4q1r0s2t4u6v8w1x3";
static const char key_b[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7l6k5j4";
static const char keyword[] = "ipgeolocation";
static const char url_prefix[] = "https://api.ipgeolocation.io/ipgeo?apiKey=";
enum { URL_SIZE = sizeof(url_prefix) + 32 };
typedef enum { NONE, CAPTURE, FINDING, URL, PUSH } fault_site;
static fault_site fault;
static size_t nth, urls, url_frees, sends, releases, setter_calls;
static bool fault_hit, omit_cause, expected_verified;
static br_captures *original_keys;
static br_result *candidate;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static char *original_url;

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return ipgeolocation_real_setter(result, cause, secrets, count);
}

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_context && !original_url);
    fault = NONE; nth = 0; fault_hit = omit_cause = false;
    urls = url_frees = sends = releases = 0;
    original_keys = NULL; candidate = NULL;
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
        CHECK(original_request->detector_type == 356 && !original_request->headers && !original_request->nheaders);
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
    CHECK(original_url);
    return original_url;
}

static void checked_free(void *value)
{
    CHECK(!original_request && !original_context);
    if (value && value == original_url) {
        original_values(); original_url = NULL; ++url_frees;
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
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    original_request = request; original_context = ctx; original_values(); ++sends;
    int rc = br_http_send(ctx, request, response, error);
    if (rc != 0 && omit_cause) { free(*error); *error = NULL; }
    expected_verified = rc == 0 && response->status >= 200 && response->status < 300;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && ctx == original_context && sends == releases + 1);
    original_values();
    CHECK(candidate && candidate->verified == expected_verified && !candidate->verification_error);
    CHECK(candidate->raw.len == 32 && candidate->secret_parts);
    CHECK(!memcmp(candidate->raw.data, original_keys->items[urls - 1], 32));
    br_http_release(ctx, response);
    original_values();
    original_request = NULL; original_context = NULL; ++releases;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !original_url);
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid IPGeolocation detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 356 && !d->version && !strcmp(d->name, "IPGeolocation") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "IPGeolocation provides geolocation information about IP addresses. The API key can be used to access and retrieve this data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], keyword));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Registry/default/native integration belongs to the parent. */
}

static void finding(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 356, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
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
        {"ipgeolocation '%s'", true}, {"IpGeOlOcAtIoN:%s", true}, {"myIPGEOLOCATIONsuffix:%s", true},
        {"ipgeolocation\r\n%s", true}, {"ipgeolocation\r%s", true}, {"ipgeolocation\n%s", true},
        {"ipgeolocation\t  %s  ", true}, {"ipgeolocation-%s-", true},
        {"%s", false}, {"%s ipgeolocation", false}, {"ipgeo location %s", false},
        {"ipgeolocation%s", false}, {"ipgeolocation x%s", false}, {"ipgeolocation _%s", false},
        {"ipgeolocation %s_", false}, {"ipgeolocation %s9", false}, {"ipgeolocation %.31s", false},
        {"ipgeolocation %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a, key_b);
        extract_case(d, input, strlen(input), cases[i].match ? key_a : NULL);
    }
    const char invalid[] = "AZ_-/ =";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "ipgeolocation %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "0az"; /* No hex-only, randomness, entropy or local FP filter. */
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 32); changed[32] = '\0';
        snprintf(input, sizeof(input), "ipgeolocation %s", changed);
        extract_case(d, input, strlen(input), changed);
    }
    size_t prefix_len = sizeof(keyword) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, keyword, prefix_len); memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key_a, 32);
        extract_case(d, input, prefix_len + gap + 32, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + prefix_len + 2 * i, "\xc3\xa9", 2);
        memcpy(input + prefix_len + 2 * gap, key_a, 32);
        extract_case(d, input, prefix_len + 2 * gap + 32, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "ipgeolocation%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("IPGeolocation keyword-only CI/lower-alphanumeric nonhex/prefix 40-41/boundaries/TrimSpace/binary input: 0 failures");
}

typedef struct {
    const char *const *keys;
    size_t count;
    const char *agent;
    const br_scan_ctx *ctx;
    const br_http_response *responses;
} request_script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx == script->ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == URL_SIZE - 1);
    CHECK(!memcmp(request->url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!strcmp(request->url + sizeof(url_prefix) - 1, script->keys[at]));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 356);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, script->agent));
    /* Never retain effective request/header-array/synthesized UA storage. */
    if (script->responses) http->response = script->responses[at];
}

static void occurrences(const br_detector *d)
{
    char input[192], unchanged[192];
    snprintf(input, sizeof(input), "ipgeolocation %s\nIPGEOLOCATION %s\nipgeolocation %s", key_a, key_b, key_a);
    strcpy(unchanged, input);
    const char *keys[] = {key_a, key_b, key_a};
    const br_http_response responses[] = {
        {.status = 200, .body_error = ""}, {.status = 401, .body_error = "ignored read failure"}, {.status = 299},
    };
    request_script script = {.keys = keys, .count = 3, .agent = "TruffleHog ipgeolocation-offline", .responses = responses};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "ipgeolocation-offline"}; script.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        reset_observation();
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], pass != 0 && i != 1);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        CHECK(!strcmp(input, unchanged)); br_results_clear(&out);
    }
    reset_observation(); br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && http.calls == 3 && http.releases == 3); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static void response_policy(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "ipgeolocation %s", key_a);
    const char *keys[] = {key_a};
    request_script script = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; script.ctx = &ctx;
    static const unsigned char binary[] = {0xff, 0, '{', '!'};
    const struct { int status; br_slice body; const char *read_error; bool verified; } cases[] = {
        {199, {binary, sizeof(binary)}, "ignored read failure", false}, {200, {0}, NULL, true},
        {201, {binary, sizeof(binary)}, "", true}, {204, {binary, sizeof(binary)}, "ignored read failure", true},
        {299, {(const unsigned char *)"not JSON", 8}, "ignored read failure", true},
        {300, {0}, NULL, false}, {401, {0}, "", false}, {403, {binary, sizeof(binary)}, "ignored", false},
        {429, {binary, sizeof(binary)}, "ignored read failure", false}, {500, {0}, NULL, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key_a, cases[i].verified); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create IPGeolocation result"}, {7, "cannot construct IPGeolocation URL"},
        {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, ""}, {1, key_a},
        {7, "net/http: nil Context"}, {1, "context canceled"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(*failures); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body = {binary, sizeof(binary)}, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void setup_and_null(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "ipgeolocation %s", key_a);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_transport missing_send = {&http, NULL, test_http_release};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &missing_send}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(sends == 1 && releases == 1 && urls == 1 && url_frees == 1);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && urls == 1 && url_frees == 1 && !sends && !releases); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !urls && !sends && !releases); finding(&out.items[0], key_a, false); br_results_clear(&out);
    br_scan_ctx ctx = {.transport = &transport}; http.send_rc = 1;
    reset_observation(); omit_cause = true;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && sends == 1 && releases == 1 && http.calls == 1);
    finding(&out.items[0], key_a, false); br_results_clear(&out);
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence,
                        bool verify, bool nil, int send_rc, const char *message, size_t attempts)
{
    char input[128]; snprintf(input, sizeof(input), "ipgeolocation %s\nipgeolocation %s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot create IPGeolocation result" : NULL,
        .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) != 0);
    CHECK(error && !strcmp(error, message)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_url);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(url_frees + (site == URL ? 1u : 0u) == urls);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 0, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 0, "cannot create IPGeolocation result", 0);
    own_failure(d, FINDING, 2, true, false, 0, "cannot create IPGeolocation result", 1);
    own_failure(d, FINDING, 2, false, false, 0, "cannot create IPGeolocation result", 0);
    own_failure(d, URL, 1, true, true, 0, "cannot construct IPGeolocation URL", 0);
    own_failure(d, URL, 2, true, false, -7, "cannot construct IPGeolocation URL", 1);
    own_failure(d, PUSH, 2, true, false, 0, "cannot append IPGeolocation result", 2);
    own_failure(d, PUSH, 2, true, false, 7, "cannot append IPGeolocation result", 2);
    own_failure(d, PUSH, 2, false, false, 0, "cannot append IPGeolocation result", 0);
    reset_observation(); br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) != 0);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) != 0);
    CHECK(!out.len && !urls && !sends);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 32 && strlen(key_b) == 32);
    const br_detector *d = descriptor(br_ipgeolocation_init);
    grammar(d); occurrences(d); response_policy(d);
    puts("IPGeolocation original occurrences/duplicates/Raw-key-only metadata/exact apiKey GET/SANE5/common UA: 0 failures");
    const br_detector *observed = descriptor(observed_ipgeolocation_init);
    occurrences(observed); response_policy(observed); setup_and_null(observed);
    puts("IPGeolocation all-2xx/ignored bodies and read errors/whole mixed setup and Do failures/no setter: 0 failures");
    puts("IPGeolocation finding then full URL before nil drop/one release each attempt/provider originals through release: 0 failures");
    owned_resources(observed);
    CHECK(!original_request && !original_context && !original_url && fault == NONE && !setter_calls);
    puts("IPGeolocation every owned nonzero fatal/invocation-only caller-preserving rollback: 0 failures");
    return test_finish("IPGeolocation ABI1 focused checks");
}
