/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

/* Factory is not in the shared header yet. Parent owns that declaration. */
int br_ipstack_init(const br_detector **out, char **error);

#define br_result_set_verification_error ipstack_real_setter
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
#define br_ipstack_init observed_ipstack_init
#include "../../src/detectors/ipstack.c"
#undef malloc
#undef free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_ipstack_init

static const char key_mixed[] = "FA0E2B0be2fd6076b59c8696783eadeB";
static const char key_lower[] = "0123456789abcdef0123456789abcdef";
static const char key_upper[] = "0123456789ABCDEF0123456789ABCDEF";
static const char keyword[] = "ipstack";
static const char url_prefix[] = "https://api.ipstack.com/134.201.250.155?access_key=";
static const char restricted[] =
    "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
enum { URL_SIZE = sizeof(url_prefix) + 32 };
typedef enum { NONE, CAPTURE, FINDING, URL, PUSH } fault_site;
static fault_site fault;
static size_t nth, urls, url_frees, sends, releases, setter_calls;
static bool fault_hit, omit_cause, expected_verified, expected_drop;
static br_captures *original_keys;
static br_result *candidate;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static char *original_url;

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return ipstack_real_setter(result, cause, secrets, count);
}

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE;
    fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_context && !original_url);
    fault = NONE;
    nth = 0;
    fault_hit = omit_cause = expected_verified = expected_drop = false;
    urls = url_frees = sends = releases = 0;
    original_keys = NULL;
    candidate = NULL;
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
        CHECK(original_request->detector_type == 133 && !original_request->headers && !original_request->nheaders);
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
        original_values();
        original_url = NULL;
        ++url_frees;
    }
    free(value);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique && !original_keys);
    original_keys = out;
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure");
        CHECK(*error);
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

static bool body_has_needle(br_slice body)
{
    const br_slice continent = {(const unsigned char *)"continent_code", 14};
    const br_slice plan = {(const unsigned char *)restricted, sizeof(restricted) - 1};
    return br_slice_find(body, continent, 0) != SIZE_MAX || br_slice_find(body, plan, 0) != SIZE_MAX;
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(!original_request && !original_context && sends == releases);
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    original_request = request;
    original_context = ctx;
    original_values();
    ++sends;
    int rc = br_http_send(ctx, request, response, error);
    if (rc != 0 && omit_cause) {
        free(*error);
        *error = NULL;
    }
    expected_drop = rc == 0 && response->body_error;
    expected_verified = rc == 0 && !response->body_error && body_has_needle(response->body);
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && ctx == original_context && sends == releases + 1);
    original_values();
    CHECK(candidate && candidate->verified == expected_verified && !candidate->verification_error);
    CHECK(!expected_drop || !candidate->verified);
    CHECK(candidate->raw.len == 32 && candidate->secret_parts);
    CHECK(!memcmp(candidate->raw.data, original_keys->items[urls - 1], 32));
    br_http_release(ctx, response);
    original_values();
    original_request = NULL;
    original_context = NULL;
    ++releases;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !original_url && !expected_drop);
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid IpStack detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 133 && !d->version && !strcmp(d->name, "IpStack") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "IpStack provides a REST API for IP geolocation services. IpStack API keys can be used to access geolocation data for IP addresses."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], keyword));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 133, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    reset_observation();
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) finding(&out.items[0], key, false);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[320], changed[33];
    snprintf(input, sizeof(input), "ipstack token = '%s'", key_mixed);
    extract_case(d, input, strlen(input), key_mixed);
    snprintf(input, sizeof(input), "ipstack token = '%s' | '%s'", key_mixed, key_mixed);
    extract_case(d, input, strlen(input), key_mixed); /* Keyword consumption, not uniqueness. */
    snprintf(input, sizeof(input), "ipstack keyword is not close to the real key in the data\n = '%s'", key_mixed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "ipstack = '%s'", "FA0E2B0be2fd6076b59c8696783eade");
    extract_case(d, input, strlen(input), NULL);
    const char *formats[] = {"IPSTACK '%s'", "IpStack:%s", "prefixIPSTACKsuffix\r\n%s", "ipstack\r%s", "ipstack\n%s", "ipstack \t%s\t "};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key_upper);
        extract_case(d, input, strlen(input), key_upper);
    }
    snprintf(input, sizeof(input), "ipstack %s", key_lower);
    extract_case(d, input, strlen(input), key_lower);
    const char *missing[] = {"%s", "%s ipstack", "ip stack %s", "ipstack%s", "ipstack _%s", "ipstack %s_", "ipstack %sg"};
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i) {
        snprintf(input, sizeof(input), missing[i], key_lower);
        extract_case(d, input, strlen(input), NULL);
    }
    const char invalid[] = {'g', 'G', 'z', '_', '-', '/', ' '};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key_lower, 33);
        changed[8] = invalid[i];
        snprintf(input, sizeof(input), "ipstack %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    memset(changed, 'a', 32);
    changed[32] = '\0';
    snprintf(input, sizeof(input), "ipstack %s", changed);
    extract_case(d, input, strlen(input), changed);
    memset(changed, 'F', 32);
    changed[32] = '\0';
    snprintf(input, sizeof(input), "ipstack %s", changed);
    extract_case(d, input, strlen(input), changed);
    size_t prefix_len = sizeof(keyword) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, keyword, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key_lower, 32);
        extract_case(d, input, prefix_len + gap + 32, gap == 40 ? key_lower : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + prefix_len + 2 * i, "\xc3\xa9", 2);
        memcpy(input + prefix_len + 2 * gap, key_mixed, 32);
        extract_case(d, input, prefix_len + 2 * gap + 32, gap == 40 ? key_mixed : NULL);
    }
    memcpy(input, "ipstack\0", 8);
    memcpy(input + 8, key_mixed, 32);
    extract_case(d, input, 40, key_mixed);
    extract_case(d, NULL, 0, NULL);
    snprintf(input, sizeof(input), "ipstack %s ipstack %s", key_mixed, key_lower);
    reset_observation();
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls && !http.releases);
    finding(&out.items[0], key_mixed, false);
    finding(&out.items[1], key_lower, false);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const char *agent;
    const br_scan_ctx *ctx;
    const br_http_response *responses;
} request_script;

static const char *borrowed_url, *expected_key;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user;
    size_t at = http->calls - 1;
    CHECK(ctx == script->ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == URL_SIZE - 1);
    CHECK(!memcmp(request->url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!strcmp(request->url + sizeof(url_prefix) - 1, script->keys[at]));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 133);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, script->agent));
    borrowed_url = request->url;
    expected_key = script->keys[at];
    if (script->responses) http->response = script->responses[at];
}

static void release_response(void *user, br_http_response *response)
{
    if (borrowed_url) {
        CHECK(!memcmp(borrowed_url, url_prefix, sizeof(url_prefix) - 1));
        CHECK(!strcmp(borrowed_url + sizeof(url_prefix) - 1, expected_key));
    }
    borrowed_url = expected_key = NULL;
    test_http_release(user, response);
}

static void occurrences(const br_detector *d)
{
    char input[192], unchanged[192];
    snprintf(input, sizeof(input), "ipstack %s\nIPSTACK %s\nipstack %s", key_mixed, key_lower, key_mixed);
    strcpy(unchanged, input);
    const char *keys[] = {key_mixed, key_lower, key_mixed};
    const br_http_response responses[] = {
        {.status = 500, .body = {(const unsigned char *)"x continent_code y", 19}, .body_error = "partial needle"},
        {.status = 401, .body = {(const unsigned char *)restricted, sizeof(restricted) - 1}},
        {.status = 200, .body = {(const unsigned char *)"latitude", 8}},
    };
    request_script script = {.keys = keys, .count = 3, .agent = "TruffleHog ipstack-offline", .responses = responses};
    test_http http = {.inspect = inspect, .user = &script};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "ipstack-offline"};
    script.ctx = &ctx;
    reset_observation();
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 3 && !http.calls && !http.releases && !borrowed_url);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    CHECK(!strcmp(input, unchanged));
    br_results_clear(&out);
    reset_observation();
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 3 && http.releases == 3 && !borrowed_url);
    finding(&out.items[0], key_lower, true);
    finding(&out.items[1], key_mixed, false);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    reset_observation();
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases);
    br_results_clear(&out);
    reset_observation();
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static void response_policy(const br_detector *d)
{
    char input[80];
    snprintf(input, sizeof(input), "ipstack %s", key_mixed);
    const char *keys[] = {key_mixed};
    request_script script = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    script.ctx = &ctx;
    static const unsigned char binary[] = {0xff, 0, 'c', 'o', 'n', 't', 'i', 'n', 'e', 'n', 't', '_', 'c', 'o', 'd', 'e', 0};
    char middle[160];
    snprintf(middle, sizeof(middle), "prefix %s suffix", restricted);
    struct { int status; br_slice body; const char *read_error; bool keep, verified; } cases[] = {
        {200, {(const unsigned char *)"continent_code", 14}, NULL, true, true},
        {401, {(const unsigned char *)"xxcontinent_code", 16}, NULL, true, true},
        {500, {(const unsigned char *)restricted, sizeof(restricted) - 1}, NULL, true, true},
        {199, {(const unsigned char *)middle, 0}, NULL, true, true},
        {302, {binary, sizeof(binary)}, NULL, true, true},
        {204, {(const unsigned char *)"latitude", 8}, NULL, true, false},
        {200, {(const unsigned char *)"CONTINENT_CODE", 14}, NULL, true, false},
        {200, {(const unsigned char *)"continent_cod", 13}, NULL, true, false},
        {200, {(const unsigned char *)"\"info\":\"Access Restricted\"", 28}, NULL, true, false},
        {200, {0}, NULL, true, false},
        {200, {(const unsigned char *)"continent_code", 14}, "", false, false},
        {401, {(const unsigned char *)restricted, sizeof(restricted) - 1}, "synthetic read failure", false, false},
        {500, {binary, sizeof(binary)}, "read failed", false, false},
    };
    cases[3].body.len = strlen(middle);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == (cases[i].keep ? 1u : 0u) && http.calls == 1 && http.releases == 1 && !borrowed_url);
        if (out.len) finding(&out.items[0], key_mixed, cases[i].verified);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create IpStack result"}, {7, "cannot construct IpStack URL"},
        {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, ""}, {1, key_mixed},
        {7, "net/http: nil Context"}, {1, "context canceled"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        http.send_rc = failures[i].rc;
        http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"continent_code", 14}, .body_error = "ignored after Do error"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !borrowed_url);
        finding(&out.items[0], key_mixed, false);
        br_results_clear(&out);
    }
}

static bool cancelled(void *user)
{
    ++*(size_t *)user;
    return true;
}

static void setup_and_null(const br_detector *d)
{
    char input[64];
    snprintf(input, sizeof(input), "ipstack %s", key_mixed);
    test_http http = {0};
    br_transport transport = {&http, test_http_send, release_response};
    br_transport missing_send = {&http, NULL, release_response};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0},
        {.transport = &missing_send},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(sends == 1 && releases == 1 && urls == 1 && url_frees == 1 && !setter_calls);
        finding(&out.items[0], key_mixed, false);
        br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation();
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && urls == 1 && url_frees == 1 && !sends && !releases && !setter_calls);
    br_results_clear(&out);
    reset_observation();
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !urls && !sends && !releases);
    finding(&out.items[0], key_mixed, false);
    br_results_clear(&out);
    br_scan_ctx ctx = {.transport = &transport};
    http.send_rc = 1;
    http.send_error = "timeout";
    reset_observation();
    omit_cause = true;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && sends == 1 && releases == 1 && http.calls == 1 && !setter_calls);
    finding(&out.items[0], key_mixed, false);
    br_results_clear(&out);
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence,
                        bool verify, bool nil, int send_rc, const char *message, size_t attempts)
{
    char input[128];
    snprintf(input, sizeof(input), "ipstack %s\nipstack %s", key_mixed, key_lower);
    br_results out = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    test_http http = {
        .send_rc = send_rc,
        .send_error = send_rc ? "synthetic Do failure" : NULL,
        .response = {.status = 401, .body = {(const unsigned char *)"continent_code", 14}},
    };
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    reset_observation();
    fault = site;
    nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify,
                  (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) != 0);
    CHECK(error && !strcmp(error, message));
    free(error);
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !original_url && !setter_calls);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(url_frees + (site == URL ? 1u : 0u) == urls);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 0, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 0, "cannot create IpStack result", 0);
    own_failure(d, FINDING, 2, true, false, 0, "cannot create IpStack result", 1);
    own_failure(d, FINDING, 2, false, false, 0, "cannot create IpStack result", 0);
    own_failure(d, URL, 1, true, true, 0, "cannot construct IpStack URL", 0);
    own_failure(d, URL, 2, true, false, -7, "cannot construct IpStack URL", 1);
    own_failure(d, PUSH, 2, true, false, 0, "cannot append IpStack result", 2);
    own_failure(d, PUSH, 2, true, false, 7, "cannot append IpStack result", 2);
    own_failure(d, PUSH, 2, false, false, 0, "cannot append IpStack result", 0);
    reset_observation();
    br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) != 0);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) != 0);
    CHECK(!out.len && !urls && !sends && !setter_calls);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_mixed) == 32 && strlen(key_lower) == 32 && strlen(key_upper) == 32);
    const br_detector *d = descriptor(br_ipstack_init);
    grammar(d);
    occurrences(d);
    response_policy(d);
    const br_detector *observed = descriptor(observed_ipstack_init);
    grammar(observed);
    occurrences(observed);
    response_policy(observed);
    setup_and_null(observed);
    owned_resources(observed);
    CHECK(!original_request && !original_context && !original_url && fault == NONE && !setter_calls && !borrowed_url);
    return test_finish("IpStack");
}
