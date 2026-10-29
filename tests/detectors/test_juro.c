/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_juro_init(const br_detector **out, char **error);

#define br_result_set_verification_error juro_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error

static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
#define br_captures_find checked_captures
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_juro_init observed_juro_init
#include "../../src/detectors/juro.c"
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_juro_init

static const char key_a[] = "b2hKUaFGc0nyBmk3xRr0cyPCzRJOGW97G9WIhBtQ";
static const char key_b[] = "0123456789ABCDEFGHIJabcdefghij0123456789";
static const char keyword[] = "juro";
static const char url[] = "https://api.juro.com/v3/templates";
typedef enum { NONE, CAPTURE, FINDING, PUSH } fault_site;
static fault_site fault;
static size_t nth, sends, releases, setter_calls;
static bool fault_hit, omit_cause, expected_verified;
static br_captures *original_keys;
static br_result *candidate;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static const char *sent_header;

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return juro_real_setter(result, cause, secrets, count);
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
    CHECK(!original_request && !original_context && !sent_header);
    fault = NONE;
    nth = 0;
    fault_hit = omit_cause = expected_verified = false;
    sends = releases = 0;
    original_keys = NULL;
    candidate = NULL;
}

static void check_request(const br_http_request *request)
{
    CHECK(request && request->url && !strcmp(request->url, url) && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && !request->timeout_ms && request->detector_type == 295);
    CHECK(request->nheaders == 1 && request->headers && !strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(request->headers[0].value && request->headers[0].value[40] == '\0');
    CHECK(!memcmp(request->headers[0].value, candidate->raw.data, 40));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
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

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(!original_request && !original_context && !sent_header && sends == releases);
    CHECK(candidate && !candidate->verified && !candidate->verification_error);
    original_request = request;
    original_context = ctx;
    check_request(request);
    sent_header = request->headers[0].value;
    ++sends;
    int rc = br_http_send(ctx, request, response, error);
    if (rc != 0 && omit_cause) {
        free(*error);
        *error = NULL;
    }
    expected_verified = rc == 0 && response->status >= 200 && response->status < 300;
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(original_request && ctx == original_context && sends == releases + 1);
    check_request(original_request);
    CHECK(sent_header && sent_header == original_request->headers[0].value);
    CHECK(sent_header[40] == '\0' && !memcmp(sent_header, candidate->raw.data, 40));
    CHECK(candidate->verified == expected_verified && !candidate->verification_error);
    br_http_release(ctx, response);
    check_request(original_request);
    original_request = NULL;
    original_context = NULL;
    sent_header = NULL;
    ++releases;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(!original_request && !sent_header);
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid Juro detector output"));
    free(error);
    CHECK(init(NULL, NULL) != 0);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 295 && !d->version && !strcmp(d->name, "Juro") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Juro is a contract automation platform. Juro API keys can be used to access and manage contract templates and other resources in Juro."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], keyword));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *key, bool verified)
{
    test_key_result(result, 295, key, "key");
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
    char input[320], changed[41];
    snprintf(input, sizeof(input), "juro token = '%s'", key_a);
    extract_case(d, input, strlen(input), key_a);
    snprintf(input, sizeof(input), "juro token = '%s' | '%s'", key_a, key_a);
    extract_case(d, input, strlen(input), key_a);
    snprintf(input, sizeof(input), "juro keyword is not close to the real key in the data\n = '%s'", key_a);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "juro = '%s'", "b2hKUaFGc0nyBmk3xRr0cyPCzRJOGW97G9WIhBt");
    extract_case(d, input, strlen(input), NULL);
    const char *formats[] = {"JURO '%s'", "Juro:%s", "prefixJUROsuffix\r\n%s", "juro\r%s", "juro\n%s", "juro \t%s\t "};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key_b);
        extract_case(d, input, strlen(input), key_b);
    }
    memset(changed, 'Z', 40);
    changed[40] = '\0';
    snprintf(input, sizeof(input), "juro %s", changed);
    extract_case(d, input, strlen(input), changed);
    const char *missing[] = {"%s", "%s juro", "ju ro %s", "juro%s", "juro _%s", "juro %s_", "juro %sa"};
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i) {
        snprintf(input, sizeof(input), missing[i], key_b);
        extract_case(d, input, strlen(input), NULL);
    }
    const char invalid[] = {'_', '-', '/', ' ', '.'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key_a, 41);
        changed[12] = invalid[i];
        snprintf(input, sizeof(input), "juro %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    size_t prefix_len = sizeof(keyword) - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, keyword, prefix_len);
        memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key_a, 40);
        extract_case(d, input, prefix_len + gap + 40, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + prefix_len + 2 * i, "\xc3\xa9", 2);
        memcpy(input + prefix_len + 2 * gap, key_b, 40);
        extract_case(d, input, prefix_len + 2 * gap + 40, gap == 40 ? key_b : NULL);
    }
    memcpy(input, "juro\0", 5);
    memcpy(input + 5, key_a, 40);
    extract_case(d, input, 45, key_a);
    extract_case(d, NULL, 0, NULL);
    snprintf(input, sizeof(input), "juro %s juro %s", key_a, key_b);
    reset_observation();
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 2 && !http.calls && !http.releases);
    finding(&out.items[0], key_a, false);
    finding(&out.items[1], key_b, false);
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

static const char *borrowed_url, *borrowed_header, *expected_key;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user;
    size_t at = http->calls - 1;
    CHECK(ctx == script->ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 295);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && request->headers);
    CHECK(!strcmp(request->headers[0].name, "X-Api-Key"));
    CHECK(!strcmp(request->headers[0].value, script->keys[at]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, script->agent));
    borrowed_url = request->url;
    borrowed_header = request->headers[0].value;
    expected_key = script->keys[at];
    if (script->responses) http->response = script->responses[at];
}

static void release_response(void *user, br_http_response *response)
{
    if (borrowed_url) {
        CHECK(!strcmp(borrowed_url, url));
        CHECK(borrowed_header && !strcmp(borrowed_header, expected_key));
    }
    borrowed_url = borrowed_header = expected_key = NULL;
    test_http_release(user, response);
}

static void occurrences(const br_detector *d)
{
    char input[220], unchanged[220];
    snprintf(input, sizeof(input), "juro %s\nJURO %s\njuro %s", key_a, key_b, key_a);
    strcpy(unchanged, input);
    const char *keys[] = {key_a, key_b, key_a};
    static const unsigned char junk[] = {0xff, 0, '{'};
    const br_http_response responses[] = {
        {.status = 500, .body = {junk, sizeof(junk)}, .body_error = "ignored read failure"},
        {.status = 204, .body_error = ""},
        {.status = 401, .body = {(const unsigned char *)"not read", 8}, .body_error = "ignored"},
    };
    request_script script = {.keys = keys, .count = 3, .agent = "TruffleHog juro-offline", .responses = responses};
    test_http http = {.inspect = inspect, .user = &script};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "juro-offline"};
    script.ctx = &ctx;
    reset_observation();
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 3 && !http.calls && !http.releases && !borrowed_url && !borrowed_header);
    for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    CHECK(!strcmp(input, unchanged));
    br_results_clear(&out);
    reset_observation();
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3 && !borrowed_url && !borrowed_header);
    finding(&out.items[0], key_a, false);
    finding(&out.items[1], key_b, true);
    finding(&out.items[2], key_a, false);
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
    snprintf(input, sizeof(input), "juro %s", key_a);
    const char *keys[] = {key_a};
    request_script script = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport};
    script.ctx = &ctx;
    static const unsigned char binary[] = {0xff, 0, 'x'};
    const struct { int status; br_slice body; const char *read_error; bool verified; } cases[] = {
        {199, {binary, sizeof(binary)}, "ignored read failure", false},
        {200, {0}, NULL, true},
        {200, {binary, sizeof(binary)}, "", true},
        {204, {binary, sizeof(binary)}, "synthetic read failure", true},
        {299, {(const unsigned char *)"not JSON", 8}, "ignored", true},
        {300, {0}, NULL, false},
        {401, {binary, sizeof(binary)}, "", false},
        {500, {0}, "read failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !borrowed_url);
        finding(&out.items[0], key_a, cases[i].verified);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Juro result"}, {7, "cannot construct Juro URL"},
        {1, "out of memory constructing HTTP headers"}, {-1, NULL}, {1, ""}, {1, key_a},
        {7, "net/http: nil Context"}, {1, "context canceled"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        reset_observation();
        http.calls = http.releases = 0;
        http.send_rc = failures[i].rc;
        http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body = {binary, sizeof(binary)}, .body_error = "ignored after Do error"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !borrowed_url);
        finding(&out.items[0], key_a, false);
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
    snprintf(input, sizeof(input), "juro %s", key_a);
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
        CHECK(sends == 1 && releases == 1 && !setter_calls);
        finding(&out.items[0], key_a, false);
        br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation();
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && !sends && !releases && !setter_calls);
    br_results_clear(&out);
    reset_observation();
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !sends && !releases);
    finding(&out.items[0], key_a, false);
    br_results_clear(&out);
    br_scan_ctx ctx = {.transport = &transport};
    http.send_rc = 1;
    http.send_error = "timeout";
    reset_observation();
    omit_cause = true;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && sends == 1 && releases == 1 && http.calls == 1 && !setter_calls);
    finding(&out.items[0], key_a, false);
    br_results_clear(&out);
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence,
                        bool verify, bool nil, int send_rc, const char *message, size_t attempts)
{
    char input[160];
    snprintf(input, sizeof(input), "juro %s\njuro %s", key_a, key_b);
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
        .response = {.status = 204, .body_error = "ignored"},
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
    CHECK(fault == NONE && !nth && fault_hit && !original_request && !sent_header && !setter_calls);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 0, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 0, "cannot create Juro result", 0);
    own_failure(d, FINDING, 2, true, false, 0, "cannot create Juro result", 1);
    own_failure(d, FINDING, 2, false, false, 0, "cannot create Juro result", 0);
    own_failure(d, PUSH, 2, true, false, 0, "cannot append Juro result", 2);
    own_failure(d, PUSH, 2, true, false, 7, "cannot append Juro result", 2);
    own_failure(d, PUSH, 2, false, false, 0, "cannot append Juro result", 0);
    reset_observation();
    br_results out = {0};
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) != 0);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) != 0);
    CHECK(!out.len && !sends && !setter_calls);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 40 && strlen(key_b) == 40);
    const br_detector *d = descriptor(br_juro_init);
    grammar(d);
    occurrences(d);
    response_policy(d);
    const br_detector *observed = descriptor(observed_juro_init);
    grammar(observed);
    occurrences(observed);
    response_policy(observed);
    setup_and_null(observed);
    owned_resources(observed);
    CHECK(!original_request && !original_context && !sent_header && fault == NONE && !setter_calls && !borrowed_url);
    return test_finish("Juro");
}
