/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_messagebird_init(const br_detector **out, char **error); /* Main owns the shared declaration. */

/* Existing named-test inclusion seam: real shared helpers plus focused owned
 * nonzero returns and original provider-storage observations through release. */
static int checked_compile(const char *const *, size_t, const char *, br_regex **, char **);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static void checked_captures_clear(br_captures *);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_push(br_results *, br_result *);
static void checked_free(void *);
static inline int forbidden_setter(br_result *r, const char *cause, const br_slice *secrets, size_t n)
{
    (void)r; (void)cause; (void)secrets; (void)n;
    CHECK(false);
    return 1;
}
#define br_regex_compile_prefixed checked_compile
#define br_captures_find checked_captures
#define br_captures_clear checked_captures_clear
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#define free checked_free
#define br_messagebird_init observed_messagebird_init
#include "../../src/detectors/messagebird.c"
#undef br_regex_compile_prefixed
#undef br_captures_find
#undef br_captures_clear
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_result_set_verification_error
#undef free
#undef br_messagebird_init

#define BYTES(s) {(const unsigned char *)(s), sizeof(s) - 1}
static char key_a[26], key_b[26];
static const char url[] = "https://rest.messagebird.com/messages";
typedef enum { NONE, COMPILE, CAPTURE, FINDING, PUSH } fault_site;
static fault_site fault;
static size_t nth, findings, pushes, sends, releases, capture_clears, causes_freed;
static bool fault_hit;
static br_result *candidate;
static br_slice original_key;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static const char *original_cause;
static char saved_cause[160];

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void reset_observation(void)
{
    CHECK(!original_request && !original_context && !original_cause);
    fault = NONE; nth = 0; fault_hit = false;
    findings = pushes = sends = releases = capture_clears = causes_freed = 0;
    candidate = NULL; original_key = (br_slice){0};
}

static int checked_compile(const char *const *keywords, size_t count, const char *pattern,
                           br_regex **out, char **error)
{
    CHECK(count == 1 && !strcmp(keywords[0], "messagebird"));
    CHECK(!strcmp(pattern, "\\b([A-Za-z0-9_-]{25})\\b"));
    if (hit(COMPILE)) {
        *out = NULL; *error = strdup("synthetic compile failure"); CHECK(*error);
        return 1;
    }
    return br_regex_compile_prefixed(keywords, count, pattern, out, error);
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

static void checked_captures_clear(br_captures *keys)
{
    CHECK(!original_request && !original_cause && sends == releases);
    br_captures_clear(keys); ++capture_clears;
    CHECK(!keys->items && !keys->lengths && !keys->len && !keys->cap);
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    CHECK(!original_request && key.len == 25 && !strcmp(part, "key"));
    candidate = result; original_key = key; ++findings;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static void provider_values(void)
{
    CHECK(original_request && original_context && candidate && original_key.data);
    CHECK(!strcmp(original_request->method, "GET") && !strcmp(original_request->url, url));
    CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms);
    CHECK(original_request->detector_type == 111 && original_request->nheaders == 1);
    CHECK(!strcmp(original_request->headers[0].name, "Authorization"));
    const char *authorization = original_request->headers[0].value;
    CHECK(strlen(authorization) == 35 && !memcmp(authorization, "AccessKey ", 10));
    CHECK(!memcmp(authorization + 10, original_key.data, original_key.len) && !authorization[35]);
    CHECK(!original_request->body.data && !original_request->body.len);
    CHECK(!original_request->dedup_key.data && !original_request->dedup_key.len);
    CHECK(candidate->raw.len == 25 && !memcmp(candidate->raw.data, original_key.data, 25));
    CHECK(candidate->secret_parts && !candidate->verification_error);
    if (original_cause) CHECK(!strcmp(original_cause, saved_cause));
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(!original_request && sends == releases && candidate && !candidate->verified);
    original_request = request; original_context = ctx; ++sends; provider_values();
    int rc = br_http_send(ctx, request, response, error);
    original_cause = *error;
    if (original_cause) {
        CHECK(strlen(original_cause) < sizeof(saved_cause)); strcpy(saved_cause, original_cause);
    }
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(ctx == original_context && sends == releases + 1);
    provider_values(); br_http_release(ctx, response); provider_values();
    original_request = NULL; original_context = NULL; ++releases;
}

static void checked_free(void *value)
{
    CHECK(!original_request && !original_context);
    if (value && value == original_cause) {
        CHECK(!strcmp(original_cause, saved_cause)); original_cause = NULL; ++causes_freed;
    }
    free(value);
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(result == candidate && !original_request && sends == releases);
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
    CHECK(d->type == 111 && !d->version && !strcmp(d->name, "MessageBird") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "MessageBird is a cloud communications platform. MessageBird API keys can be used to send and receive SMS, voice, and chat messages."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "messagebird"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Main owns declaration, registry/default selection and engine integration. */
}

static void finding(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 111, key, "key");
    CHECK(r->raw.len == 25 && r->verified == verified && !r->verification_error);
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
    char input[256], changed[26];
    const struct { const char *format; bool match; } cases[] = {
        {"messagebird '%s'", true}, {"MeSsAgEbIrD:%s", true}, {"mymessagebirdsuffix:%s", true},
        {"messagebird\r\n%s", true}, {"messagebird\r%s", true}, {"messagebird\n%s", true},
        {"messagebird\t  %s  ", true}, {"messagebird-%s-", true}, {"messagebird é%sé", true},
        {"%s", false}, {"%s messagebird", false}, {"message bird %s", false},
        {"messagebird%s", false}, {"messagebird x%s", false}, {"messagebird _%s", false},
        {"messagebird %s_", false}, {"messagebird %s9", false}, {"messagebird %.24s", false},
        {"messagebird %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a, key_b);
        extract_case(d, input, strlen(input), cases[i].match ? key_a : NULL);
    }
    const char invalid[] = "+/=. ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[12] = invalid[i];
        snprintf(input, sizeof(input), "messagebird %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "0AZaz_";
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 25); changed[25] = '\0';
        snprintf(input, sizeof(input), "messagebird %s", changed);
        extract_case(d, input, strlen(input), changed);
    }
    memcpy(changed, key_a, sizeof(changed)); changed[0] = '-';
    snprintf(input, sizeof(input), "messagebird %s", changed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "messagebird%s", changed);
    extract_case(d, input, strlen(input), changed);
    snprintf(input, sizeof(input), "messagebirdx%s", changed);
    extract_case(d, input, strlen(input), changed);
    memcpy(changed, key_a, sizeof(changed)); changed[24] = '-';
    snprintf(input, sizeof(input), "messagebird %s", changed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "messagebird %sX", changed);
    extract_case(d, input, strlen(input), changed);
    changed[0] = '-'; snprintf(input, sizeof(input), "messagebird%sX", changed);
    extract_case(d, input, strlen(input), changed);
    memset(changed, '-', 25); changed[25] = '\0';
    snprintf(input, sizeof(input), "messagebird %s", changed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "messagebird%sX", changed);
    extract_case(d, input, strlen(input), changed);
    const size_t prefix_len = sizeof("messagebird") - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "messagebird", prefix_len); memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key_a, 25);
        extract_case(d, input, prefix_len + 25 + gap, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + prefix_len + 2 * i, "\xc3\xa9", 2);
        memcpy(input + prefix_len + 2 * gap, key_a, 25);
        extract_case(d, input, prefix_len + 25 + 2 * gap, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "messagebird%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("MessageBird 25-byte case/underscore/hyphen grammar/odd endpoint ASCII boundaries/40-rune gap/CR-LF-NUL/no local filtering: 0 failures");
}

typedef struct { const char *const *keys; size_t count; const char *agent; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 111);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 35 && !memcmp(request->headers[0].value, "AccessKey ", 10));
    CHECK(!strcmp(request->headers[0].value + 10, script->keys[at]));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, script->agent));
    /* Never retain borrowed effective prepared request/header-array/UA storage. */
}

static void occurrences_and_requests(const br_detector *d)
{
    char input[192]; snprintf(input, sizeof(input), "messagebird %s\nMESSAGEBIRD %s\nmessagebird %s", key_a, key_b, key_a);
    const char *keys[] = {key_a, key_b, key_a};
    request_script script = {keys, 3, "TruffleHog messagebird-offline"};
    test_http http = {.inspect = inspect, .user = &script, .response = {.status = 204}};
    br_transport transport = test_transport(&http);
    const char *configured[] = {"https://unused.invalid"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .cloud = "https://ignored.invalid"};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "messagebird-offline", .endpoints = &endpoints};
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    char edge[26]; memcpy(edge, key_a, sizeof(edge));
    for (size_t i = 0; i < 2; ++i) {
        memcpy(edge, key_a, sizeof(edge)); edge[i ? 24 : 0] = '-';
        snprintf(input, sizeof(input), i ? "messagebird %sX" : "messagebird%s", edge);
        const char *one[] = {edge}; script.keys = one; script.count = 1; http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], edge, true); br_results_clear(&out);
    }
    puts("MessageBird duplicate order/Raw-key-only metadata/exact GET/literal AccessKey including edge hyphens/SANE/empty key/common UA: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "messagebird %s", key_a);
    const char *keys[] = {key_a}; request_script script = {keys, 1, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {NULL, 1},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored read failure"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && sends == 1 && releases == 1 && capture_clears == 1);
        finding(&out.items[0], key_a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } errors[] = {
        {1, "context canceled"}, {-7, "context deadline exceeded"},
        {1, "out of memory constructing HTTP headers"}, {-1, "cannot create MessageBird finding"},
        {7, "net/http: nil Context"}, {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = (br_http_response){.status = 200, .body = BYTES("ignored"), .body_error = "also ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && causes_freed == 1 && capture_clears == 1);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    puts("MessageBird all 2xx verified/body-read errors ignored/whole mixed send errors suppressed/no setter/one release/provider lifetimes: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void setup_and_null(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "messagebird %s", key_a);
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
        CHECK(sends == 1 && releases == 1 && pushes == 1 && causes_freed == 1 && capture_clears == 1);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && findings == 1 && !sends && !releases && !pushes && capture_clears == 1); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && findings == 1 && !sends && pushes == 1); finding(&out.items[0], key_a, false); br_results_clear(&out);
    reset_observation(); out = test_scan(d, &contexts[3], false, input, strlen(input));
    CHECK(out.len == 1 && cancellations == 1 && !sends); br_results_clear(&out);
    puts("MessageBird preparation guards release once/finding before nil-context skip/NoV zero I-O and no context work: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence,
                        bool verify, bool nil, int status, const char *read_error, int send_rc, size_t attempts)
{
    char input[128]; snprintf(input, sizeof(input), "messagebird %s\nmessagebird %s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot append MessageBird finding" : NULL,
        .response = {.status = status, .body_error = read_error}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    const char *expected = site == CAPTURE ? "synthetic capture failure" :
        site == FINDING ? "cannot create MessageBird finding" : "cannot append MessageBird finding";
    CHECK(error && !strcmp(error, expected)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && capture_clears == 1 && !original_cause);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 200, NULL, 0, 0);
    own_failure(d, FINDING, 1, true, true, 200, NULL, 0, 0);
    own_failure(d, FINDING, 2, true, false, 200, NULL, 0, 1);
    own_failure(d, FINDING, 2, false, false, 200, NULL, 0, 0);
    own_failure(d, PUSH, 2, true, false, 200, NULL, 0, 2);
    own_failure(d, PUSH, 2, true, false, 300, "", 0, 2);
    own_failure(d, PUSH, 2, true, false, 200, "ignored", 7, 2);
    own_failure(d, PUSH, 2, false, false, 200, NULL, 0, 0);
    reset_observation(); br_results out = {0}; br_detector uninitialized = *d; uninitialized.state = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(&uninitialized, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !sends);
    puts("MessageBird owned +1 capture/finding/push fatal before skip/suppression/publication/invocation-only caller-preserving rollback: 0 failures");
}

int main(void)
{
    test_secret(key_a, 25, 0); key_a[0] = 'A'; key_a[12] = 'Z';
    test_secret(key_b, 25, 17); key_b[0] = 'B'; key_b[4] = '_'; key_b[13] = '-';
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 25 && strlen(key_b) == 25);
    const br_detector *d = descriptor(br_messagebird_init);
    grammar(d); occurrences_and_requests(d);
    reset_observation(); fault = COMPILE; nth = 1;
    const br_detector *observed = d; char *error = NULL;
    CHECK(observed_messagebird_init(&observed, &error) == -1 && !observed && error);
    CHECK(fault_hit && fault == NONE && !strcmp(error, "synthetic compile failure")); free(error);
    observed = descriptor(observed_messagebird_init);
    response_policy(observed); setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_context && !original_cause && fault == NONE);
    return test_finish("MessageBird ABI1 focused checks");
}
