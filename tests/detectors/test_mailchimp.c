/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_mailchimp_init(const br_detector **out, char **error); /* Main owns the shared declaration. */

/* Existing named-test inclusion seam, with real helpers and focused ownership
 * failures. Only original provider storage is observed through release. */
static int checked_compile(const char *, br_regex **, char **);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static void checked_captures_clear(br_captures *);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static br_json *checked_object(void);
static br_json *checked_string(const char *);
static int checked_add(br_json *, const char *, br_json *);
static int checked_put(br_json *);
static int checked_auth(br_slice, br_slice, char **, char **);
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
#define br_regex_compile checked_compile
#define br_captures_find checked_captures
#define br_captures_clear checked_captures_clear
#define br_finding_key_bytes checked_finding
#define json_object_new_object checked_object
#define json_object_new_string checked_string
#define json_object_object_add checked_add
#define json_object_put checked_put
#define br_http_basic_auth checked_auth
#define br_http_send checked_send
#define br_http_release checked_release
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#define free checked_free
#define br_mailchimp_init observed_mailchimp_init
#include "../../src/detectors/mailchimp.c"
#undef br_regex_compile
#undef br_captures_find
#undef br_captures_clear
#undef br_finding_key_bytes
#undef json_object_new_object
#undef json_object_new_string
#undef json_object_object_add
#undef json_object_put
#undef br_http_basic_auth
#undef br_http_send
#undef br_http_release
#undef br_results_push
#undef br_result_set_verification_error
#undef free
#undef br_mailchimp_init

#define BYTES(s) {(const unsigned char *)(s), sizeof(s) - 1}
static const char key_a[] = "0123456789abcdef0123456789abcdef-us1";
static const char key_b[] = "fedcba9876543210fedcba9876543210-us09";
static const char key_zero[] = "0123456789abcdef0123456789abcdef-us0";
static const char key_zero2[] = "0123456789abcdef0123456789abcdef-us00";
static const char guide[] = "https://howtorotate.com/docs/tutorials/mailchimp/";
typedef struct { const char *key, *url, *auth; } request_fixture;
static const request_fixture fixtures[] = {
    {key_a, "https://us1.api.mailchimp.com/3.0/", "Basic YW55c3RyaW5nOjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmLXVzMQ=="},
    {key_b, "https://us09.api.mailchimp.com/3.0/", "Basic YW55c3RyaW5nOmZlZGNiYTk4NzY1NDMyMTBmZWRjYmE5ODc2NTQzMjEwLXVzMDk="},
    {key_zero, "https://us0.api.mailchimp.com/3.0/", "Basic YW55c3RyaW5nOjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmLXVzMA=="},
    {key_zero2, "https://us00.api.mailchimp.com/3.0/", "Basic YW55c3RyaW5nOjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmLXVzMDA="},
};
typedef enum { NONE, COMPILE, CAPTURE, FINDING, META_OBJECT, META_STRING, META_ADD, AUTH, PUSH } fault_site;
static fault_site fault;
static size_t nth, findings, objects, strings, adds, guide_frees, auths, auth_frees;
static size_t pushes, sends, releases, capture_clears, causes_freed;
static bool fault_hit;
static br_result *candidate;
static br_json *pending_guide;
static br_slice original_key;
static char *original_auth;
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
    CHECK(!original_request && !original_context && !original_cause && !original_auth && !pending_guide);
    fault = NONE; nth = 0; fault_hit = false;
    findings = objects = strings = adds = guide_frees = auths = auth_frees = 0;
    pushes = sends = releases = capture_clears = causes_freed = 0;
    candidate = NULL; original_key = (br_slice){0};
}

static void metadata(const br_result *result)
{
    br_json *value = NULL;
    CHECK(result->extra_data && json_object_is_type(result->extra_data, json_type_object));
    CHECK(json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), guide));
}

static int checked_compile(const char *pattern, br_regex **out, char **error)
{
    CHECK(!strcmp(pattern, "([0-9a-f]{32}-us[0-9]{1,2})"));
    if (hit(COMPILE)) {
        *out = NULL; *error = strdup("synthetic compile failure"); CHECK(*error);
        return 1;
    }
    return br_regex_compile(pattern, out, error);
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
    CHECK(!original_request && !original_cause && !original_auth && !pending_guide && sends == releases);
    br_captures_clear(keys); ++capture_clears;
    CHECK(!keys->items && !keys->lengths && !keys->len && !keys->cap);
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    CHECK(!original_request && (key.len == 36 || key.len == 37) && !strcmp(part, "key"));
    candidate = result; original_key = key; ++findings;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static br_json *checked_object(void)
{
    CHECK(candidate && candidate->raw.len && candidate->secret_parts && !candidate->extra_data && !candidate->verified);
    ++objects;
    return hit(META_OBJECT) ? NULL : json_object_new_object();
}

static br_json *checked_string(const char *text)
{
    CHECK(candidate->extra_data && !pending_guide && !strcmp(text, guide)); ++strings;
    if (hit(META_STRING)) return NULL;
    pending_guide = json_object_new_string(text);
    return pending_guide;
}

static int checked_add(br_json *object, const char *name, br_json *value)
{
    CHECK(object == candidate->extra_data && value == pending_guide && !strcmp(name, "rotation_guide")); ++adds;
    if (hit(META_ADD)) return 1;
    int rc = json_object_object_add(object, name, value);
    if (rc == 0) pending_guide = NULL;
    return rc;
}

static int checked_put(br_json *value)
{
    CHECK(value && value == pending_guide && !original_request);
    pending_guide = NULL; ++guide_frees;
    return json_object_put(value); /* Refcount deletion returns 1, not a failure status. */
}

static int checked_auth(br_slice username, br_slice password, char **out, char **error)
{
    metadata(candidate);
    CHECK(username.len == 9 && !memcmp(username.data, "anystring", 9));
    CHECK(password.data == original_key.data && password.len == original_key.len && !original_auth);
    ++auths;
    int rc = br_http_basic_auth(username, password, out, error);
    original_auth = *out;
    if (rc == 0 && hit(AUTH)) {
        *error = strdup("synthetic Basic auth failure"); CHECK(*error);
        return 1; /* Leave a real allocated value to exercise fatal cleanup. */
    }
    return rc;
}

static const request_fixture *fixture_for(br_slice key)
{
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(*fixtures); ++i)
        if (key.len == strlen(fixtures[i].key) && !memcmp(key.data, fixtures[i].key, key.len)) return &fixtures[i];
    CHECK(false);
    return NULL;
}

static void provider_values(void)
{
    CHECK(original_request && original_context && candidate && original_key.data && original_auth);
    const request_fixture *fixture = fixture_for(original_key);
    CHECK(!strcmp(original_request->method, "GET") && !strcmp(original_request->url, fixture->url));
    CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms);
    CHECK(original_request->detector_type == 20 && original_request->nheaders == 2);
    CHECK(!strcmp(original_request->headers[0].name, "Authorization") && original_request->headers[0].value == original_auth);
    CHECK(!strcmp(original_auth, fixture->auth));
    CHECK(!strcmp(original_request->headers[1].name, "Accept") && !strcmp(original_request->headers[1].value, "application/json"));
    CHECK(!original_request->body.data && !original_request->body.len);
    CHECK(!original_request->dedup_key.data && !original_request->dedup_key.len);
    CHECK(candidate->raw.len == original_key.len && !memcmp(candidate->raw.data, original_key.data, original_key.len));
    CHECK(candidate->secret_parts && !candidate->verification_error); metadata(candidate);
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
    if (value && value == original_auth) { original_auth = NULL; ++auth_frees; }
    free(value);
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(result == candidate && !original_request && !original_auth && sends == releases);
    metadata(result); ++pushes;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error); free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 20 && !d->version && !strcmp(d->name, "Mailchimp") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Mailchimp is a marketing automation platform and email marketing service. Mailchimp API keys can be used to access and manage email campaigns, audience data, and other marketing resources."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "-us"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *r, const char *key, bool verified)
{
    br_result base = *r; base.extra_data = NULL;
    test_key_result(&base, 20, key, "key"); metadata(r);
    CHECK(r->verified == verified && !r->verification_error);
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
    char input[512], changed[64];
    const char *formats[] = {"%s", "'%s'", "mailchimp %s", "not-a-provider %s", "g%s_", "abcdef0%sTAIL", "\r\n%s\r\n", "%sa"};
    for (size_t i = 0; i < sizeof(formats) / sizeof(*formats); ++i) {
        snprintf(input, sizeof(input), formats[i], key_a);
        extract_case(d, input, strlen(input), key_a);
    }
    for (size_t i = 0; i < sizeof(fixtures) / sizeof(*fixtures); ++i)
        extract_case(d, fixtures[i].key, strlen(fixtures[i].key), fixtures[i].key);
    snprintf(input, sizeof(input), "%s23", key_a);
    extract_case(d, input, strlen(input), "0123456789abcdef0123456789abcdef-us12");
    snprintf(input, sizeof(input), "%s3", key_zero2);
    extract_case(d, input, strlen(input), key_zero2);
    snprintf(input, sizeof(input), "mailchimp %.31s-us1", key_a);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "%.32s-us", key_a);
    extract_case(d, input, strlen(input), NULL);
    const char invalid[] = "AGZ_-/";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(key_a)); changed[16] = invalid[i];
        extract_case(d, changed, strlen(changed), NULL);
    }
    memcpy(changed, key_a, sizeof(key_a)); changed[33] = 'U';
    extract_case(d, changed, strlen(changed), NULL);
    memcpy(changed, key_a, sizeof(key_a)); changed[34] = 'S';
    extract_case(d, changed, strlen(changed), NULL);
    const char *low_entropy = "00000000000000000000000000000000-us99";
    extract_case(d, low_entropy, strlen(low_entropy), low_entropy);
    memset(input, 'q', 300); memcpy(input + 300, key_b, sizeof(key_b));
    extract_case(d, input, 300 + strlen(key_b), key_b);
    int n = snprintf(input, sizeof(input), "arbitrary%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("Mailchimp unprefixed/unbounded whole match/lowercase/greedy 1-2 digits/no boundaries/leading zeros/NUL/no local filtering: 0 failures");
}

typedef struct { const request_fixture *const *attempts; size_t count; const char *agent; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    const request_fixture *fixture = script->attempts[at];
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, fixture->url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 20);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, fixture->auth));
    CHECK(!strcmp(request->headers[1].name, "Accept") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, script->agent));
    /* The effective prepared request/header-array/UA is never retained here. */
}

static void occurrences_and_requests(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "%s\n%s\n%s", key_a, key_b, key_a);
    const request_fixture *attempts[] = {&fixtures[0], &fixtures[1], &fixtures[0]};
    request_script script = {attempts, 3, "TruffleHog mailchimp-offline"};
    test_http http = {.inspect = inspect, .user = &script, .response = {.status = 204}};
    br_transport transport = test_transport(&http);
    const char *configured[] = {"https://unused.invalid"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .cloud = "https://ignored.invalid"};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mailchimp-offline", .endpoints = &endpoints};
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], attempts[i]->key, pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        CHECK(out.items[0].extra_data != out.items[2].extra_data); br_results_clear(&out);
    }
    for (size_t i = 2; i < sizeof(fixtures) / sizeof(*fixtures); ++i) {
        const request_fixture *one[] = {&fixtures[i]}; script.attempts = one; script.count = 1;
        http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, true, fixtures[i].key, strlen(fixtures[i].key));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], fixtures[i].key, true); br_results_clear(&out);
    }
    puts("Mailchimp occurrence order/NoV rotation metadata/exact datacenter URL and full-password Basic/Accept/SANE/common UA/empty key: 0 failures");
}

static void response_policy(const br_detector *d)
{
    const request_fixture *attempts[] = {&fixtures[0]}; request_script script = {attempts, 1, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {NULL, 1},
            .body_error = i % 3 == 0 ? NULL : i % 3 == 1 ? "" : "ignored read failure"};
        br_results out = test_scan(d, &ctx, true, key_a, strlen(key_a));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && sends == 1 && releases == 1 && capture_clears == 1);
        CHECK(auths == 1 && auth_frees == 1 && adds == 1);
        finding(&out.items[0], key_a, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } errors[] = {
        {1, "context canceled"}, {-7, "context deadline exceeded"},
        {1, "out of memory constructing HTTP headers"}, {-1, "cannot create Mailchimp metadata"},
        {7, "net/http: nil Context"}, {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = (br_http_response){.status = 200, .body = BYTES("ignored")};
        br_results out = test_scan(d, &ctx, true, key_a, strlen(key_a));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && causes_freed == 1 && auth_frees == 1);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    puts("Mailchimp all 2xx verified/body-read errors ignored/whole mixed send errors suppressed/no setter/one release/provider lifetimes: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void setup_and_null(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_transport missing_send = {&http, NULL, test_http_release}, missing_release = {&http, test_http_send, NULL};
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &missing_send}, {.transport = &missing_release},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, key_a, strlen(key_a));
        CHECK(out.len == 1 && !http.calls && http.releases == (i == 0 || i == 2 ? 0u : 1u));
        CHECK(sends == 1 && releases == 1 && pushes == 1 && causes_freed == 1 && auth_frees == 1);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, key_a, strlen(key_a));
    CHECK(!out.len && findings == 1 && objects == 1 && strings == 1 && adds == 1 && !auths && !sends && !pushes && capture_clears == 1);
    br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, key_a, strlen(key_a));
    CHECK(out.len == 1 && adds == 1 && !auths && !sends && pushes == 1);
    finding(&out.items[0], key_a, false); br_results_clear(&out);
    reset_observation(); out = test_scan(d, &contexts[3], false, key_a, strlen(key_a));
    CHECK(out.len == 1 && cancellations == 1 && !auths && !sends); br_results_clear(&out);
    puts("Mailchimp metadata before nil-context skip/NoV metadata with zero context work/preparation guards release once: 0 failures");
}

static const char *failure_message(fault_site site)
{
    switch (site) {
    case CAPTURE: return "synthetic capture failure";
    case FINDING: return "cannot create Mailchimp finding";
    case META_OBJECT: return "cannot create Mailchimp metadata";
    case META_STRING: return "cannot create Mailchimp rotation guide";
    case META_ADD: return "cannot add Mailchimp rotation guide";
    case AUTH: return "synthetic Basic auth failure";
    default: return "cannot append Mailchimp finding";
    }
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence,
                        bool verify, bool nil, int send_rc, size_t attempts)
{
    char input[128]; snprintf(input, sizeof(input), "%s\n%s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot append Mailchimp finding" : NULL,
        .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, failure_message(site))); free(error);
    CHECK(fault == NONE && !nth && fault_hit && capture_clears == 1 && !original_auth && !pending_guide);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    CHECK(auths == auth_frees && guide_frees == (site == META_ADD ? 1u : 0u));
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 0, 0);
    own_failure(d, FINDING, 1, true, true, 0, 0);
    own_failure(d, FINDING, 2, true, false, 0, 1);
    own_failure(d, META_OBJECT, 1, true, true, 0, 0);
    own_failure(d, META_STRING, 1, true, true, 0, 0);
    own_failure(d, META_ADD, 1, true, true, 0, 0);
    own_failure(d, META_ADD, 2, false, false, 0, 0);
    own_failure(d, AUTH, 1, true, false, 0, 0);
    own_failure(d, AUTH, 2, true, false, 0, 1);
    own_failure(d, PUSH, 2, true, false, 0, 2);
    own_failure(d, PUSH, 2, true, false, 7, 2);
    own_failure(d, PUSH, 2, false, false, 0, 0);
    reset_observation(); br_results out = {0}; br_detector uninitialized = *d; uninitialized.state = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(&uninitialized, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !sends);
    puts("Mailchimp owned capture/finding/metadata/add+1/Basic+1/push+1 fatal before outcomes/temporary cleanup/caller-preserving rollback: 0 failures");
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 36 && strlen(key_b) == 37);
    const br_detector *d = descriptor(br_mailchimp_init);
    grammar(d); occurrences_and_requests(d);
    reset_observation(); fault = COMPILE; nth = 1;
    const br_detector *observed = d; char *error = NULL;
    CHECK(observed_mailchimp_init(&observed, &error) == -1 && !observed && error);
    CHECK(fault_hit && fault == NONE && !strcmp(error, "synthetic compile failure")); free(error);
    observed = descriptor(observed_mailchimp_init);
    response_policy(observed); setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_context && !original_cause && !original_auth && !pending_guide && fault == NONE);
    return test_finish("Mailchimp ABI1 focused checks");
}
