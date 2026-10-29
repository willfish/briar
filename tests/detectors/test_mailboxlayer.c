/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_mailboxlayer_init(const br_detector **out, char **error); /* Main owns the shared declaration. */

/* Reuse the named-test inclusion seam for owned nonzero returns and original
 * provider lifetimes; regex, findings, HTTP preparation and byte search stay real. */
static int checked_compile(const char *const *, size_t, const char *, br_regex **, char **);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static void checked_captures_clear(br_captures *);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static size_t checked_find(br_slice, br_slice, size_t);
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
#define br_slice_find checked_find
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#define free checked_free
#define br_mailboxlayer_init observed_mailboxlayer_init
#include "../../src/detectors/mailboxlayer.c"
#undef br_regex_compile_prefixed
#undef br_captures_find
#undef br_captures_clear
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_slice_find
#undef br_results_push
#undef br_result_set_verification_error
#undef free
#undef br_mailboxlayer_init

#define BYTES(s) {(const unsigned char *)(s), sizeof(s) - 1}
static const char key_a[] = "g7h9j2k5l6m8n3p4q1r0s2t4u6v8w1x3";
static const char key_b[] = "z9y8x7w6v5u4t3s2r1q0p9n8m7l6k5j4";
static const char url_prefix[] = "https://apilayer.net/api/check?access_key=";
static const char url_suffix[] = "&email=support@email.com";
static const char restricted[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
enum { URL_LENGTH = sizeof(url_prefix) - 1 + 32 + sizeof(url_suffix) - 1 };
typedef enum { NONE, COMPILE, CAPTURE, FINDING, BODY, PUSH } fault_site;
static fault_site fault;
static size_t nth, findings, pushes, sends, releases, capture_clears, causes_freed, projections;
static bool fault_hit, project_body;
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
    fault = NONE; nth = 0; fault_hit = project_body = false;
    findings = pushes = sends = releases = capture_clears = causes_freed = projections = 0;
    candidate = NULL; original_key = (br_slice){0};
}

static int checked_compile(const char *const *keywords, size_t count, const char *pattern,
                           br_regex **out, char **error)
{
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
    CHECK(!original_request && key.len == 32 && !strcmp(part, "key"));
    candidate = result; original_key = key; ++findings;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static void provider_values(void)
{
    CHECK(original_request && original_context && candidate && original_key.data);
    const char *url = original_request->url;
    CHECK(!strcmp(original_request->method, "GET") && strlen(url) == URL_LENGTH);
    CHECK(!memcmp(url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(url + sizeof(url_prefix) - 1, original_key.data, original_key.len));
    CHECK(!strcmp(url + sizeof(url_prefix) - 1 + original_key.len, url_suffix));
    CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms);
    CHECK(original_request->detector_type == 145 && !original_request->nheaders && !original_request->headers);
    CHECK(!original_request->body.data && !original_request->body.len);
    CHECK(!original_request->dedup_key.data && !original_request->dedup_key.len);
    CHECK(candidate->raw.len == 32 && !memcmp(candidate->raw.data, original_key.data, 32));
    CHECK(candidate->secret_parts && !candidate->verification_error);
    if (original_cause) CHECK(!strcmp(original_cause, saved_cause));
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(!original_request && sends == releases && candidate && !candidate->verified);
    original_request = request; original_context = ctx; ++sends; provider_values();
    int rc = br_http_send(ctx, request, response, error);
    if (rc == 0 && hit(BODY)) response->body = (br_slice){NULL, 5};
    projections = 0;
    project_body = rc == 0 && response->body_error == NULL && (response->body.data || !response->body.len);
    original_cause = *error;
    if (original_cause) {
        CHECK(strlen(original_cause) < sizeof(saved_cause)); strcpy(saved_cause, original_cause);
    }
    return rc;
}

static size_t checked_find(br_slice body, br_slice needle, size_t start)
{
    CHECK(original_request && project_body && !candidate->verified && !start && projections < 2);
    const char *expected = projections ? restricted : "email";
    CHECK(needle.len == strlen(expected) && !memcmp(needle.data, expected, needle.len));
    ++projections;
    return br_slice_find(body, needle, start);
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(ctx == original_context && sends == releases + 1);
    CHECK(project_body ? projections >= 1 && projections <= 2 : !projections);
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
    CHECK(d->type == 145 && !d->version && !strcmp(d->name, "Mailboxlayer") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Mailboxlayer is an email validation and verification service. Mailboxlayer API keys can be used to validate and verify email addresses."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "mailboxlayer"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 145, key, "key");
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
    char input[256], changed[33];
    const struct { const char *format; bool match; } cases[] = {
        {"mailboxlayer '%s'", true}, {"MaIlBoXlAyEr:%s", true}, {"mymailboxlayersuffix:%s", true},
        {"mailboxlayer\r\n%s", true}, {"mailboxlayer\r%s", true}, {"mailboxlayer\n%s", true},
        {"mailboxlayer\t  %s  ", true}, {"mailboxlayer-%s-", true}, {"mailboxlayer é%sé", true},
        {"%s", false}, {"%s mailboxlayer", false}, {"mailbox layer %s", false},
        {"mailboxlayer%s", false}, {"mailboxlayer x%s", false}, {"mailboxlayer _%s", false},
        {"mailboxlayer %s_", false}, {"mailboxlayer %s9", false}, {"mailboxlayer %.31s", false},
        {"mailboxlayer %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a, key_b);
        extract_case(d, input, strlen(input), cases[i].match ? key_a : NULL);
    }
    const char invalid[] = "AGZ_-/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "mailboxlayer %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "0agz";
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 32); changed[32] = '\0';
        snprintf(input, sizeof(input), "mailboxlayer %s", changed);
        extract_case(d, input, strlen(input), changed);
    }
    const size_t prefix_len = sizeof("mailboxlayer") - 1;
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "mailboxlayer", prefix_len); memset(input + prefix_len, '.', gap);
        memcpy(input + prefix_len + gap, key_a, 32);
        extract_case(d, input, prefix_len + 32 + gap, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + prefix_len + 2 * i, "\xc3\xa9", 2);
        memcpy(input + prefix_len + 2 * gap, key_a, 32);
        extract_case(d, input, prefix_len + 32 + 2 * gap, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "mailboxlayer%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("Mailboxlayer lower-alnum/nonhex grammar/case/ASCII boundaries/40-rune gap/CR-LF-NUL/no local filtering: 0 failures");
}

typedef struct { br_http_response response; int rc; const char *cause; } response_step;
typedef struct { const char *const *keys; size_t count; const char *agent; const response_step *steps; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET") && strlen(request->url) == URL_LENGTH);
    CHECK(!memcmp(request->url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(request->url + sizeof(url_prefix) - 1, script->keys[at], 32));
    CHECK(!strcmp(request->url + sizeof(url_prefix) - 1 + 32, url_suffix));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 145);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, script->agent));
    if (script->steps) {
        http->response = script->steps[at].response;
        http->send_rc = script->steps[at].rc; http->send_error = script->steps[at].cause;
    }
    /* Never retain borrowed effective prepared request/header-array/UA storage. */
}

static void occurrences(const br_detector *d)
{
    char input[192]; snprintf(input, sizeof(input), "mailboxlayer %s\nMAILBOXLAYER %s\nmailboxlayer %s", key_a, key_b, key_a);
    const char *keys[] = {key_a, key_b, key_a};
    request_script script = {keys, 3, "TruffleHog mailboxlayer-offline", NULL};
    test_http http = {.inspect = inspect, .user = &script, .response = {.status = 500, .body = BYTES("malformed:email!")}};
    br_transport transport = test_transport(&http);
    const char *configured[] = {"https://unused.invalid"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .cloud = "https://ignored.invalid"};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mailboxlayer-offline", .endpoints = &endpoints};
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    puts("Mailboxlayer occurrences/order/Raw-key-only metadata/exact literal query/email/SANE/empty key/common UA/matching 500: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "mailboxlayer %s", key_a);
    const char *keys[] = {key_a}; request_script script = {keys, 1, "TruffleHog", NULL};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; br_slice body; const char *read_error; bool keep, valid; } cases[] = {
        {0, BYTES("email"), NULL, true, true}, {199, BYTES("email"), NULL, true, true},
        {200, BYTES("email"), NULL, true, true}, {401, BYTES("!notemailword!"), NULL, true, true},
        {500, BYTES(restricted), NULL, true, true}, {403, BYTES("\xff\0junkemail!"), NULL, true, true},
        {429, BYTES("notJSON:\0\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"!"), NULL, true, true},
        {200, {0}, NULL, true, false}, {200, BYTES("EMAIL"), NULL, true, false},
        {500, BYTES("e-mail"), NULL, true, false}, {200, BYTES("{}"), NULL, true, false},
        {200, BYTES("{\"info\": \"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"}"), NULL, true, false},
        {200, BYTES("\"info\":\"access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, true, false},
        {200, BYTES("\"info\":\"Access  Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""), NULL, true, false},
        {200, BYTES("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption\""), NULL, true, false},
        {200, BYTES("\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."), NULL, true, false},
        {200, BYTES("email"), "", false, false}, {500, BYTES(restricted), "partial read", false, false},
        {200, {0}, "read failed", false, false}, {401, {NULL, 1}, "", false, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == (cases[i].keep ? 1u : 0u) && http.calls == 1 && http.releases == 1);
        CHECK(sends == 1 && releases == 1 && pushes == (cases[i].keep ? 1u : 0u) && capture_clears == 1);
        if (cases[i].keep) finding(&out.items[0], key_a, cases[i].valid);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause, *read_error; br_slice body; } errors[] = {
        {1, "context canceled", NULL, BYTES("email")},
        {-7, "context deadline exceeded", "", BYTES(restricted)},
        {1, "out of memory constructing HTTP headers", "read failed", BYTES("email")},
        {-1, "invalid Mailboxlayer response body slice", NULL, {NULL, 5}},
        {7, "net/http: nil Context", "", {NULL, 5}},
        {1, "", NULL, BYTES(restricted)}, {-1, NULL, "read failed", BYTES("email")},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = (br_http_response){.status = 200, .body = errors[i].body, .body_error = errors[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && causes_freed == 1 && !projections);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    puts("Mailboxlayer exact binary markers/status never consulted/non-JSON and NUL/any read-error pointer drops after release: 0 failures");
    puts("Mailboxlayer whole mixed send errors retain false without touching populated body/read-error or classifying text: 0 failures");
}

static void mixed_outcomes(const br_detector *d)
{
    char input[192]; snprintf(input, sizeof(input), "mailboxlayer %s\nmailboxlayer %s\nmailboxlayer %s", key_a, key_b, key_a);
    const char *keys[] = {key_a, key_b, key_a};
    const response_step steps[] = {
        {{.status = 200, .body = BYTES("email"), .body_error = ""}, 0, NULL},
        {{.status = 500, .body = BYTES(restricted)}, 0, NULL},
        {{.status = 200, .body = {NULL, 5}, .body_error = "read failed"}, 1, "synthetic Do failure"},
    };
    request_script script = {keys, 3, "TruffleHog", steps};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; br_results out = {0}; br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    reset_observation(); char *error = NULL;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0 && !error);
    CHECK(out.len == 3 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    finding(&out.items[1], key_b, true); finding(&out.items[2], key_a, false);
    CHECK(findings == 3 && pushes == 2 && sends == 3 && releases == 3 && http.calls == 3 && http.releases == 3);
    br_results_clear(&out);
    puts("Mailboxlayer read drop continues later occurrences/Do failure is not a read drop/caller findings preserved: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void setup_and_null(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "mailboxlayer %s", key_a);
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
        CHECK(sends == 1 && releases == 1 && pushes == 1 && causes_freed == 1 && !projections);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && findings == 1 && !sends && !releases && !pushes && capture_clears == 1); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && findings == 1 && !sends && pushes == 1); finding(&out.items[0], key_a, false); br_results_clear(&out);
    reset_observation(); out = test_scan(d, &contexts[3], false, input, strlen(input));
    CHECK(out.len == 1 && cancellations == 1 && !sends); br_results_clear(&out);
    puts("Mailboxlayer preparation failures retain false/release once/finding before nil-context skip/NoV zero context work: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence,
                        bool verify, bool nil, const char *read_error, int send_rc, int status, size_t attempts)
{
    char input[128]; snprintf(input, sizeof(input), "mailboxlayer %s\nmailboxlayer %s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot append Mailboxlayer finding" : NULL,
        .response = {.status = status, .body = BYTES("email"), .body_error = read_error}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    const char *expected = site == CAPTURE ? "synthetic capture failure" :
        site == FINDING ? "cannot create Mailboxlayer finding" :
        site == BODY ? "invalid Mailboxlayer response body slice" : "cannot append Mailboxlayer finding";
    CHECK(error && !strcmp(error, expected)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && capture_clears == 1 && !original_cause);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, NULL, 0, 200, 0);
    own_failure(d, FINDING, 1, true, true, NULL, 0, 200, 0);
    own_failure(d, FINDING, 2, true, false, NULL, 0, 200, 1);
    own_failure(d, FINDING, 2, true, false, "", 0, 200, 1);
    own_failure(d, FINDING, 2, false, false, NULL, 0, 200, 0);
    own_failure(d, BODY, 2, true, false, NULL, 0, 200, 2);
    own_failure(d, BODY, 2, true, false, NULL, 0, 500, 2);
    own_failure(d, PUSH, 2, true, false, NULL, 0, 500, 2);
    own_failure(d, PUSH, 2, true, false, "", 7, 200, 2);
    own_failure(d, PUSH, 2, false, false, NULL, 0, 200, 0);
    reset_observation(); br_results out = {0}; br_detector uninitialized = *d; uninitialized.state = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(&uninitialized, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !sends);
    puts("Mailboxlayer owned +1 capture/finding/push and invalid body fatal before ordinary outcomes/invocation-only caller-preserving rollback: 0 failures");
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 32 && strlen(key_b) == 32);
    const br_detector *d = descriptor(br_mailboxlayer_init);
    grammar(d); occurrences(d);
    reset_observation(); fault = COMPILE; nth = 1;
    const br_detector *observed = d; char *error = NULL;
    CHECK(observed_mailboxlayer_init(&observed, &error) == -1 && !observed && error);
    CHECK(fault_hit && fault == NONE && !strcmp(error, "synthetic compile failure")); free(error);
    observed = descriptor(observed_mailboxlayer_init);
    response_policy(observed); mixed_outcomes(observed); setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_context && !original_cause && fault == NONE);
    return test_finish("Mailboxlayer ABI1 focused checks");
}
