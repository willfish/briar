/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_metaapi_init(const br_detector **out, char **error); /* Main owns the shared declaration. */

/* Existing named-test inclusion seam: real helpers, targeted owned failures,
 * collection/product ordering and original provider lifetime observations. */
static int checked_compile(const char *const *, size_t, const char *, br_regex **, char **);
static void checked_regex_free(br_regex *);
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
#define br_regex_free checked_regex_free
#define br_captures_find checked_captures
#define br_captures_clear checked_captures_clear
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_slice_find checked_find
#define br_results_push checked_push
#define br_result_set_verification_error forbidden_setter
#define free checked_free
#define br_metaapi_init observed_metaapi_init
#include "../../src/detectors/metaapi.c"
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_captures_clear
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_slice_find
#undef br_results_push
#undef br_result_set_verification_error
#undef free
#undef br_metaapi_init

#define BYTES(s) {(const unsigned char *)(s), sizeof(s) - 1}
static char key_a[65], key_b[65], spell_a[25], spell_b[25];
static const char url_prefix[] = "https://api.meta-api.io/api/spells/";
static const char url_suffix[] = "/runSync";
static const char marker[] = "\"success\":true";
typedef enum { NONE, COMPILE, CAPTURE, FINDING, BODY, PUSH } fault_site;
static fault_site fault;
static size_t nth, compiles, regex_frees, capture_calls, capture_clears;
static size_t findings, pushes, sends, releases, causes_freed, projections;
static bool fault_hit, search_body;
static br_captures *key_values, *spell_values;
static br_result *candidate;
static br_slice original_key, original_spell;
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
    CHECK(!original_request && !original_context && !original_cause && !key_values && !spell_values);
    fault = NONE; nth = 0; fault_hit = search_body = false;
    compiles = regex_frees = capture_calls = capture_clears = 0;
    findings = pushes = sends = releases = causes_freed = projections = 0;
    candidate = NULL; original_key = original_spell = (br_slice){0};
}

static int checked_compile(const char *const *keywords, size_t count, const char *pattern,
                           br_regex **out, char **error)
{
    CHECK(count == 2 && !strcmp(keywords[0], "metaapi") && !strcmp(keywords[1], "meta-api"));
    ++compiles;
    CHECK(compiles <= 2 && !strcmp(pattern, compiles == 1 ? "\\b([0-9a-f]{64})\\b" : "\\b([0-9a-f]{24})\\b"));
    int rc = br_regex_compile_prefixed(keywords, count, pattern, out, error);
    if (rc == 0 && hit(COMPILE)) {
        *error = strdup("synthetic compile failure"); CHECK(*error);
        return 1; /* Preserve the real allocated regex to verify fatal init cleanup. */
    }
    return rc;
}

static void checked_regex_free(br_regex *regex)
{
    if (regex) ++regex_frees;
    br_regex_free(regex);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out,
                            bool unique, char **error)
{
    CHECK(!unique && !findings && !sends && capture_calls < 2);
    ++capture_calls;
    if (capture_calls == 1) { CHECK(regex == metaapi_compiled.key); key_values = out; }
    else { CHECK(regex == metaapi_compiled.spell); spell_values = out; }
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) {
        *error = strdup("synthetic capture failure"); CHECK(*error);
        return 1;
    }
    return rc;
}

static void checked_captures_clear(br_captures *values)
{
    CHECK(!original_request && !original_cause && sends == releases);
    br_captures_clear(values); ++capture_clears;
    if (values == key_values) key_values = NULL;
    if (values == spell_values) spell_values = NULL;
    CHECK(!values->items && !values->lengths && !values->len && !values->cap);
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    CHECK(capture_calls == 2 && key_values && spell_values && key_values->len && spell_values->len);
    size_t key_index = findings % key_values->len, spell_index = findings / key_values->len;
    CHECK(spell_index < spell_values->len && key.len == 64 && !strcmp(part, "key"));
    CHECK(key.data == (const unsigned char *)key_values->items[key_index]);
    candidate = result; original_key = key; original_spell = br_captures_at(spell_values, spell_index); ++findings;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static void provider_values(void)
{
    CHECK(original_request && original_context && candidate && original_key.data && original_spell.data);
    const char *url = original_request->url;
    CHECK(!strcmp(original_request->method, "GET"));
    CHECK(strlen(url) == sizeof(url_prefix) - 1 + 24 + sizeof(url_suffix) - 1);
    CHECK(!memcmp(url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(url + sizeof(url_prefix) - 1, original_spell.data, 24));
    CHECK(!strcmp(url + sizeof(url_prefix) - 1 + 24, url_suffix));
    CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms && original_request->detector_type == 737);
    CHECK(original_request->nheaders == 2 && !strcmp(original_request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(original_request->headers[0].value, "application/json"));
    CHECK(!strcmp(original_request->headers[1].name, "Apikey") && original_request->headers[1].value == (const char *)original_key.data);
    CHECK(strlen(original_request->headers[1].value) == 64 && !memcmp(candidate->raw.data, original_key.data, 64));
    CHECK(!original_request->body.data && !original_request->body.len && !original_request->dedup_key.data && !original_request->dedup_key.len);
    CHECK(candidate->raw.len == 64 && candidate->secret_parts && !candidate->verification_error);
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
    search_body = rc == 0 && response->body_error == NULL && (response->body.data || !response->body.len) &&
        response->status >= 200 && response->status < 300;
    original_cause = *error;
    if (original_cause) { CHECK(strlen(original_cause) < sizeof(saved_cause)); strcpy(saved_cause, original_cause); }
    return rc;
}

static size_t checked_find(br_slice body, br_slice needle, size_t start)
{
    CHECK(original_request && search_body && !projections && !candidate->verified && !start);
    CHECK(needle.len == sizeof(marker) - 1 && !memcmp(needle.data, marker, needle.len));
    ++projections;
    return br_slice_find(body, needle, start);
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(ctx == original_context && sends == releases + 1 && projections == (search_body ? 1u : 0u));
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
    CHECK(result == candidate && !original_request && sends == releases && capture_calls == 2);
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
    CHECK(d->type == 737 && !d->version && !strcmp(d->name, "MetaAPI") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Detects MetaAPI credentials, which are typically API keys used for accessing the MetaAPI service."));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "metaapi") && !strcmp(d->keywords[1], "meta-api"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 737, key, "key");
    CHECK(r->raw.len == 64 && r->verified == verified && !r->verification_error);
}

static void component_case(const br_detector *d, bool key, const char *fragment, size_t len, const char *expected)
{
    char input[512]; CHECK(len + 90 < sizeof(input));
    memcpy(input, fragment, len);
    int added = snprintf(input + len, sizeof(input) - len, "\nmetaapi %s", key ? spell_a : key_a);
    CHECK(added > 0);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len + (size_t)added);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], key ? expected : key_a, false);
    br_results_clear(&out);
}

static void grammar_and_dependency(const br_detector *d)
{
    char fragment[256], changed[65];
    for (size_t kind = 0; kind < 2; ++kind) {
        const char *token = kind ? spell_a : key_a; size_t length = kind ? 24 : 64;
        const struct { const char *format; bool match; } cases[] = {
            {"metaapi '%s'", true}, {"META-API:%s", true}, {"mymetaapisuffix:%s", true},
            {"metaapi\r\n%s", true}, {"meta-api\t%s", true}, {"metaapi é%sé", true},
            {"%s", false}, {"%s metaapi", false}, {"meta api %s", false},
            {"metaapi%s", false}, {"metaapi x%s", false}, {"metaapi _%s", false},
            {"metaapi %s_", false}, {"metaapi %s9", false},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
            snprintf(fragment, sizeof(fragment), cases[i].format, token);
            component_case(d, !kind, fragment, strlen(fragment), cases[i].match ? token : NULL);
        }
        const char invalid[] = "AGg_-/";
        for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
            memcpy(changed, token, length + 1); changed[length / 2] = invalid[i];
            snprintf(fragment, sizeof(fragment), "metaapi %s", changed);
            component_case(d, !kind, fragment, strlen(fragment), NULL);
        }
        snprintf(fragment, sizeof(fragment), "metaapi %.*s", (int)length - 1, token);
        component_case(d, !kind, fragment, strlen(fragment), NULL);
        const size_t prefix_len = sizeof("metaapi") - 1;
        for (size_t gap = 40; gap <= 41; ++gap) {
            memcpy(fragment, "metaapi", prefix_len); memset(fragment + prefix_len, '.', gap);
            memcpy(fragment + prefix_len + gap, token, length);
            component_case(d, !kind, fragment, prefix_len + gap + length, gap == 40 ? token : NULL);
            for (size_t i = 0; i < gap; ++i) memcpy(fragment + prefix_len + 2 * i, "\xc3\xa9", 2);
            memcpy(fragment + prefix_len + 2 * gap, token, length);
            component_case(d, !kind, fragment, prefix_len + 2 * gap + length, gap == 40 ? token : NULL);
        }
        int n = snprintf(fragment, sizeof(fragment), "meta-api%c%s", 0, token);
        component_case(d, !kind, fragment, (size_t)n, token);
    }
    const char *tokens[] = {key_a, spell_a, ""};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(fragment, sizeof(fragment), "metaapi %s", tokens[i]);
        br_results out = test_scan(d, NULL, false, fragment, strlen(fragment)); CHECK(!out.len); br_results_clear(&out);
    }
    char distant[2200]; int n = snprintf(distant, sizeof(distant), "metaapi %s\n", key_a);
    CHECK(n > 0); memset(distant + n, '.', 1800 - (size_t)n);
    n = snprintf(distant + 1800, sizeof(distant) - 1800, "\nmeta-api %s", spell_a); CHECK(n > 0);
    br_results out = test_scan(d, NULL, false, distant, 1800 + (size_t)n);
    CHECK(out.len == 1); finding(&out.items[0], key_a, false); br_results_clear(&out);
    puts("MetaAPI independent lowercase-hex64/24 grammars/OR keywords/ASCII boundaries/40-rune CR-LF-NUL gaps/spell dependency/distant NoV product: 0 failures");
}

typedef struct { const char *const *keys, *const *spells; size_t count; const char *agent; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(strlen(request->url) == sizeof(url_prefix) - 1 + 24 + sizeof(url_suffix) - 1);
    CHECK(!memcmp(request->url, url_prefix, sizeof(url_prefix) - 1));
    CHECK(!memcmp(request->url + sizeof(url_prefix) - 1, script->spells[at], 24));
    CHECK(!strcmp(request->url + sizeof(url_prefix) - 1 + 24, url_suffix));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 737);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Apikey") && !strcmp(request->headers[1].value, script->keys[at]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, script->agent));
    /* No effective prepared request/header-array/UA is retained here. */
}

static void products(const br_detector *d)
{
    char input[512]; snprintf(input, sizeof(input), "metaapi %s\nmeta-api %s\nmetaapi %s\nmeta-api %s\nmetaapi %s\nmetaapi %s", spell_a, key_a, key_b, spell_b, key_a, spell_a);
    const char *keys[] = {key_a, key_b, key_a, key_a, key_b, key_a, key_a, key_b, key_a};
    const char *spells[] = {spell_a, spell_a, spell_a, spell_b, spell_b, spell_b, spell_a, spell_a, spell_a};
    request_script script = {keys, spells, 9, "TruffleHog metaapi-offline"};
    test_http http = {.inspect = inspect, .user = &script, .response = {.status = 204, .body = BYTES("notJSON:\"success\":true!")}};
    br_transport transport = test_transport(&http);
    const char *configured[] = {"https://unused.invalid"}; br_endpoints endpoints = {.configured = configured, .nconfigured = 1};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "metaapi-offline", .endpoints = &endpoints};
    for (size_t pass = 0; pass < 2; ++pass) {
        reset_observation(); http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 9 && findings == 9 && capture_calls == 2 && capture_clears == 2);
        CHECK(http.calls == (pass ? 9u : 0u) && sends == http.calls && releases == sends && http.releases == http.calls);
        for (size_t i = 0; i < 9; ++i) finding(&out.items[i], keys[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[3].secret_parts);
        br_results_clear(&out);
    }
    puts("MetaAPI all keys then all spells/spell-outer duplicate Cartesian products/NoV key-only metadata/exact URL and header order/UA/SANE: 0 failures");
}

static void response_policy(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "metaapi %s\nmeta-api %s", key_a, spell_a);
    const char *keys[] = {key_a}, *spells[] = {spell_a}; request_script script = {keys, spells, 1, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const struct { int status; br_slice body; const char *read_error; bool valid; } cases[] = {
        {199, BYTES(marker), NULL, false}, {200, BYTES(marker), NULL, true}, {204, BYTES("!\"success\":trueword!"), NULL, true},
        {299, BYTES("\xff\0junk\"success\":true!"), NULL, true}, {300, BYTES(marker), NULL, false},
        {401, BYTES(marker), NULL, false}, {500, BYTES(marker), NULL, false},
        {200, BYTES("{\"success\": true}"), NULL, false}, {200, BYTES("{\"success\" :true}"), NULL, false},
        {200, BYTES("{\"Success\":true}"), NULL, false}, {200, BYTES("{\"success\":TRUE}"), NULL, false},
        {200, BYTES("success:true"), NULL, false}, {200, BYTES("{\"success\":false}"), NULL, false}, {200, {0}, NULL, false},
        {200, BYTES(marker), "", false}, {204, BYTES(marker), "completed read failed", false},
        {401, {NULL, 5}, "", false}, {200, {NULL, 5}, "read failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        reset_observation(); http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body = cases[i].body, .body_error = cases[i].read_error};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && sends == 1 && releases == 1 && pushes == 1 && capture_clears == 2);
        finding(&out.items[0], key_a, cases[i].valid); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } errors[] = {
        {1, "context canceled"}, {-7, "context deadline exceeded"}, {1, "out of memory constructing HTTP headers"},
        {-1, "invalid MetaAPI response body slice"}, {7, "net/http: nil Context"}, {1, ""}, {-1, NULL},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); http.calls = http.releases = 0; http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = (br_http_response){.status = 200, .body = {NULL, 5}, .body_error = "read failed"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !projections && causes_freed == 1 && http.calls == 1 && http.releases == 1);
        finding(&out.items[0], key_a, false); br_results_clear(&out);
    }
    puts("MetaAPI read error at every status retains false/exact binary marker plus 2xx/no JSON or spacing tolerance/whole-send suppression/no setter: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void setup_and_null(const br_detector *d)
{
    char input[128]; snprintf(input, sizeof(input), "metaapi %s\nmeta-api %s", key_a, spell_a);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_transport missing_send = {&http, NULL, test_http_release}, missing_release = {&http, test_http_send, NULL}; size_t cancellations = 0;
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
    CHECK(!out.len && findings == 1 && capture_calls == 2 && capture_clears == 2 && !sends && !pushes); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && findings == 1 && !sends && pushes == 1); finding(&out.items[0], key_a, false); br_results_clear(&out);
    reset_observation(); out = test_scan(d, &contexts[3], false, input, strlen(input));
    CHECK(out.len == 1 && cancellations == 1 && !sends); br_results_clear(&out);
    puts("MetaAPI preparation guards release once/finding before nil skip/NoV zero context work/both owned collections cleared: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify, bool nil,
                        bool empty_keys, int status, const char *read_error, int send_rc, size_t attempts)
{
    char input[256];
    if (empty_keys) snprintf(input, sizeof(input), "metaapi %s", spell_a);
    else snprintf(input, sizeof(input), "metaapi %s\nmetaapi %s\nmeta-api %s", key_a, key_b, spell_a);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? "cannot append MetaAPI finding" : NULL,
        .response = {.status = status, .body = BYTES(marker), .body_error = read_error}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); fault = site; nth = occurrence; char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    const char *expected = site == CAPTURE ? "synthetic capture failure" : site == FINDING ? "cannot create MetaAPI finding" :
        site == BODY ? "invalid MetaAPI response body slice" : "cannot append MetaAPI finding";
    CHECK(error && !strcmp(error, expected)); free(error);
    CHECK(fault == NONE && !nth && fault_hit && capture_clears == 2 && !key_values && !spell_values && !original_cause);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, false, 200, NULL, 0, 0);
    own_failure(d, CAPTURE, 2, true, true, false, 200, NULL, 0, 0);
    own_failure(d, CAPTURE, 2, false, false, true, 200, NULL, 0, 0);
    own_failure(d, FINDING, 1, true, true, false, 200, NULL, 0, 0);
    own_failure(d, FINDING, 2, true, false, false, 200, NULL, 0, 1);
    own_failure(d, BODY, 2, true, false, false, 200, NULL, 0, 2);
    own_failure(d, BODY, 2, true, false, false, 401, NULL, 0, 2);
    own_failure(d, PUSH, 2, true, false, false, 200, NULL, 0, 2);
    own_failure(d, PUSH, 2, true, false, false, 200, "", 0, 2);
    own_failure(d, PUSH, 2, true, false, false, 200, "ignored", 7, 2);
    own_failure(d, PUSH, 2, false, false, false, 200, NULL, 0, 0);
    reset_observation(); br_results out = {0}; br_detector uninitialized = *d; uninitialized.state = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(&uninitialized, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !sends);
    puts("MetaAPI owned +1 collections/finding/push and invalid read slices fatal before ordinary outcomes/temporary cleanup/caller-preserving rollback: 0 failures");
}

int main(void)
{
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 64; ++i) { key_a[i] = hex[i % 16]; key_b[i] = hex[(i + 5) % 16]; }
    for (size_t i = 0; i < 24; ++i) { spell_a[i] = hex[(i + 3) % 16]; spell_b[i] = hex[(i + 9) % 16]; }
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 64 && strlen(key_b) == 64 && strlen(spell_a) == 24 && strlen(spell_b) == 24);
    const br_detector *d = descriptor(br_metaapi_init); grammar_and_dependency(d);
    for (size_t attempt = 1; attempt <= 2; ++attempt) {
        reset_observation(); fault = COMPILE; nth = attempt; const br_detector *failed = d; char *error = NULL;
        CHECK(observed_metaapi_init(&failed, &error) == -1 && !failed && error && !strcmp(error, "synthetic compile failure"));
        CHECK(fault_hit && fault == NONE && compiles == attempt && regex_frees == attempt && !metaapi_detector.state); free(error);
    }
    reset_observation(); const br_detector *observed = descriptor(observed_metaapi_init);
    CHECK(compiles == 2 && !regex_frees);
    products(observed); response_policy(observed); setup_and_null(observed); owned_resources(observed);
    CHECK(!original_request && !original_context && !original_cause && !key_values && !spell_values && fault == NONE);
    return test_finish("MetaAPI ABI1 focused checks");
}
