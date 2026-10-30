/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

int br_mesibo_init(const br_detector **out, char **error); /* Main owns the shared declaration. */

/* Existing named-test inclusion seam, using real HTTP/JSON/result helpers and
 * focused owned-failure/lifetime observations rather than a new test framework. */
static void *checked_malloc(size_t);
static char *checked_strdup(const char *);
static void checked_free(void *);
static int checked_compile(const char *const *, size_t, const char *, br_regex **, char **);
static void checked_regex_free(br_regex *);
static int checked_captures(const br_regex *, br_slice, br_captures *, bool, char **);
static void checked_captures_clear(br_captures *);
static int checked_finding(br_result *, int32_t, br_slice, const char *);
static int checked_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
static void checked_release(const br_scan_ctx *, br_http_response *);
static int checked_document(br_slice, br_json **, char **);
static int checked_each(br_slice, br_json_member_fn, void *);
static int checked_type(br_json *, const char *, const char *, char **);
static int checked_json_put(br_json *);
static int checked_setter(br_result *, const char *, const br_slice *, size_t);
static int checked_push(br_results *, br_result *);
#define malloc checked_malloc
#define strdup checked_strdup
#define free checked_free
#define br_regex_compile_prefixed checked_compile
#define br_regex_free checked_regex_free
#define br_captures_find checked_captures
#define br_captures_clear checked_captures_clear
#define br_finding_key_bytes checked_finding
#define br_http_send checked_send
#define br_http_release checked_release
#define br_json_document checked_document
#define br_json_each_member checked_each
#define br_json_type_cause checked_type
#define json_object_put checked_json_put
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#define br_mesibo_init observed_mesibo_init
#include "../../src/detectors/mesibo.c"
#undef malloc
#undef strdup
#undef free
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_captures_clear
#undef br_finding_key_bytes
#undef br_http_send
#undef br_http_release
#undef br_json_document
#undef br_json_each_member
#undef br_json_type_cause
#undef json_object_put
#undef br_result_set_verification_error
#undef br_results_push
#undef br_mesibo_init

#define BYTES(s) {(const unsigned char *)(s), sizeof(s) - 1}
#define FIELD_CAUSE(type) "json: cannot unmarshal " type " into Go struct field apiResponse.code of type int"
#define NUMBER_CAUSE(token) FIELD_CAUSE("number " token)
#define TOP_CAUSE(type) "json: cannot unmarshal " type " into Go value of type mesibo.apiResponse"
static char key_a[65], key_b[65];
static const char url[] = "https://api.mesibo.com/backend";
static const char payload_prefix[] = "{\"op\":\"useradd\",\"token\":\"";
static const char create_prefix[] = "failed to create request: ";
static const char execute_prefix[] = "failed to execute request: ";
static const char read_prefix[] = "failed to read response body: ";
static const char decode_prefix[] = "failed to unmarshal response body: ";
typedef enum { NONE, COMPILE, CAPTURE, FINDING, DOCUMENT, VISIT, CAUSE, ALLOC, COPY, SETTER, PUSH, BODY } fault_site;
static fault_site fault;
static size_t nth, compiles, regex_frees, capture_clears, findings, sends, releases, documents, visits, type_causes;
static size_t malloc_calls, copy_calls, setters, pushes, setters_at_send;
static bool fault_hit;
static void *allocations[64];
static size_t nallocations;
static br_json *held_document;
static br_result *candidate;
static br_slice original_key;
static const br_http_request *original_request;
static const br_scan_ctx *original_context;
static const char *original_cause, *setter_leaf;
static const char *expected_leaf, *expected_wrapper;

static bool hit(fault_site site)
{
    if (fault != site || --nth) return false;
    fault = NONE; fault_hit = true;
    return true;
}

static void remember(void *pointer)
{
    if (!pointer) return;
    CHECK(nallocations < sizeof(allocations) / sizeof(*allocations));
    for (size_t i = 0; i < nallocations; ++i) CHECK(allocations[i] != pointer);
    allocations[nallocations++] = pointer;
}

static bool remembered(const void *pointer)
{
    for (size_t i = 0; i < nallocations; ++i) if (allocations[i] == pointer) return true;
    return false;
}

static void reset_observation(void)
{
    CHECK(!nallocations && !held_document && !original_request && !original_context && !original_cause && !setter_leaf);
    fault = NONE; nth = 0; fault_hit = false;
    compiles = regex_frees = capture_clears = findings = sends = releases = documents = visits = type_causes = 0;
    malloc_calls = copy_calls = setters = pushes = setters_at_send = 0;
    expected_leaf = expected_wrapper = NULL; candidate = NULL; original_key = (br_slice){0};
}

static void *checked_malloc(size_t size)
{
    ++malloc_calls;
    if (hit(ALLOC)) return NULL;
    void *value = malloc(size); remember(value); return value;
}

static char *checked_strdup(const char *text)
{
    ++copy_calls;
    if (hit(COPY)) return NULL;
    char *value = strdup(text); remember(value); return value;
}

static void checked_free(void *value)
{
    if (value && value == original_cause) { CHECK(!original_request && !original_context); original_cause = NULL; }
    if (value && value == setter_leaf) { CHECK(!original_request && sends == releases); setter_leaf = NULL; }
    for (size_t i = 0; i < nallocations; ++i)
        if (allocations[i] == value) { allocations[i] = allocations[--nallocations]; break; }
    free(value);
}

static int checked_compile(const char *const *keywords, size_t count, const char *pattern,
                           br_regex **out, char **error)
{
    CHECK(count == 1 && !strcmp(keywords[0], "mesibo") && !strcmp(pattern, "\\b([0-9A-Za-z]{64})\\b")); ++compiles;
    int rc = br_regex_compile_prefixed(keywords, count, pattern, out, error);
    if (rc == 0 && hit(COMPILE)) { *error = strdup("synthetic compile failure"); CHECK(*error); remember(*error); return 1; }
    return rc;
}

static void checked_regex_free(br_regex *regex)
{
    if (regex) ++regex_frees;
    br_regex_free(regex);
}

static int checked_captures(const br_regex *regex, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique);
    int rc = br_captures_find(regex, input, out, unique, error);
    if (rc == 0 && hit(CAPTURE)) { *error = strdup("synthetic capture failure"); CHECK(*error); remember(*error); return 1; }
    return rc;
}

static void checked_captures_clear(br_captures *values)
{
    CHECK(!original_request && !original_cause && !setter_leaf && !held_document && sends == releases);
    br_captures_clear(values); ++capture_clears;
    CHECK(!values->items && !values->lengths && !values->len && !values->cap);
}

static int checked_finding(br_result *result, int32_t type, br_slice key, const char *part)
{
    CHECK(!original_request && key.len == 64 && !strcmp(part, "key"));
    candidate = result; original_key = key; ++findings;
    int rc = br_finding_key_bytes(result, type, key, part);
    return rc == 0 && hit(FINDING) ? 1 : rc;
}

static void provider_values(void)
{
    CHECK(original_request && original_context && candidate && original_key.data);
    CHECK(!candidate->verified && !candidate->verification_error); /* Outer verdict follows helper release. */
    CHECK(!strcmp(original_request->method, "POST") && !strcmp(original_request->url, url));
    CHECK(original_request->profile == BR_HTTP_SANE && !original_request->timeout_ms && original_request->detector_type == 503);
    CHECK(original_request->nheaders == 1 && !strcmp(original_request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(original_request->headers[0].value, "application/json"));
    CHECK(original_request->body.len == 91 && original_request->body.data);
    CHECK(!memcmp(original_request->body.data, payload_prefix, sizeof(payload_prefix) - 1));
    CHECK(!memcmp(original_request->body.data + sizeof(payload_prefix) - 1, original_key.data, 64));
    CHECK(!memcmp(original_request->body.data + 89, "\"}", 2));
    CHECK(!original_request->dedup_key.data && !original_request->dedup_key.len);
    CHECK(candidate->raw.len == 64 && !memcmp(candidate->raw.data, original_key.data, 64));
    if (original_cause) CHECK(remembered(original_cause));
}

static int checked_send(const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    CHECK(!original_request && sends == releases && candidate && !candidate->verified && !nallocations);
    original_request = request; original_context = ctx; setters_at_send = setters; ++sends; provider_values();
    int rc = br_http_send(ctx, request, response, error);
    original_cause = *error; remember(*error);
    if (rc == 0 && hit(BODY)) response->body = (br_slice){NULL, 5};
    return rc;
}

static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(ctx == original_context && sends == releases + 1 && !held_document && setters == setters_at_send);
    provider_values(); br_http_release(ctx, response); provider_values();
    original_request = NULL; original_context = NULL; ++releases;
}

static int checked_document(br_slice body, br_json **out, char **cause)
{
    CHECK(original_request && !held_document && !candidate->verified); ++documents;
    int rc = br_json_document(body, out, cause);
    held_document = *out; remember(*cause);
    return hit(DOCUMENT) ? 2 : rc; /* +1 is the helper's ordinary decode-cause domain, +2 is fatal. */
}

typedef struct { br_json_member_fn callback; void *user; } member_proxy;
static int visit_proxy(void *user, br_slice name, br_json *value, br_slice encoded)
{
    member_proxy *proxy = user; ++visits;
    int rc = proxy->callback(proxy->user, name, value, encoded);
    return rc == 0 && hit(VISIT) ? 1 : rc;
}

static int checked_each(br_slice object, br_json_member_fn callback, void *user)
{
    CHECK(held_document && original_request);
    member_proxy proxy = {callback, user};
    return br_json_each_member(object, visit_proxy, &proxy);
}

static int checked_type(br_json *value, const char *field, const char *expected, char **cause)
{
    CHECK(original_request && !candidate->verified); ++type_causes;
    CHECK(field ? !strcmp(field, "apiResponse.code") && !strcmp(expected, "int") : !strcmp(expected, "mesibo.apiResponse"));
    int rc = br_json_type_cause(value, field, expected, cause); remember(*cause);
    return rc == 0 && hit(CAUSE) ? 1 : rc;
}

static int checked_json_put(br_json *value)
{
    if (value && value == held_document) held_document = NULL;
    return json_object_put(value); /* Refcount deletion's positive return is not an error status. */
}

static int checked_setter(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(result == candidate && cause && expected_leaf && !strcmp(cause, expected_leaf));
    CHECK(!original_request && !original_context && sends == releases && !held_document && !result->verified);
    CHECK(count == 1 && secrets && secrets[0].data == original_key.data && secrets[0].len == 64);
    CHECK(remembered(cause) && nallocations == (expected_wrapper ? 2u : 1u));
    if (expected_wrapper) {
        bool found = false; size_t prefix = strlen(expected_wrapper), length = strlen(cause);
        for (size_t i = 0; i < nallocations; ++i) {
            const char *text = allocations[i];
            if (strlen(text) == prefix + length && !memcmp(text, expected_wrapper, prefix) && !strcmp(text + prefix, cause)) found = true;
        }
        CHECK(found); /* Actual owned wrapper survives until the conditional setter. */
    }
    setter_leaf = cause; ++setters;
    int rc = br_result_set_verification_error(result, cause, secrets, count);
    return rc == 0 && hit(SETTER) ? 1 : rc;
}

static int checked_push(br_results *out, br_result *result)
{
    CHECK(result == candidate && !original_request && !held_document && !setter_leaf && !original_cause && !nallocations && sends == releases);
    ++pushes;
    return hit(PUSH) ? 1 : br_results_push(out, result);
}

static const br_detector *descriptor(int (*init)(const br_detector **, char **))
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(init(NULL, &error) == -1 && error); checked_free(error);
    CHECK(init(NULL, NULL) == -1);
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, NULL) == 0 && d == again);
    CHECK(d->type == 503 && !d->version && !strcmp(d->name, "Mesibo") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Mesibo is a real-time communication platform that allows developers to add messaging, voice, and video calls to their apps. Mesibo tokens can be used to access and interact with the Mesibo API."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "mesibo"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *r, const char *key, bool verified, const char *error)
{
    test_key_result(r, 503, key, "key"); CHECK(r->raw.len == 64 && r->verified == verified);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) finding(&out.items[0], key, false, NULL);
    br_results_clear(&out);
}

static void grammar(const br_detector *d)
{
    char input[256], changed[65];
    const struct { const char *format; bool match; } cases[] = {
        {"mesibo '%s'", true}, {"MeSiBo:%s", true}, {"mymesibosuffix:%s", true},
        {"mesibo\r\n%s", true}, {"mesibo\t%s", true}, {"mesibo é%sé", true},
        {"%s", false}, {"%s mesibo", false}, {"me sibo %s", false},
        {"mesibo%s", false}, {"mesibo x%s", false}, {"mesibo _%s", false},
        {"mesibo %s_", false}, {"mesibo %s9", false}, {"mesibo %.63s", false},
        {"mesibo %s %s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key_a, key_b);
        extract_case(d, input, strlen(input), cases[i].match ? key_a : NULL);
    }
    const char invalid[] = "_-/= ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key_a, sizeof(changed)); changed[32] = invalid[i];
        snprintf(input, sizeof(input), "mesibo %s", changed); extract_case(d, input, strlen(input), NULL);
    }
    const char repeated[] = "0AZaz";
    for (size_t i = 0; i < sizeof(repeated) - 1; ++i) {
        memset(changed, repeated[i], 64); changed[64] = '\0';
        snprintf(input, sizeof(input), "mesibo %s", changed); extract_case(d, input, strlen(input), changed);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "mesibo", 6); memset(input + 6, '.', gap); memcpy(input + 6 + gap, key_a, 64);
        extract_case(d, input, 70 + gap, gap == 40 ? key_a : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 6 + 2 * i, "\xc3\xa9", 2);
        memcpy(input + 6 + 2 * gap, key_a, 64); extract_case(d, input, 70 + 2 * gap, gap == 40 ? key_a : NULL);
    }
    int n = snprintf(input, sizeof(input), "mesibo%c%s", 0, key_a);
    extract_case(d, input, (size_t)n, key_a); extract_case(d, NULL, 0, NULL);
    puts("Mesibo mixed-alnum64/case/boundaries/40-rune CR-LF-NUL prefix/no local filtering/NoV metadata: 0 failures");
}

typedef struct { const char *const *keys; size_t count; const char *agent; } request_script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    request_script *script = http->user; size_t at = http->calls - 1;
    CHECK(ctx && at < script->count && http->calls == http->releases + 1);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 503);
    CHECK(request->body.len == 91 && !memcmp(request->body.data, payload_prefix, sizeof(payload_prefix) - 1));
    CHECK(!memcmp(request->body.data + sizeof(payload_prefix) - 1, script->keys[at], 64));
    CHECK(!memcmp(request->body.data + 89, "\"}", 2));
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, script->agent));
    /* Effective prepared request/header-array/UA are borrowed only inside send. */
}

static void occurrences(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "mesibo %s\nMESIBO %s\nmesibo %s", key_a, key_b, key_a);
    const char *keys[] = {key_a, key_b, key_a}; request_script script = {keys, 3, "TruffleHog mesibo-offline"};
    test_http http = {.inspect = inspect, .user = &script, .response = {.status = 200, .body = BYTES("{\"code\":400}")}};
    br_transport transport = test_transport(&http);
    const char *configured[] = {"https://unused.invalid"}; br_endpoints endpoints = {.configured = configured, .nconfigured = 1};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "mesibo-offline", .endpoints = &endpoints};
    for (size_t pass = 0; pass < 2; ++pass) {
        reset_observation();
        br_results out = test_scan(d, &ctx, pass != 0, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls && !setters);
        for (size_t i = 0; i < 3; ++i) finding(&out.items[i], keys[i], pass != 0, NULL);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        CHECK(!nallocations); br_results_clear(&out);
    }
    puts("Mesibo duplicate/source order/key-only fields/exact sorted 91-byte POST/Content-Type/SANE/UA/empty key/400 no setter: 0 failures");
}

static void json_policy(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "mesibo %s", key_a);
    const char *keys[] = {key_a}; request_script script = {keys, 1, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const struct { br_slice body; bool verified; const char *leaf, *wrapper; size_t members; } cases[] = {
        {BYTES("{\"code\":400}"), true, NULL, NULL, 1}, {BYTES("{\"code\":401}"), false, NULL, NULL, 1},
        {BYTES("{\"CoDe\":400,\"code\":null}"), true, NULL, NULL, 2},
        {BYTES("{\"code\":401,\"CODE\":400}"), true, NULL, NULL, 2},
        {BYTES("{\"code\":400,\"code\":401}"), false, NULL, NULL, 2},
        {BYTES("{\"c\\u006fde\":400}"), true, NULL, NULL, 1},
        {BYTES("{\"code\":null,\"code\":400}"), true, NULL, NULL, 2},
        {BYTES("{\"code\":400,\"code\\u0000\":401}"), true, NULL, NULL, 2},
        {BYTES("{\"unknown\":1e9999,\"code\":400}"), true, NULL, NULL, 2},
        {BYTES("{\"unknown\":{\"x\":99999999999999999999999999999},\"code\":400}"), true, NULL, NULL, 2},
        {BYTES("{\"code\":400 \t\n}\r\n"), true, NULL, NULL, 1},
        {BYTES("{}"), false, "unexpected code field: 0", NULL, 0},
        {BYTES("null"), false, "unexpected code field: 0", NULL, 0},
        {BYTES("{\"other\":400}"), false, "unexpected code field: 0", NULL, 1},
        {BYTES("{\"code\":null}"), false, "unexpected code field: 0", NULL, 1},
        {BYTES("{\"code\":-0}"), false, "unexpected code field: 0", NULL, 1},
        {BYTES("{\"code\":402}"), false, "unexpected code field: 402", NULL, 1},
        {BYTES("{\"code\":-7}"), false, "unexpected code field: -7", NULL, 1},
        {BYTES("{\"code\":9223372036854775807}"), false, "unexpected code field: 9223372036854775807", NULL, 1},
        {BYTES("{\"code\":-9223372036854775808}"), false, "unexpected code field: -9223372036854775808", NULL, 1},
        {BYTES("{\"code\":400.0}"), false, NUMBER_CAUSE("400.0"), decode_prefix, 1},
        {BYTES("{\"code\":4e2}"), false, NUMBER_CAUSE("4e2"), decode_prefix, 1},
        {BYTES("{\"code\":4E+2}"), false, NUMBER_CAUSE("4E+2"), decode_prefix, 1},
        {BYTES("{\"code\":9223372036854775808}"), false, NUMBER_CAUSE("9223372036854775808"), decode_prefix, 1},
        {BYTES("{\"code\":-9223372036854775809}"), false, NUMBER_CAUSE("-9223372036854775809"), decode_prefix, 1},
        {BYTES("{\"code\":18446744073709551615}"), false, NUMBER_CAUSE("18446744073709551615"), decode_prefix, 1},
        {BYTES("{\"code\":1e9999}"), false, NUMBER_CAUSE("1e9999"), decode_prefix, 1},
        {BYTES("{\"code\":\"400\"}"), false, FIELD_CAUSE("string"), decode_prefix, 1},
        {BYTES("{\"code\":true}"), false, FIELD_CAUSE("bool"), decode_prefix, 1},
        {BYTES("{\"code\":[]}"), false, FIELD_CAUSE("array"), decode_prefix, 1},
        {BYTES("{\"code\":{}}"), false, FIELD_CAUSE("object"), decode_prefix, 1},
        {BYTES("{\"code\":\"bad\",\"code\":400,\"unknown\":1e9999}"), false, FIELD_CAUSE("string"), decode_prefix, 3},
        {BYTES("{\"code\":false,\"code\":9223372036854775808,\"code\":null,\"code\":400}"), false, FIELD_CAUSE("bool"), decode_prefix, 4},
        {BYTES("{\"code\":400.0 \n,\"code\":400}"), false, NUMBER_CAUSE("400.0"), decode_prefix, 2},
        {BYTES("[]"), false, TOP_CAUSE("array"), decode_prefix, 0},
        {BYTES("true"), false, TOP_CAUSE("bool"), decode_prefix, 0},
        {BYTES("400"), false, TOP_CAUSE("number"), decode_prefix, 0},
        {BYTES("\"text\""), false, TOP_CAUSE("string"), decode_prefix, 0},
        {BYTES("{\"code\":400}x"), false, "invalid character 'x' after top-level value", decode_prefix, 0},
        {BYTES("{\"code\":\"bad\"}x"), false, "invalid character 'x' after top-level value", decode_prefix, 0},
        {BYTES("{\"code\":400}{\"code\":401}"), false, "invalid character '{' after top-level value", decode_prefix, 0},
        {BYTES("{"), false, "unexpected end of JSON input", decode_prefix, 0},
        {BYTES(""), false, "unexpected end of JSON input", decode_prefix, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        reset_observation(); expected_leaf = cases[i].leaf; expected_wrapper = cases[i].wrapper; http.calls = http.releases = 0;
        http.response = (br_http_response){.status = 200, .body = cases[i].body};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && sends == 1 && releases == 1 && documents == 1 && visits == cases[i].members);
        CHECK(setters == (cases[i].leaf ? 1u : 0u) && !nallocations && !held_document && !setter_leaf);
        finding(&out.items[0], key_a, cases[i].verified, cases[i].leaf); br_results_clear(&out);
    }
    puts("Mesibo whole JSON/Go-int64 original tokens/null duplicate merge/fold/sticky first error/continued visits/unknown huge numbers/no float coercion: 0 failures");
}

static void error_precedence(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "mesibo %s", key_a);
    const char *keys[] = {key_a}; request_script script = {keys, 1, "TruffleHog"};
    test_http http = {.inspect = inspect, .user = &script}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    const int statuses[] = {0, -7, 199, 201, 204, 299, 400, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char leaf[80]; snprintf(leaf, sizeof(leaf), "unexpected status code: %d", statuses[i]);
        reset_observation(); expected_leaf = leaf; http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {NULL, 5}, .body_error = "must not read"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !documents && !visits && setters == 1 && sends == 1 && releases == 1 && !nallocations);
        finding(&out.items[0], key_a, false, leaf); br_results_clear(&out);
    }
    const char *read_errors[] = {"", "completed read failed"};
    for (size_t i = 0; i < 2; ++i) {
        reset_observation(); expected_leaf = read_errors[i]; expected_wrapper = read_prefix; http.calls = http.releases = 0;
        http.response = (br_http_response){.status = 200, .body = BYTES("{\"code\":400}"), .body_error = read_errors[i]};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !documents && setters == 1 && !nallocations);
        finding(&out.items[0], key_a, false, read_errors[i]); br_results_clear(&out);
    }
    const struct { int rc; const char *cause, *stored; } errors[] = {
        {1, "context canceled", "context canceled"}, {-7, "context deadline exceeded", "context deadline exceeded"},
        {1, "out of memory constructing HTTP headers", "out of memory constructing HTTP headers"},
        {1, "failed to execute request: literal backend text", "failed to execute request: literal backend text"},
        {1, "net/http: nil Context", "net/http: nil Context"}, {1, "", ""}, {-1, NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset_observation(); expected_leaf = errors[i].stored; expected_wrapper = execute_prefix; http.calls = http.releases = 0;
        http.send_rc = errors[i].rc; http.send_error = errors[i].cause;
        http.response = (br_http_response){.status = 200, .body = BYTES("{\"code\":400}"), .body_error = "do not read"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && !documents && setters == 1 && !nallocations);
        finding(&out.items[0], key_a, false, errors[i].stored); br_results_clear(&out);
    }
    puts("Mesibo whole-send/status/read/unmarshal precedence/constructed wrappers but stored explicit leaf/no diagnostic stripping/empty causes retained: 0 failures");
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void nil_guards_redaction(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "mesibo %s", key_a);
    reset_observation(); expected_leaf = "net/http: nil Context"; expected_wrapper = create_prefix;
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && findings == 1 && setters == 1 && !sends && !releases && !documents && !nallocations);
    finding(&out.items[0], key_a, false, "net/http: nil Context"); br_results_clear(&out);
    reset_observation(); out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && !setters && !sends && !malloc_calls && !copy_calls); finding(&out.items[0], key_a, false, NULL); br_results_clear(&out);
    test_http http = {0}; br_transport transport = test_transport(&http);
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    const char *leaves[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded", "invalid HTTP user agent"};
    for (size_t i = 0; i < 4; ++i) {
        reset_observation(); expected_leaf = leaves[i]; expected_wrapper = execute_prefix; http.calls = http.releases = 0;
        out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u) && sends == 1 && releases == 1 && setters == 1);
        finding(&out.items[0], key_a, false, leaves[i]); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
    reset_observation(); out = test_scan(d, &contexts[1], false, input, strlen(input));
    CHECK(out.len == 1 && cancellations == 1 && !sends && !setters); br_results_clear(&out);
    char echo[192]; snprintf(echo, sizeof(echo), "provider %s and %s", key_a, key_a);
    for (size_t i = 0; i < 2; ++i) {
        reset_observation(); expected_leaf = echo; expected_wrapper = i ? read_prefix : execute_prefix;
        http.calls = http.releases = 0; http.send_rc = i ? 0 : 1; http.send_error = i ? NULL : echo;
        http.response = (br_http_response){.status = 200, .body = BYTES("{\"code\":400}"), .body_error = i ? echo : NULL};
        br_scan_ctx ctx = {.transport = &transport}; out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && setters == 1 && !documents && !nallocations);
        finding(&out.items[0], key_a, false, "provider [REDACTED] and [REDACTED]"); br_results_clear(&out);
    }
    for (size_t i = 0; i < 3; ++i) {
        reset_observation(); fault = SETTER; nth = 1; http.calls = http.releases = 0; http.send_rc = 0; http.send_error = NULL;
        http.response = (br_http_response){.status = 200, .body = i == 2 ? (br_slice)BYTES("{\"code\":401}") : (br_slice)BYTES("{\"code\":400}")};
        br_scan_ctx ctx = {.transport = &transport}; out = test_scan(d, &ctx, i != 0, input, strlen(input));
        CHECK(out.len == 1 && !setters && !fault_hit && fault == SETTER && nth == 1 && !nallocations);
        finding(&out.items[0], key_a, i == 1, NULL); br_results_clear(&out);
    }
    reset_observation();
    puts("Mesibo nil context retains finding/stored leaf only/guard release once/full-key redaction/conditional setter absent for NoV-400-401: 0 failures");
}

static void own_failure(const br_detector *d, fault_site site, size_t occurrence, bool verify, bool nil,
                        int status, const char *body, const char *read_error, int send_rc,
                        const char *leaf, const char *wrapper, const char *fatal, size_t attempts)
{
    char input[160]; snprintf(input, sizeof(input), "mesibo %s\nmesibo %s", key_a, key_b);
    br_results out = {0}; br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    test_http http = {.send_rc = send_rc, .send_error = send_rc ? leaf : NULL,
        .response = {.status = status, .body = {(const unsigned char *)body, strlen(body)}, .body_error = read_error}};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    reset_observation(); expected_leaf = leaf; expected_wrapper = wrapper; fault = site; nth = occurrence;
    char *error = NULL;
    CHECK(d->scan(d, nil ? NULL : &ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, fatal)); checked_free(error);
    CHECK(fault_hit && fault == NONE && !nth && !nallocations && capture_clears == 1 && !held_document);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
    CHECK(prior.verified && !strcmp(prior.verification_error, "caller-owned") && !memcmp(prior.raw.data, "prior", 5));
    CHECK(sends == attempts && releases == attempts && http.calls == attempts && http.releases == attempts);
    br_results_clear(&out);
}

static void owned_resources(const br_detector *d)
{
    own_failure(d, CAPTURE, 1, true, true, 200, "{}", NULL, 0, NULL, NULL, "synthetic capture failure", 0);
    own_failure(d, FINDING, 1, true, true, 200, "{}", NULL, 0, NULL, NULL, "cannot create Mesibo finding", 0);
    own_failure(d, FINDING, 2, true, false, 200, "{\"code\":400}", NULL, 0, NULL, NULL, "cannot create Mesibo finding", 1);
    own_failure(d, COPY, 1, true, true, 200, "{}", NULL, 0, NULL, NULL, "cannot copy Mesibo verification cause", 0);
    own_failure(d, ALLOC, 1, true, true, 200, "{}", NULL, 0, NULL, NULL, "cannot wrap Mesibo verification error", 0);
    own_failure(d, ALLOC, 1, true, false, 200, "{}", NULL, 1, "synthetic cause", execute_prefix, "cannot wrap Mesibo verification error", 1);
    own_failure(d, COPY, 1, true, false, 200, "{\"code\":400}", "read cause", 0, NULL, NULL, "cannot copy Mesibo verification cause", 1);
    own_failure(d, ALLOC, 1, true, false, 503, "{}", "ignored", 0, NULL, NULL, "cannot format Mesibo verification cause", 1);
    own_failure(d, DOCUMENT, 1, true, false, 200, "{\"code\":400}", NULL, 0, NULL, NULL, "cannot decode Mesibo response document", 1);
    own_failure(d, DOCUMENT, 1, true, false, 200, "{", NULL, 0, NULL, NULL, "cannot decode Mesibo response document", 1);
    own_failure(d, VISIT, 2, true, false, 200, "{\"code\":\"bad\",\"code\":400,\"unknown\":1e9999}", NULL, 0, NULL, NULL, "cannot visit Mesibo response fields", 1);
    own_failure(d, CAUSE, 2, true, false, 200, "{\"code\":\"bad\",\"code\":false}", NULL, 0, NULL, NULL, "cannot create Mesibo field type cause", 1);
    own_failure(d, ALLOC, 1, true, false, 200, "{\"code\":4e2}", NULL, 0, NULL, NULL, "cannot create Mesibo number type cause", 1);
    own_failure(d, ALLOC, 2, true, false, 200, "{\"code\":4e2}", NULL, 0, NULL, NULL, "cannot wrap Mesibo verification error", 1);
    own_failure(d, BODY, 2, true, false, 200, "{\"code\":400}", NULL, 0, NULL, NULL, "invalid Mesibo response body slice", 2);
    own_failure(d, SETTER, 2, true, false, 200, "{\"code\":402}", NULL, 0, "unexpected code field: 402", NULL, "cannot set Mesibo verification error", 2);
    own_failure(d, SETTER, 2, true, false, 200, "{}", NULL, 1, "wrapped leaf", execute_prefix, "cannot set Mesibo verification error", 2);
    own_failure(d, PUSH, 2, true, false, 200, "{\"code\":400}", NULL, 0, NULL, NULL, "cannot append Mesibo finding", 2);
    own_failure(d, PUSH, 2, true, false, 200, "{}", "read leaf", 0, "read leaf", read_prefix, "cannot append Mesibo finding", 2);
    own_failure(d, PUSH, 2, false, false, 200, "{}", NULL, 0, NULL, NULL, "cannot append Mesibo finding", 0);
    reset_observation(); br_results out = {0}; br_detector uninitialized = *d; uninitialized.state = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(&uninitialized, NULL, false, (br_slice){0}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, NULL) == -1);
    CHECK(d->scan(d, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    CHECK(!out.len && !nallocations && !sends);
    puts("Mesibo owned +1 capture/finding/typed cause/visit/setter/push and checked cause/wrap allocation failures fatal/cleanup/invocation-only rollback: 0 failures");
}

int main(void)
{
    test_secret(key_a, 64, 0); key_a[0] = 'A'; key_a[32] = 'Z';
    test_secret(key_b, 64, 17); key_b[0] = 'B'; key_b[32] = 'Y';
    CHECK(BR_ABI_REVISION == 1 && strlen(key_a) == 64 && strlen(key_b) == 64 && sizeof(payload_prefix) - 1 == 25);
    const br_detector *d = descriptor(br_mesibo_init); grammar(d);
    reset_observation(); fault = COMPILE; nth = 1; const br_detector *failed = d; char *error = NULL;
    CHECK(observed_mesibo_init(&failed, &error) == -1 && !failed && error && !strcmp(error, "synthetic compile failure"));
    CHECK(fault_hit && compiles == 1 && regex_frees == 1 && !mesibo_detector.state); checked_free(error);
    reset_observation(); const br_detector *observed = descriptor(observed_mesibo_init);
    occurrences(observed); json_policy(observed); error_precedence(observed); nil_guards_redaction(observed); owned_resources(observed);
    CHECK(!nallocations && !held_document && !original_request && !original_cause && !setter_leaf && fault == NONE);
    return test_finish("Mesibo ABI1 focused checks");
}
