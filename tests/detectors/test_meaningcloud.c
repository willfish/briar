/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"
#include <openssl/rand.h>
#include <json-c/json_util.h>

int br_meaningcloud_init(const br_detector **out, char **error);
#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
#define TYPE(v) "json: cannot unmarshal " v " into Go struct field response.deepTime of type float64"
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static char key[33], other[33];
typedef enum { NONE, COMPILE, CAPTURE, FINDING, RANDOM, DOCUMENT, VISITOR, TYPE_CAUSE, ALLOCATE, SETTER, PUSH } fault_kind;
static fault_kind fault;
static size_t fail_nth, failures, freed_patterns, random_calls, current_draw;
static int random_failure;
static size_t sends, releases, setters, documents;
static size_t document_override_nth, null_type_causes, type_causes, numbers, null_setters;
static int document_override_status;
static const br_http_request *provider_request;
static const br_scan_ctx *provider_ctx;
static br_result *active_result;
static char *last_cause;
static char events[128];
static size_t nevents;
static bool watch;

static bool hit(fault_kind kind)
{
    if (fault != kind || (fail_nth && --fail_nth)) return false;
    fault = NONE; ++failures; return true;
}
static void event(char c)
{
    if (!watch) return;
    CHECK(nevents + 1 < sizeof(events)); events[nevents++] = c; events[nevents] = 0;
}
/* Existing module-local seams: injected synthetic bytes, not production RNG
 * configuration, a provider verdict callback or a new test framework. */
static int checked_random(unsigned char *out, int count)
{
    CHECK(out && count == 30 && active_result && active_result->raw.len == 32);
    current_draw = random_calls++;
    for (int i = 0; i < count; ++i) out[i] = (unsigned char)(current_draw + (size_t)i);
    return hit(RANDOM) ? random_failure : 1;
}
static void *checked_malloc(size_t n) { return hit(ALLOCATE) ? NULL : malloc(n); }
static int checked_compile(const char *const *keywords, size_t count, const char *capture, br_regex **out, char **error)
{
    CHECK(count == 1 && !strcmp(keywords[0], "meaningcloud") && !strcmp(capture, "\\b([a-z0-9]{32})\\b"));
    int rc = br_regex_compile_prefixed(keywords, count, capture, out, error);
    if (rc == 0 && hit(COMPILE)) { if (error) *error = strdup("synthetic compile failure"); return 1; }
    return rc;
}
static void checked_free(br_regex *r) { if (r) ++freed_patterns; br_regex_free(r); }
static int checked_capture(const br_regex *r, br_slice input, br_captures *out, bool unique, char **error)
{
    CHECK(!unique); int rc = br_captures_find(r, input, out, unique, error);
    return rc == 0 && hit(CAPTURE) ? 1 : rc;
}
static int checked_finding(br_result *r, int32_t type, br_slice token, const char *part)
{
    int rc = br_finding_key_bytes(r, type, token, part); active_result = r;
    return rc == 0 && hit(FINDING) ? 1 : rc;
}
static int checked_document(br_slice body, const char *read, br_json **out, size_t *end, char **cause)
{
    ++documents;
    if (hit(DOCUMENT)) return -1;
    int rc = br_json_first_document(body, read, out, end, cause);
    if (document_override_nth && --document_override_nth == 0) {
        free(*cause); *cause = NULL;
        return document_override_status;
    }
    return rc;
}
static int checked_visitor(br_slice object, br_json_member_fn fn, void *u)
{
    int rc = br_json_each_member(object, fn, u);
    return rc == 0 && hit(VISITOR) ? 1 : rc;
}
static int checked_type_cause(br_json *v, const char *field, const char *expected, char **cause)
{
    ++type_causes;
    int rc = br_json_type_cause(v, field, expected, cause);
    if (rc == 0 && null_type_causes) { --null_type_causes; free(*cause); *cause = NULL; }
    return rc == 0 && hit(TYPE_CAUSE) ? 1 : rc;
}
static int checked_number(const char *token, double *out)
{
    ++numbers; return json_parse_double(token, out);
}
static void request_values(const br_http_request *r, bool effective)
{
    CHECK(active_result && active_result->raw.len == 32 && r->detector_type == 622 && r->profile == BR_HTTP_SANE);
    CHECK(!strcmp(r->method, "POST") && !strcmp(r->url, "https://api.meaningcloud.com/lang-4.0/identification"));
    CHECK(r->timeout_ms == (effective ? 5000u : 0u) && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders == (effective ? 2u : 1u) && !strcmp(r->headers[0].name, "Content-Type"));
    char boundary[61], content_type[91], body[327], token[33];
    for (size_t i = 0; i < 30; ++i) CHECK(snprintf(boundary + 2 * i, 3, "%02x", (unsigned int)(unsigned char)(current_draw + i)) == 2);
    if (!current_draw) CHECK(!strcmp(boundary, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"));
    memcpy(token, active_result->raw.data, 32); token[32] = 0;
    CHECK(snprintf(content_type, sizeof(content_type), "multipart/form-data; boundary=%s", boundary) == 90);
    CHECK(strlen(r->headers[0].value) == 90 && !strcmp(r->headers[0].value, content_type));
    CHECK(snprintf(body, sizeof(body), "--%s\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name=\"txt\"\r\n\r\ntest\r\n--%s--\r\n", boundary, token, boundary, boundary) == 326);
    CHECK(r->body.data && r->body.len == 326 && !memcmp(r->body.data, body, 326));
}
static int checked_send(const br_scan_ctx *ctx, const br_http_request *r, br_http_response *response, char **error)
{
    CHECK(ctx && !provider_request && !active_result->verification_error);
    request_values(r, false); provider_request = r; provider_ctx = ctx; ++sends;
    return br_http_send(ctx, r, response, error);
}
static void checked_release(const br_scan_ctx *ctx, br_http_response *response)
{
    CHECK(provider_request && provider_ctx == ctx);
    /* Provider ORIGINAL body/type/header/key/URL only, never prepared storage. */
    request_values(provider_request, false);
    br_http_release(ctx, response); ++releases; event('R'); provider_request = NULL; provider_ctx = NULL;
}
static int checked_setter(br_result *r, const char *cause, const br_slice *secrets, size_t count)
{
    CHECK(r == active_result && provider_request && sends == releases + 1 && secrets && count == 1);
    CHECK(secrets[0].len == 32 && !memcmp(secrets[0].data, r->raw.data, 32));
    ++setters; if (!cause) ++null_setters; event('S');
    if (hit(SETTER)) return 1;
    int rc = br_result_set_verification_error(r, cause, secrets, count);
    CHECK(!rc && (!!r->verification_error == !!cause));
    free(last_cause); last_cause = r->verification_error ? strdup(r->verification_error) : NULL;
    CHECK(!r->verification_error || last_cause);
    return rc;
}
static int checked_push(br_results *out, br_result *r)
{
    CHECK(r == active_result && !provider_request && sends == releases); event('P');
    return hit(PUSH) ? 1 : br_results_push(out, r);
}

#define malloc checked_malloc
#define RAND_bytes checked_random
#define br_regex_compile_prefixed checked_compile
#define br_regex_free checked_free
#define br_captures_find checked_capture
#define br_finding_key_bytes checked_finding
#define br_json_first_document checked_document
#define br_json_each_member checked_visitor
#define br_json_type_cause checked_type_cause
#define json_parse_double checked_number
#define br_http_send checked_send
#define br_http_release checked_release
#define br_result_set_verification_error checked_setter
#define br_results_push checked_push
#include "../../src/detectors/meaningcloud.c"
#undef malloc
#undef RAND_bytes
#undef br_regex_compile_prefixed
#undef br_regex_free
#undef br_captures_find
#undef br_finding_key_bytes
#undef br_json_first_document
#undef br_json_each_member
#undef br_json_type_cause
#undef json_parse_double
#undef br_http_send
#undef br_http_release
#undef br_result_set_verification_error
#undef br_results_push

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_meaningcloud_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_meaningcloud_init(NULL, NULL) == -1);
    fault = COMPILE; fail_nth = 1;
    CHECK(br_meaningcloud_init(&d, &error) == -1 && !d && error && fault == NONE && freed_patterns == 1); free(error); error = NULL;
    CHECK(!br_meaningcloud_init(&d, &error) && d && !error && !br_meaningcloud_init(&again, NULL) && again == d);
    CHECK(d->type == 622 && !d->version && !strcmp(d->name, "MeaningCloud") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "MeaningCloud is a text analytics service used to extract insights from unstructured content. MeaningCloud API keys can be used to access and utilize these text analytics services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "meaningcloud"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint && !random_calls);
    return d;
}
static void result_is(const br_result *r, const char *token, bool verified)
{
    test_key_result(r, 622, token, "key"); CHECK(r->verified == verified && !r->verification_error);
}
static void extract(const br_detector *d, const void *input, size_t len, const char *token)
{
    size_t rng = random_calls, sent = sends, set = setters;
    br_results out = test_scan(d, NULL, false, input, len);
    CHECK(out.len == (token ? 1u : 0u) && random_calls == rng && sends == sent && setters == set);
    if (token) result_is(&out.items[0], token, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[300], changed[34];
    const char *good[] = {"meaningcloud '%s'", "MeAnInGcLoUd=-%s-", "myMEANINGCLOUDsuffix\r\n%s", "meaningcloud\r%s", "meaningcloud\n%s", "meaningcloud \t%s\t ", "meaningcloud é%sé"};
    const char *bad[] = {"%s", "meaning cloud %s", "%s meaningcloud", "meaningcloud%s", "meaningcloud _%s", "meaningcloud %s_", "meaningcloud %sa", "meaningcloud %.31s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], key); extract(d, input, strlen(input), key); }
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], key); extract(d, input, strlen(input), NULL); }
    const char invalid[] = "A_-+/ ";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[15] = invalid[i]; snprintf(input, sizeof(input), "meaningcloud %s", changed); extract(d, input, strlen(input), NULL);
    }
    memset(changed, 'a', 32); changed[32] = 0; snprintf(input, sizeof(input), "meaningcloud %s", changed); extract(d, input, strlen(input), changed);
    memset(changed, '0', 32); snprintf(input, sizeof(input), "meaningcloud %s", changed); extract(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "meaningcloud", 12); memset(input + 12, ':', gap); memcpy(input + 12 + gap, key, 32); extract(d, input, 44 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 12 + 4 * i, "💡", 4);
        memcpy(input + 12 + 4 * gap, key, 32); extract(d, input, 44 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "meaningcloud\0", 13); memcpy(input + 13, key, 32); extract(d, input, 45, key);
    snprintf(input, sizeof(input), "meaningcloud %s %s", key, other); extract(d, input, strlen(input), key);
    extract(d, NULL, 0, NULL);
}

static const char *expected_agent = "TruffleHog";
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; CHECK(provider_request && ctx == provider_ctx); request_values(r, true);
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, expected_agent));
}
static br_results response(const br_detector *d, int status, br_slice body, const char *read, const char *send_error, int send_rc)
{
    char input[60]; snprintf(input, sizeof(input), "meaningcloud %s", key);
    test_http http = {.inspect = inspect, .response = {.status = status, .body = body, .body_error = read}, .send_error = send_error, .send_rc = send_rc};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t rng = random_calls, sent = sends, released = releases;
    nevents = 0; events[0] = 0; watch = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input)); watch = false;
    CHECK(random_calls == rng + 1 && sends == sent + 1 && releases == released + 1 && http.calls == 1 && http.releases == 1 && !provider_request);
    return out;
}
static void json_case(const br_detector *d, br_slice body, const char *read, bool verified, const char *cause)
{
    size_t set = setters;
    br_results out = response(d, 200, body, read, NULL, 0);
    CHECK(out.len == (cause ? 0u : 1u) && setters == set + (cause ? 1u : 0u));
    CHECK(!strcmp(events, cause ? "SR" : "RP"));
    if (cause) CHECK(last_cause && !strcmp(last_cause, cause));
    else result_is(&out.items[0], key, verified);
    br_results_clear(&out);
}
static void requests_and_statuses(const br_detector *d)
{
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        size_t set = setters, doc = documents;
        bool success = statuses[i] >= 200 && statuses[i] < 300;
        br_results out = response(d, statuses[i], success ? TEXT("{\"deepTime\":2}") : TEXT("{invalid"), "ignored after complete value", NULL, 0);
        CHECK(out.len == 1 && setters == set && documents == doc + (success ? 1u : 0u) && !strcmp(events, "RP"));
        result_is(&out.items[0], key, success); br_results_clear(&out);
    }
    const char *causes[] = {"timeout", "out of memory constructing HTTP headers", "cannot generate MeaningCloud multipart boundary", "cannot decode MeaningCloud response", key, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(*causes); ++i) {
        size_t set = setters, doc = documents;
        br_results out = response(d, 200, TEXT("{bad"), "ignored", causes[i], i % 2 ? -7 : 1);
        CHECK(out.len == 1 && setters == set && documents == doc && !strcmp(events, "RP"));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
}
static void typed_json(const br_detector *d)
{
    const struct { const char *body; bool verified; } values[] = {
        {"null", false}, {"{}", false}, {"{\"deepTime\":null}", false}, {"{\"deepTime\":0}", false},
        {"{\"deepTime\":-0.0}", false}, {"{\"deepTime\":-1}", false}, {"{\"deepTime\":2.5}", true},
        {"{\"deepTime\":1e-10000}", false}, {"{\"deepTime\":-1e-10000}", false},
        {"{\"deepTime\":3e-324}", true}, {"{\"deepTime\":1e-324}", false},
        {"{\"deepTime\":4.9406564584124654e-324}", true}, {"{\"deepTime\":1.7976931348623157e308}", true},
        {"{\"deepTime\":9999999999999999999999999999999999999999}", true},
        {"{\"deepTime\":2,\"DEEPTIME\":null}", true}, {"{\"deepTime\":2,\"DeepTime\":-1}", false},
        {"{\"ignored\":1e999999,\"nested\":{\"deepTime\":false},\"deepTime\":1}", true},
        {"{\"deep_time\":8}", false},
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(*values); ++i) json_case(d, text(values[i].body), NULL, values[i].verified, NULL);
    json_case(d, TEXT("{\"deepTime\":2} {bad trailing"), "late read failure", true, NULL);
    fault = ALLOCATE; fail_nth = 1;
    json_case(d, TEXT("{\"ignored\":1e999999}"), NULL, false, NULL);
    CHECK(fault == ALLOCATE && fail_nth == 1); fault = NONE;
    const struct { const char *body, *cause; } errors[] = {
        {"[]", "json: cannot unmarshal array into Go value of type meaningcloud.response"},
        {"7", "json: cannot unmarshal number into Go value of type meaningcloud.response"},
        {"\"value\"", "json: cannot unmarshal string into Go value of type meaningcloud.response"},
        {"true", "json: cannot unmarshal bool into Go value of type meaningcloud.response"},
        {"{\"deepTime\":\"2\"}", TYPE("string")}, {"{\"deepTime\":true}", TYPE("bool")},
        {"{\"deepTime\":[]}", TYPE("array")}, {"{\"deepTime\":{}}", TYPE("object")},
        {"{\"deepTime\":1e99999}", TYPE("number 1e99999")}, {"{\"deepTime\":-1e9999}", TYPE("number -1e9999")},
        {"{\"deepTime\":1.7976931348623159e308}", TYPE("number 1.7976931348623159e308")},
        {"{\"deepTime\":false,\"deepTime\":2}", TYPE("bool")},
        {"{\"deepTime\":1e9999,\"deepTime\":2}", TYPE("number 1e9999")},
        {"", "EOF"}, {" \r\n", "EOF"}, {"{", "unexpected EOF"},
        {"{bad", "invalid character 'b' looking for beginning of object key string"},
    };
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) json_case(d, text(errors[i].body), NULL, false, errors[i].cause);
    json_case(d, TEXT("{\"deepTime\":false}"), "late read failure", false, TYPE("bool"));
    json_case(d, TEXT("{"), "partial read failure", false, "partial read failure");
    json_case(d, TEXT("\"scalar\""), "partial read failure", false, "partial read failure");
    json_case(d, (br_slice){0}, "", false, "");
    char cause[100]; snprintf(cause, sizeof(cause), "reading %s twice %s", key, key);
    json_case(d, TEXT("{"), cause, false, "reading [REDACTED] twice [REDACTED]");
}
static void nullable_errors(const br_detector *d)
{
    /* Component status/presence tuples, not native/backend/guard evidence. */
    size_t set = setters, nulls = null_setters, numeric = numbers;
    document_override_nth = 1; document_override_status = 1;
    br_results out = response(d, 200, TEXT("{\"deepTime\":2}"), NULL, NULL, 0);
    CHECK(!out.len && setters == set + 1 && null_setters == nulls + 1 && numbers == numeric);
    CHECK(!document_override_nth && !last_cause && !strcmp(events, "SR")); br_results_clear(&out);
    set = setters; nulls = null_setters;
    document_override_nth = 1; document_override_status = 0;
    out = response(d, 200, TEXT("null"), NULL, NULL, 0);
    CHECK(out.len == 1 && setters == set && null_setters == nulls && !document_override_nth && !strcmp(events, "RP"));
    result_is(&out.items[0], key, false); br_results_clear(&out);
    const struct { const char *body; size_t numeric; } cases[] = {
        {"[]", 0}, {"{\"deepTime\":false}", 0},
        {"{\"deepTime\":false,\"deepTime\":2}", 1},
        {"{\"deepTime\":false,\"DEEPTIME\":null,\"deepTime\":2}", 1},
        {"{\"deepTime\":false,\"deepTime\":\"later\",\"deepTime\":2}", 1},
        {"{\"deepTime\":false,\"deepTime\":1e9999,\"deepTime\":2}", 2},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        set = setters; nulls = null_setters; numeric = numbers; size_t types = type_causes;
        null_type_causes = 1;
        out = response(d, 200, text(cases[i].body), NULL, NULL, 0);
        CHECK(!out.len && setters == set + 1 && null_setters == nulls + 1 && !null_type_causes);
        CHECK(type_causes == types + 1 && numbers == numeric + cases[i].numeric && !last_cause && !strcmp(events, "SR"));
        br_results_clear(&out);
    }
}
static void inspect_three(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    inspect(http, ctx, r);
    size_t at = http->calls - 1; CHECK(at < 3);
    const char *expected[] = {key, other, key};
    CHECK(!memcmp(active_result->raw.data, expected[at], 32));
    http->response = (br_http_response){.status = 200, .body = at == 0 ? TEXT("{\"deepTime\":false}") : at == 1 ? TEXT("{\"deepTime\":2}") : TEXT("{}")};
}
static void occurrences_and_nil(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "meaningcloud %s\nmeaningcloud %s\nmeaningcloud %s", key, other, key);
    test_http http = {.inspect = inspect_three}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "meaningcloud-offline"}; expected_agent = "TruffleHog meaningcloud-offline";
    size_t rng = random_calls, set = setters, sent = sends;
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == 3 && random_calls == rng && sends == sent && !http.calls);
    result_is(&out.items[0], key, false); result_is(&out.items[1], other, false); result_is(&out.items[2], key, false); br_results_clear(&out);
    nevents = 0; events[0] = 0; watch = true;
    out = test_scan(d, &ctx, true, input, strlen(input)); watch = false;
    CHECK(out.len == 2 && http.calls == 3 && http.releases == 3 && random_calls == rng + 3 && setters == set + 1 && !strcmp(events, "SRRPRP"));
    result_is(&out.items[0], other, true); result_is(&out.items[1], key, false); br_results_clear(&out);
    rng = random_calls; sent = sends; set = setters;
    out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && random_calls == rng + 3 && sends == sent && setters == set); br_results_clear(&out);
    expected_agent = "TruffleHog";
}
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void preparation(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); size_t cancellations = 0;
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations}, {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"}};
    char input[60]; snprintf(input, sizeof(input), "meaningcloud %s", key);
    for (size_t i = 0; i < sizeof(contexts) / sizeof(*contexts); ++i) {
        size_t rng = random_calls, sent = sends, released = releases, set = setters; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], false, input, strlen(input));
        CHECK(out.len == 1 && random_calls == rng && sends == sent); br_results_clear(&out);
        out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && random_calls == rng + 1 && sends == sent + 1 && releases == released + 1 && setters == set && !http.calls && http.releases == (i ? 1u : 0u));
        result_is(&out.items[0], key, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void owned_failures(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "meaningcloud %s\nmeaningcloud %s", key, other);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true; prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { fault_kind kind; size_t nth; const char *body; bool nil, nov; } cases[] = {
        {CAPTURE, 1, NULL, true, false}, {FINDING, 1, NULL, true, false},
        {FINDING, 2, NULL, false, false}, {FINDING, 2, NULL, true, true},
        {RANDOM, 1, NULL, true, false}, {RANDOM, 2, NULL, false, false},
        {DOCUMENT, 1, NULL, false, false}, {VISITOR, 1, "{\"deepTime\":false}", false, false},
        {TYPE_CAUSE, 1, "{\"deepTime\":false}", false, false},
        {ALLOCATE, 1, NULL, false, false}, {ALLOCATE, 2, "{\"deepTime\":1e9999}", false, false},
        {ALLOCATE, 1, "{\"deepTime\":false,\"deepTime\":2}", false, false},
        {ALLOCATE, 3, "{\"deepTime\":1e9999,\"deepTime\":2}", false, false},
        {SETTER, 1, "{", false, false}, {SETTER, 1, "{\"deepTime\":false}", false, false},
        {PUSH, 1, NULL, false, false}, {PUSH, 2, NULL, false, false}, {PUSH, 2, NULL, true, true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.inspect = inspect, .response = {.status = 200, .body = text(cases[i].body ? cases[i].body : "{\"deepTime\":2}")}};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        size_t failed = failures, sent = sends, released = releases, rng = random_calls, set = setters;
        fault = cases[i].kind; fail_nth = cases[i].nth; random_failure = 0; char *error = NULL;
        CHECK(d->scan(d, cases[i].nil ? NULL : &ctx, !cases[i].nov, text(input), &out, &error) == -1);
        CHECK(error && fault == NONE && failures == failed + 1 && out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)));
        CHECK(sends - sent == releases - released && !provider_request);
        if (cases[i].nil || cases[i].nov) CHECK(sends == sent);
        if (cases[i].kind == CAPTURE || (cases[i].kind == FINDING && cases[i].nth == 1) || cases[i].nov) CHECK(random_calls == rng);
        if (cases[i].kind != SETTER) CHECK(setters == set);
        free(error); active_result = NULL;
    }
    const int rng_errors[] = {-1, 2};
    for (size_t i = 0; i < 2; ++i) {
        fault = RANDOM; fail_nth = 1; random_failure = rng_errors[i]; size_t sent = sends; char *error = NULL;
        CHECK(d->scan(d, NULL, true, text(input), &out, &error) == -1 && error && fault == NONE && sends == sent);
        CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); free(error);
    }
    char *error = NULL;
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, &out, &error) == -1 && error); free(error); error = NULL;
    CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
    CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior))); br_results_clear(&out);
}
static void nullable_owned_failures(const br_detector *d)
{
    char input[120]; snprintf(input, sizeof(input), "meaningcloud %s\nmeaningcloud %s", key, other);
    br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "caller", "key")); prior.verified = true;
    prior.verification_error = strdup("untouched"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(!br_results_push(&out, &prior)); prior = out.items[0];
    const struct { size_t doc_nth; int status; bool typed; fault_kind kind; } cases[] = {
        {1,1,false,SETTER}, {2,1,false,SETTER}, {0,0,true,SETTER},
        {0,0,true,VISITOR}, {0,0,true,TYPE_CAUSE}, {0,0,true,ALLOCATE},
        {1,2,false,NONE}, {2,2,false,NONE},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        test_http http = {.inspect = inspect, .response = {.status = 200,
            .body = cases[i].typed ? TEXT("{\"deepTime\":false,\"deepTime\":2}") : TEXT("{\"deepTime\":2}")}};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        document_override_nth = cases[i].doc_nth; document_override_status = cases[i].status;
        null_type_causes = cases[i].typed ? 1 : 0; fault = cases[i].kind; fail_nth = 1;
        size_t sent = sends, released = releases, set = setters, nulls = null_setters, failed = failures;
        nevents = 0; events[0] = 0; watch = true; char *error = NULL;
        CHECK(d->scan(d, &ctx, true, text(input), &out, &error) == -1); watch = false;
        CHECK(error && fault == NONE && !document_override_nth && !null_type_causes);
        CHECK(failures == failed + (cases[i].kind == NONE ? 0u : 1u));
        CHECK(out.len == 1 && !memcmp(&out.items[0], &prior, sizeof(prior)) && !provider_request);
        CHECK(sends - sent == releases - released && sends == sent + (cases[i].doc_nth == 2 ? 2u : 1u));
        CHECK(setters == set + (cases[i].kind == SETTER ? 1u : 0u) && null_setters == nulls + (cases[i].kind == SETTER ? 1u : 0u));
        CHECK(!strcmp(events, cases[i].kind == SETTER ? (cases[i].doc_nth == 2 ? "RPSR" : "SR") : cases[i].doc_nth == 2 ? "RPR" : "R"));
        free(error); active_result = NULL;
    }
    br_results_clear(&out);
}
int main(void)
{
    test_secret(key, 32, 0); key[0] = 'g'; key[31] = 'z'; test_secret(other, 32, 7); other[0] = 'q'; other[31] = 'g';
    const br_detector *d = descriptor(); extraction(d); requests_and_statuses(d); typed_json(d); nullable_errors(d); occurrences_and_nil(d); preparation(d); owned_failures(d); nullable_owned_failures(d);
    CHECK(fault == NONE && sends == releases && !provider_request && !watch && !document_override_nth && !null_type_causes);
    free(last_cause); return test_finish("MeaningCloud");
}
