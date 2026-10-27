/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static const char key[] = "0123456789abcdef0123456789abcdef01234567";
static const char other_key[] = "fedcba9876543210fedcba9876543210fedcba98";
static const char yes[] = "{\"data\":{\"id\":\"x\"}}";
static const char wrong[] = "{\"data\":{\"id\":1}}";
static const char type_cause[] = "json: cannot unmarshal number into Go struct field response.data.id of type string";
static const char *tracked_cause = type_cause;
static bool track_cause;
static size_t cause_copies, fail_cause_after;

/* Count/fail the helper's owned cause and the ACTUAL core setter's subsequent
 * copy. This does not replace the provider's KEEP/SKIP/ABORT decisions. */
char *strdup(const char *value)
{
    if (track_cause && !strcmp(value, tracked_cause)) {
        ++cause_copies;
        if (fail_cause_after && --fail_cause_after == 0) return NULL;
    }
    size_t len = strlen(value) + 1; char *copy = malloc(len); if (copy) memcpy(copy, value, len); return copy;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 40 && strlen(other_key) == 40);
    CHECK(br_codeclimate_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 844 && detector->version == 0 && !strcmp(detector->name, "Codeclimate") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Codeclimate is a tool for automated code review and analysis. Codeclimate tokens can be used to access and manage repositories and their analysis results."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "codeclimate"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *state = detector->state;
    CHECK(br_codeclimate_init(&again, &error) == 0 && !error && again == detector && again->state == state);
    CHECK(br_codeclimate_init(&again, NULL) == 0 && again == detector && again->state == state);
    CHECK(br_codeclimate_init(NULL, &error) != 0 && error && !strcmp(error, "invalid Codeclimate detector output"));
    free(error); CHECK(br_codeclimate_init(NULL, NULL) != 0); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 844, expected, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[41];
    const struct { const char *format; bool matches; } cases[] = {
        {"codeclimate '%s'", true}, {"CODECLIMATE=-%s-", true}, {"preCoDeClImAtEsuffix\r\n%s", true},
        {"codeclimate \t(%s)==\r\n", true}, {"%s", false}, {"code climate %s", false},
        {"codeclimate _%s", false}, {"codeclimate %s_", false}, {"codeclimate x%s", false},
        {"codeclimate %sa", false}, {"codeclimate %.39s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, key); extraction_case(detector, input, cases[i].matches ? key : NULL);
    }
    memcpy(changed, key, sizeof(changed)); changed[0] = 'A'; snprintf(input, sizeof(input), "CODECLIMATE %s", changed); extraction_case(detector, input, NULL);
    changed[0] = 'g'; snprintf(input, sizeof(input), "codeclimate %s", changed); extraction_case(detector, input, NULL);
    memset(changed, '0', 40); changed[40] = '\0'; snprintf(input, sizeof(input), "codeclimate %s", changed); extraction_case(detector, input, changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "codeclimate", 11); memset(input + 11, '.', gap); memcpy(input + 11 + gap, key, sizeof(key));
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    extraction_case(detector, "", NULL);
}

typedef struct {
    const char *key; int status; br_slice body; const char *read_error;
    int send_rc; const char *send_error; size_t copies_before_release;
} reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *expected_ctx; const char *borrowed_auth; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    const reply *step = &steps->rows[at];
    CHECK(request->detector_type == 844 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.codeclimate.com/v1/user"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/vnd.api+json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 52);
    CHECK(!strncmp(request->headers[1].value, "Token token=", 12) && !strcmp(request->headers[1].value + 12, step->key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog")); /* No Content-Type or logical Content-Length. */
    steps->borrowed_auth = request->headers[1].value;
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->read_error};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; CHECK(http->calls && http->calls <= steps->count);
    const reply *step = &steps->rows[http->calls - 1];
    CHECK(steps->borrowed_auth && strlen(steps->borrowed_auth) == 52 && !strcmp(steps->borrowed_auth + 12, step->key)); steps->borrowed_auth = NULL;
    if (step->copies_before_release) CHECK(cause_copies == step->copies_before_release);
    test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == (verify ? steps->count : 0u) && http.releases == http.calls && !steps->borrowed_auth); return results;
}

static void nested_typed_projection(const br_detector *detector)
{
    const struct { const char *body; bool keep, verified; } cases[] = {
        {"{}", true, false}, {"null", true, false}, {yes, true, true},
        {"{\"data\":null}", true, false}, {"{\"data\":{}}", true, false},
        {"{\"data\":{\"id\":null}}", true, false}, {"{\"data\":{\"id\":\"\"}}", true, false},
        {"{\"DATA\":{\"ID\":\"x\"}}", true, true},
        {"{\"data\":{\"id\":\"x\"},\"data\":{}}", true, true},
        {"{\"data\":{\"id\":\"x\"},\"DATA\":null}", true, true},
        {"{\"data\":{\"id\":\"x\"},\"data\":{\"id\":null}}", true, true},
        {"{\"data\":{\"id\":\"x\"},\"data\":{\"ID\":\"\"}}", true, false},
        {"{\"data\":{\"id\":\"x\",\"id\":null}}", true, true},
        {"{\"data\":{\"id\":\"x\",\"ID\":\"\"}}", true, false},
        {"{\"data\":{\"ID\":\"\",\"id\":\"last\"}}", true, true},
        {"{\"data\":{\"id\":\"\\u0000\"}}", true, true}, /* LENGTH=1, not strlen=0. */
        {"{\"data\":{\"id\":\"\\u0000x\"}}", true, true},
        {"{\"data\":{\"id\":\" \"}}", true, true}, {"{\"data\":{\"id\":\"\\n\"}}", true, true},
        {"{\"unknown\":{\"id\":\"not Data\"}}", true, false},
        {"{\"data\":{\"unknown\":{\"id\":\"not Id\"}}}", true, false},
        {"{\"unknown\":1e999,\"data\":{\"id\":\"x\",\"unknown\":[999999999999999999999999999999999999999999]}}", true, true},
        {"{\"data\":1}", false, false}, {"{\"data\":[]}", false, false}, {"{\"data\":true}", false, false}, {"{\"data\":\"wrong\"}", false, false},
        {wrong, false, false}, {"{\"data\":{\"id\":false}}", false, false}, {"{\"data\":{\"id\":[]}}", false, false}, {"{\"data\":{\"id\":{}}}", false, false},
        {"{\"data\":{\"id\":1,\"id\":\"later\"}}", false, false},
        {"{\"data\":1,\"data\":{\"id\":\"later\"}}", false, false},
        {"{\"data\":{\"id\":\"ok\"},\"data\":{\"id\":1},\"data\":{\"id\":\"later\"}}", false, false},
        {"[]", false, false}, {"true", false, false}, {"42", false, false}, {"\"root string\"", false, false}, {"", false, false}, {"{", false, false},
        {"{\"data\":{\"id\":\"x\"}} {\"data\":{\"id\":\"\"}}", true, true},
        {"{\"data\":{\"id\":\"\"}} trailing garbage", true, false},
    };
    char input[64]; snprintf(input, sizeof(input), "codeclimate %s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = 200, .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}}}};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == (cases[i].keep ? 1u : 0u));
        if (cases[i].keep) check_result(&results.items[0], key, cases[i].verified);
        br_results_clear(&results);
    }
}

static void first_document_read_boundaries(const br_detector *detector)
{
    const struct { br_slice body; bool keep, verified; } cases[] = {
        {TEXT(yes), true, true}, {TEXT("{}"), true, false}, {TEXT("null "), true, false},
        {TEXT("{\"data\":{\"id\":"), false, false},
        {TEXT("{\"data\":{\"id\":\"x\"}} trailing\0junk"), true, true},
    };
    char input[64], read_error[128]; snprintf(input, sizeof(input), "codeclimate %s", key); snprintf(read_error, sizeof(read_error), "terminal read error key=%s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = 201, .body = cases[i].body, .read_error = read_error, .copies_before_release = cases[i].keep ? 0 : 2}}};
        tracked_cause = read_error; cause_copies = 0; track_cause = true;
        br_results results = run(detector, input, true, &steps); track_cause = false;
        CHECK(results.len == (cases[i].keep ? 1u : 0u) && cause_copies == (cases[i].keep ? 0u : 2u));
        if (cases[i].keep) check_result(&results.items[0], key, cases[i].verified);
        br_results_clear(&results);
    }
    tracked_cause = type_cause;
}

static void occurrence_drop_status_and_do(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "codeclimate %s\ncodeclimate %s\ncodeclimate %s", key, other_key, key);
    script steps = {.count = 3, .rows = {
        {.key = key, .status = 200, .body = TEXT(yes)},
        {.key = other_key, .status = 200, .body = TEXT(wrong), .read_error = "ignored after complete object", .copies_before_release = 2},
        {.key = key, .status = 299, .body = TEXT(yes)},
    }};
    br_results results = run(detector, input, false, &steps); CHECK(results.len == 3);
    check_result(&results.items[0], key, false); check_result(&results.items[1], other_key, false); check_result(&results.items[2], key, false); br_results_clear(&results);
    tracked_cause = type_cause; cause_copies = 0; track_cause = true;
    results = run(detector, input, true, &steps); track_cause = false;
    CHECK(results.len == 2 && cause_copies == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], key, true); br_results_clear(&results);
    snprintf(input, sizeof(input), "codeclimate %s", key);
    const int statuses[] = {199, 300, 401, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        steps = (script){.count = 1, .rows = {{.key = key, .status = statuses[i], .body = TEXT(wrong), .read_error = "ignored"}}}; cause_copies = 0; track_cause = true;
        results = run(detector, input, true, &steps); track_cause = false; CHECK(results.len == 1 && !cause_copies); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    steps = (script){.count = 1, .rows = {{.key = key, .status = 204}}};
    results = run(detector, input, true, &steps); CHECK(!results.len); br_results_clear(&results); /* Empty 2xx body => Decode EOF => DROP. */
    const char *errors[] = {"no such host", "net/http: nil Context", "context canceled", "context deadline exceeded", "out of memory constructing HTTP headers", "unsupported: native SANE policy", NULL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        steps = (script){.count = 1, .rows = {{.key = key, .status = 200, .body = TEXT(wrong), .read_error = "ignored", .send_rc = i % 2 ? 1 : -1, .send_error = errors[i]}}}; cause_copies = 0; track_cause = true;
        results = run(detector, input, true, &steps); track_cause = false; CHECK(results.len == 1 && !cause_copies); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void contexts(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "codeclimate %s\ncodeclimate %s", key, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_result(&results.items[0], key, false); check_result(&results.items[1], key, false); br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctxs[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}};
    for (size_t i = 0; i < sizeof(ctxs) / sizeof(ctxs[0]); ++i) {
        http.calls = http.releases = 0; results = test_scan(detector, &ctxs[i], true, input, strlen(input)); CHECK(results.len == 2 && !http.calls && http.releases == (i ? 2u : 0u));
        check_result(&results.items[0], key, false); check_result(&results.items[1], key, false); br_results_clear(&results);
    }
}

static void resource_before_drop(const br_detector *detector)
{
    br_result probe = {0}; tracked_cause = type_cause; track_cause = true; cause_copies = 0; fail_cause_after = 1;
    CHECK(br_result_set_verification_error(&probe, type_cause, NULL, 0) == 1 && !fail_cause_after && cause_copies == 1 && !probe.verification_error);
    track_cause = false; br_result_clear(&probe); /* Actual setter +1 is NOT private SKIP. */
    char input[192]; snprintf(input, sizeof(input), "codeclimate %s\ncodeclimate %s\ncodeclimate %s", key, other_key, key);
    for (size_t fail_at = 1; fail_at <= 2; ++fail_at) {
        script steps = {.count = 3, .rows = {
            {.key = key, .status = 200, .body = TEXT(yes)},
            {.key = other_key, .status = 200, .body = TEXT(wrong), .copies_before_release = fail_at},
            {.key = key, .status = 200, .body = TEXT(yes)},
        }};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(&results, &prior) == 0);
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        cause_copies = 0; fail_cause_after = fail_at; track_cause = true;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); track_cause = false;
        CHECK(rc == -1 && error && !strcmp(error, fail_at == 1 ? "cannot decode Codeclimate response" : "cannot sanitize Codeclimate decode error"));
        CHECK(!fail_cause_after && cause_copies == fail_at && http.calls == 2 && http.releases == 2 && results.len == 1 && !steps.borrowed_auth);
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); free(error); br_results_clear(&results);
    }
    script recovered = {.count = 3, .rows = {
        {.key = key, .status = 200, .body = TEXT(yes)},
        {.key = other_key, .status = 200, .body = TEXT(wrong), .copies_before_release = 2},
        {.key = key, .status = 200, .body = TEXT(yes)},
    }};
    cause_copies = 0; track_cause = true; br_results results = run(detector, input, true, &recovered); track_cause = false;
    CHECK(results.len == 2 && cause_copies == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], key, true); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); nested_typed_projection(detector); first_document_read_boundaries(detector);
    occurrence_drop_status_and_do(detector); contexts(detector); resource_before_drop(detector);
    return test_finish("Codeclimate nested first-document projection + value-struct reuse + fatal-before-drop");
}
