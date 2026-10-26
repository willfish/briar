/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

#define SLICE(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
#define SCOPE_TYPE(value) "json: cannot unmarshal " value " into Go struct field APIResponse.scopes of type []string"
#define ITEM_TYPE(value) "json: cannot unmarshal " value " into Go struct field APIResponse.scopes of type string"
#define ROOT_TYPE(value) "json: cannot unmarshal " value " into Go value of type buildkite.APIResponse"
static char v1_token[41], v1_other[41], v2_token[46], v2_other[46];
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_copy;

char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, value, len);
    return copy;
}

enum metadata { META_NIL, META_EMPTY, META_SCOPES };
typedef struct {
    const char *const *tokens;
    size_t count;
    uint32_t timeout_limit;
    const int *statuses;
    const br_slice *bodies;
} expected_requests;

static const br_detector *init(int version)
{
    int (*factory)(const br_detector **, char **) = version == 1 ? br_buildkite_v1_init : br_buildkite_v2_init;
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(factory(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 142 && detector->version == version && !strcmp(detector->name, "Buildkite"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, version == 1
        ? "Buildkite is a platform for running fast, secure, and scalable continuous integration pipelines. Buildkite API tokens can be used to access and modify pipeline data and configurations."
        : "Buildkite is a platform for running fast, secure, and scalable continuous integration and delivery pipelines. Buildkite access tokens can be used to interact with the Buildkite API."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], version == 1 ? "buildkite" : "bkua_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(factory(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(factory(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(factory(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, version == 1 ? "invalid Buildkite v1 detector output" : "invalid Buildkite v2 detector output"));
    free(error);
    CHECK(factory(NULL, NULL) != 0);
    return detector;
}

static void input_for(char *out, size_t cap, int version, const char *token)
{
    int n = snprintf(out, cap, "%s%s", version == 1 ? "buildkite " : "", token);
    CHECK(n > 0 && (size_t)n < cap);
}

static void check_result(const br_result *result, const char *token, enum metadata metadata,
                          br_slice scopes, const char *error)
{
    CHECK(result->detector_type == 142 && !result->detector_name);
    CHECK(result->raw.len == strlen(token) && !memcmp(result->raw.data, token, strlen(token)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)strlen(token) && !memcmp(json_object_get_string(part), token, strlen(token)));
    if (metadata == META_NIL) CHECK(!result->extra_data);
    else {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == (metadata == META_EMPTY ? 0 : 1));
        if (metadata == META_SCOPES) {
            CHECK(json_object_object_get_ex(result->extra_data, "scopes", &part));
            CHECK(json_object_is_type(part, json_type_string));
            CHECK(json_object_get_string_len(part) == (int)scopes.len);
            if (scopes.len) CHECK(!memcmp(json_object_get_string(part), scopes.data, scopes.len));
        }
        CHECK(!json_object_object_get_ex(result->extra_data, "version", &part));
    }
    CHECK(result->verified == (metadata == META_SCOPES));
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, detector->version == 1 ? META_EMPTY : META_NIL, (br_slice){0}, NULL);
    br_results_clear(&results);
}

static void test_extraction(const br_detector *v1, const br_detector *v2)
{
    char input[256], changed[46];
    const struct { const char *format; bool matches; } cases[] = {
        {"buildkite = '%s'", true}, {"BUILDKITE: %s", true}, {"preBuildkitesuffix=%s", true},
        {"%s", false}, {"%s buildkite", false}, {"buildkite%s", false},
        {"buildkite _%s", false}, {"buildkite %s_", false}, {"buildkite %sQ", false},
        {"buildkite %.39s", false}, {"buildkite\r\n%s", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, v1_token);
        extraction_case(v1, input, cases[i].matches ? v1_token : NULL);
    }
    memcpy(changed, v1_token, sizeof(v1_token)); changed[10] = 'A';
    snprintf(input, sizeof(input), "BUILDKITE %s", changed); extraction_case(v1, input, NULL);
    memset(changed, 'z', 40); changed[40] = '\0';
    input_for(input, sizeof(input), 1, changed); extraction_case(v1, input, changed); /* Not hex/entropy-filtered. */
    const char prefix[] = "buildkite";
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1); memset(input + sizeof(prefix) - 1, '.', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, v1_token, sizeof(v1_token));
        extraction_case(v1, input, gap == 40 ? v1_token : NULL);
    }
    extraction_case(v2, v2_token, v2_token); /* Direct pattern, no buildkite/provider prefix. */
    snprintf(input, sizeof(input), "(%s)", v2_token); extraction_case(v2, input, v2_token);
    snprintf(input, sizeof(input), "x%s", v2_token); extraction_case(v2, input, NULL);
    snprintf(input, sizeof(input), "%s_", v2_token); extraction_case(v2, input, NULL);
    snprintf(input, sizeof(input), "%s9", v2_token); extraction_case(v2, input, NULL);
    memcpy(changed, v2_token, sizeof(v2_token)); changed[0] = 'B'; extraction_case(v2, changed, NULL);
    memcpy(changed, v2_token, sizeof(v2_token)); changed[5] = 'A'; extraction_case(v2, changed, NULL);
    memcpy(changed, v2_token, sizeof(v2_token)); changed[44] = '\0'; extraction_case(v2, changed, NULL);
    extraction_case(v1, "", NULL); extraction_case(v2, "", NULL);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count && http->releases + 1 == http->calls);
    const char *token = expected->tokens[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.buildkite.com/v2/access-token"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 142);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    size_t auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Authorization")) {
            ++auth; CHECK(!strncmp(header->value, "Bearer ", 7) && !strcmp(header->value + 7, token));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent; CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog buildkite-test" : "TruffleHog"));
        } else CHECK(!"unexpected Buildkite header (no Accept, Content-Type or explicit length)");
    }
    CHECK(auth == 1 && agent == 1);
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
    if (expected->bodies) http->response.body = expected->bodies[http->calls - 1];
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *token, enum metadata metadata, br_slice scopes, const char *error)
{
    char input[80]; input_for(input, sizeof(input), detector->version, token);
    br_results results = test_scan(detector, ctx, verify, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], token, metadata, scopes, error); br_results_clear(&results);
}

static void expect_json(const br_detector *detector, const char *token, br_slice body,
                         const char *read_error, br_slice scopes, const char *error)
{
    const char *tokens[] = {token}; expected_requests expected = {.tokens = tokens, .count = 1};
    test_http http = {.response = {.status = 200, .body = body, .body_error = read_error}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    expect_one(detector, &ctx, true, token, error ? META_NIL : META_SCOPES, scopes, error);
    CHECK(http.calls == 1 && http.releases == 1);
}

static void test_scopes_and_backing_slots(const br_detector *detector, const char *token)
{
    const struct { const char *body; br_slice scopes; const char *error; } cases[] = {
        {"null", {NULL, 0}, NULL}, {"{}", {NULL, 0}, NULL},
        {"{\"scopes\":null}", {NULL, 0}, NULL}, {"{\"scopes\":[]}", {NULL, 0}, NULL},
        {"{\"scopes\":[\"zeta\",\"alpha\",\"alpha\"]}", SLICE("zeta, alpha, alpha"), NULL},
        {"{\"scopes\":[\"search\",\"listIndexes\",\"settings\"]}", SLICE("search, listIndexes, settings"), NULL}, /* No Algolia filtering. */
        {"{\"scopes\":[null,\"read\",null]}", SLICE(", read, "), NULL},
        {"{\"scopes\":[\"a\",\"b\",\"c\"],\"scopes\":[\"x\"]}", SLICE("x"), NULL},
        {"{\"scopes\":[\"a\",\"b\",\"c\"],\"scopes\":[\"x\"],\"scopes\":[null,null,null]}", SLICE("x, b, c"), NULL},
        {"{\"scopes\":[\"a\",\"b\"],\"Scopes\":[null,\"y\",null]}", SLICE("a, y, "), NULL},
        {"{\"scopes\":[\"a\",\"b\"],\"scopes\":null,\"scopes\":[null,null]}", SLICE(", "), NULL},
        {"{\"scopes\":[\"a\",\"b\"],\"scopes\":[],\"scopes\":[null,null]}", SLICE(", "), NULL},
        {"{\"scopes\":[\"old\"],\"scopes\":null}", {NULL, 0}, NULL},
        {"{\"scopes\":[\"old\"],\"scopes\":[]}", {NULL, 0}, NULL},
        {"{\"SCoPeS\":[\"read\"],\"SCOPES\":[null]}", SLICE("read"), NULL},
        {"{\"\\u017fcope\\u017f\":[\"read\"]}", SLICE("read"), NULL},
        {"{\"scopes\":[\"a\\u0000b\",\"\\u03a9\"]}", SLICE("a\0b, \xce\xa9"), NULL},
        {"{\"unknown\":{\"n\":[1e999,184467440737095516161234]},\"scopes\":[\"read\"]}", SLICE("read"), NULL},
        {"[]", {NULL, 0}, ROOT_TYPE("array")}, {"\"wrong\"", {NULL, 0}, ROOT_TYPE("string")},
        {"42", {NULL, 0}, ROOT_TYPE("number")}, {"true", {NULL, 0}, ROOT_TYPE("bool")},
        {"{\"scopes\":\"read\"}", {NULL, 0}, SCOPE_TYPE("string")},
        {"{\"scopes\":false}", {NULL, 0}, SCOPE_TYPE("bool")},
        {"{\"scopes\":{}}", {NULL, 0}, SCOPE_TYPE("object")},
        {"{\"scopes\":1e999}", {NULL, 0}, SCOPE_TYPE("number")},
        {"{\"scopes\":[\"ok\",1]}", {NULL, 0}, ITEM_TYPE("number")},
        {"{\"scopes\":[{}]}", {NULL, 0}, ITEM_TYPE("object")},
        {"{\"scopes\":[[]]}", {NULL, 0}, ITEM_TYPE("array")},
        {"{\"scopes\":[true]}", {NULL, 0}, ITEM_TYPE("bool")},
        {"{\"scopes\":[1],\"scopes\":[\"fixed\"]}", {NULL, 0}, ITEM_TYPE("number")},
        {"{\"scopes\":false,\"scopes\":[\"fixed\"]}", {NULL, 0}, SCOPE_TYPE("bool")},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        expect_json(detector, token, (br_slice){(const unsigned char *)cases[i].body, strlen(cases[i].body)}, NULL, cases[i].scopes, cases[i].error);
}

static void test_first_document_and_reads(const br_detector *detector, const char *token)
{
    expect_json(detector, token, SLICE("{\"scopes\":[\"read\"]}{\"scopes\":[\"ignored\"]}"), NULL, SLICE("read"), NULL);
    expect_json(detector, token, SLICE("{} {\"scopes\":[\"ignored\"]}"), NULL, (br_slice){0}, NULL);
    expect_json(detector, token, SLICE("{\"scopes\":[\"read\"]}garbage\0tail"), NULL, SLICE("read"), NULL);
    expect_json(detector, token, (br_slice){NULL, 0}, NULL, (br_slice){0}, "EOF");
    expect_json(detector, token, SLICE("{\"scopes\":[\"read\"]"), NULL, (br_slice){0}, "unexpected EOF");
    char cause[160]; snprintf(cause, sizeof(cause), "read token %s failed again %s", token, token);
    const char *redacted = "read token [REDACTED] failed again [REDACTED]";
    expect_json(detector, token, SLICE("{\"scopes\":[\"read\"]}"), cause, SLICE("read"), NULL);
    expect_json(detector, token, SLICE("{\"scopes\":false}"), cause, (br_slice){0}, SCOPE_TYPE("bool"));
    expect_json(detector, token, SLICE("{\"scopes\":[\"read\"]"), cause, (br_slice){0}, redacted);
    expect_json(detector, token, SLICE("{\"scopes\":false,"), cause, (br_slice){0}, redacted);
    expect_json(detector, token, SLICE("@"), cause, (br_slice){0}, "invalid character '@' looking for beginning of value");
    expect_json(detector, token, SLICE("\"wrong\""), cause, (br_slice){0}, redacted);
    expect_json(detector, token, SLICE("\"wrong\" "), cause, (br_slice){0}, ROOT_TYPE("string"));
}

static void test_occurrences_and_metadata(const br_detector *detector, const char *token, const char *other)
{
    char input[256], first[80], second[80]; input_for(first, sizeof(first), detector->version, token); input_for(second, sizeof(second), detector->version, other);
    snprintf(input, sizeof(input), "%s\n%s\n%s", first, second, first);
    const char *tokens[] = {token, other, token}; expected_requests expected = {.tokens = tokens, .count = 3};
    test_http http = {.response = {.status = 200, .body = SLICE("{\"scopes\":[]}")}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], detector->version == 1 ? META_EMPTY : META_NIL, (br_slice){0}, NULL);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], META_SCOPES, (br_slice){0}, NULL);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\n%s", first, first);
    const br_slice bodies[] = {SLICE("{\"scopes\":[1]}"), SLICE("{\"scopes\":[\"read\"]}")};
    const char *duplicates[] = {token, token};
    expected.tokens = duplicates; expected.count = 2; expected.bodies = bodies; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], token, META_NIL, (br_slice){0}, ITEM_TYPE("number"));
    check_result(&results.items[1], token, META_SCOPES, SLICE("read"), NULL); br_results_clear(&results);
}

static void test_status_and_errors(const br_detector *detector, const char *token, const char *other)
{
    const struct { int status; const char *error; } statuses[] = {
        {401, NULL}, {201, "unexpected HTTP response status 201"},
        {403, "unexpected HTTP response status 403"}, {503, status_503},
    };
    const char *tokens[] = {token}; expected_requests expected = {.tokens = tokens, .count = 1};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = SLICE("{\"scopes\":[\"ignored\"]}"), .body_error = "ignored non-200 body error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "buildkite-test"};
        expect_one(detector, &ctx, true, token, META_NIL, (br_slice){0}, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, token, detector->version == 1 ? META_EMPTY : META_NIL, (br_slice){0}, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char cause[224], redacted[160];
    snprintf(cause, sizeof(cause), "token %s repeats %s; keep %s", token, token, other);
    snprintf(redacted, sizeof(redacted), "token [REDACTED] repeats [REDACTED]; keep %s", other);
    const struct { const char *cause, *error; } failures[] = {
        {cause, redacted}, {"lookup synthetic: no such host", "lookup synthetic: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = SLICE("{\"scopes\":[\"ignored\"]}")},
                          .send_rc = i % 2 ? -1 : 1, .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, token, META_NIL, (br_slice){0}, failures[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context(const br_detector *detector, const char *token)
{
    const char *tokens[] = {token}; expected_requests expected = {.tokens = tokens, .count = 1, .timeout_limit = 2000};
    test_http http = {.response = {.status = 200, .body = SLICE("{\"scopes\":[\"read\"]}")}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_one(detector, &ctx, true, token, META_SCOPES, SLICE("read"), NULL);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 1;
    expect_one(detector, &ctx, true, token, META_NIL, (br_slice){0}, "context deadline exceeded");
    CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 0; ctx.cancelled = cancelled;
    expect_one(detector, &ctx, true, token, META_NIL, (br_slice){0}, "context canceled");
    CHECK(!http.calls && http.releases == 1);
    expect_one(detector, &ctx, false, token, detector->version == 1 ? META_EMPTY : META_NIL, (br_slice){0}, NULL);
    CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL; http.calls = http.releases = 0; expected.timeout_limit = 0;
    expect_one(detector, &ctx, true, token, META_SCOPES, SLICE("read"), NULL);
    CHECK(http.calls == 1 && http.releases == 1);
    expect_one(detector, NULL, true, token, META_NIL, (br_slice){0}, "net/http: nil Context");
    expect_one(detector, NULL, false, token, detector->version == 1 ? META_EMPTY : META_NIL, (br_slice){0}, NULL);
}

static void test_positive_setter_failure_rollback(const br_detector *detector, const char *token, const char *other)
{
    char input[192], first[80], second[80]; input_for(first, sizeof(first), detector->version, token); input_for(second, sizeof(second), detector->version, other);
    snprintf(input, sizeof(input), "%s\n%s", first, second);
    const char *tokens[] = {token, other}; const int statuses[] = {200, 503};
    expected_requests expected = {.tokens = tokens, .count = 2, .statuses = statuses};
    test_http http = {.response = {.body = SLICE("{\"scopes\":[\"read\"]}")}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    unsigned char *saved = results.items[0].raw.data; fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && !strcmp(error, "cannot store Buildkite verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], token, META_SCOPES, SLICE("read"), NULL);
    check_result(&results.items[1], other, META_NIL, (br_slice){0}, status_503); br_results_clear(&results);
}

int main(void)
{
    test_secret(v1_token, 40, 0); test_secret(v1_other, 40, 11); v1_token[39] = 'z'; v1_other[39] = 'g';
    snprintf(v2_token, sizeof(v2_token), "bkua_%s", v1_token); snprintf(v2_other, sizeof(v2_other), "bkua_%s", v1_other);
    const br_detector *v1 = init(1), *v2 = init(2); CHECK(v1 != v2 && v1->state != v2->state && v1->scan == v2->scan);
    test_extraction(v1, v2);
    test_scopes_and_backing_slots(v1, v1_token); test_scopes_and_backing_slots(v2, v2_token);
    test_first_document_and_reads(v1, v1_token); test_first_document_and_reads(v2, v2_token);
    test_occurrences_and_metadata(v1, v1_token, v1_other); test_occurrences_and_metadata(v2, v2_token, v2_other);
    test_status_and_errors(v1, v1_token, v1_other); test_status_and_errors(v2, v2_token, v2_other);
    test_context(v1, v1_token); test_context(v2, v2_token);
    test_positive_setter_failure_rollback(v1, v1_token, v1_other); test_positive_setter_failure_rollback(v2, v2_token, v2_other);
    return test_finish("Buildkite v1/v2 occurrence metadata + typed first-document scopes + slot reuse");
}
