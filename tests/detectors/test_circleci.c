/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char v1_token[41], v1_other[41], v2_token[71], v2_other[71];
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;
static size_t fail_version_after;

char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, value, len);
    return copy;
}

/* The source-required metadata allocation is separate from finding allocation.
 * Forward ordinary strings to the real byte-length constructor. */
struct json_object *json_object_new_string(const char *value)
{
    if (!value) return NULL;
    if (fail_version_after && (!strcmp(value, "1") || !strcmp(value, "2")) && --fail_version_after == 0) return NULL;
    return json_object_new_string_len(value, (int)strlen(value));
}

typedef struct {
    const char *const *tokens;
    size_t count;
    uint32_t timeout_limit;
    const int *statuses;
} expected_requests;

static const br_detector *descriptor(int version)
{
    int (*factory)(const br_detector **, char **) = version == 1 ? br_circleci_v1_init : br_circleci_v2_init;
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(factory(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 4 && detector->type != 37 && detector->version == version && !strcmp(detector->name, "Circle"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "CircleCI is a continuous integration and delivery platform used to build, test, and deploy software. "
        "CircleCI tokens can be used to interact with the CircleCI API and access various resources and functionalities."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], version == 1 ? "circle" : "CCIPAT_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(factory(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(factory(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(factory(NULL, &error) != 0 && error && !strcmp(error, version == 1 ? "invalid Circle v1 detector output" : "invalid Circle v2 detector output"));
    free(error); CHECK(factory(NULL, NULL) != 0);
    return detector;
}

static void check_result(const br_result *result, int version, const char *token, bool verified, const char *error)
{
    CHECK(result->detector_type == 4 && !result->detector_name);
    CHECK(result->raw.len == strlen(token) && !memcmp(result->raw.data, token, strlen(token)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == (int)strlen(token) && !strcmp(json_object_get_string(part), token));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "Version", &part));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), version == 1 ? "1" : "2"));
    CHECK(!json_object_object_get_ex(result->extra_data, "version", &part));
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
}

static void input_for(char *out, size_t cap, int version, const char *token)
{
    int n = snprintf(out, cap, "%s%s", version == 1 ? "circle " : "", token);
    CHECK(n > 0 && (size_t)n < cap);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, len); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], detector->version, expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *v1, const br_detector *v2)
{
    char input[256], changed[71];
    const struct { const char *format; bool matches; } cases[] = {
        {"circle '%s'", true}, {"CIRCLE=%s", true}, {"preCiRcLesuffix %s", true},
        {"circleci %s", true}, {"circle%s", true}, {"circleG%sZ", true},
        {"circle_%s_", true}, {"circle %sabcdef012345", true}, {"circle\r\n%s", true},
        {"%s", false}, {"%s circle", false}, {"circle %.39s", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, v1_token);
        extraction_case(v1, input, strlen(input), cases[i].matches ? v1_token : NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "circle", 6); memset(input + 6, ':', gap); memcpy(input + 6 + gap, v1_token, sizeof(v1_token));
        extraction_case(v1, input, strlen(input), gap == 40 ? v1_token : NULL);
    }
    memcpy(changed, v1_token, sizeof(v1_token)); changed[20] = 'G';
    snprintf(input, sizeof(input), "circle %s", changed); extraction_case(v1, input, strlen(input), NULL);
    memset(changed, '0', 40); changed[40] = '\0'; input_for(input, sizeof(input), 1, changed);
    extraction_case(v1, input, strlen(input), changed); /* No entropy filtering. */
    memcpy(input, "circle", 6); input[6] = '\0'; memcpy(input + 7, v1_token, 40);
    extraction_case(v1, input, 47, v1_token);
    extraction_case(v2, v2_token, strlen(v2_token), v2_token); /* DIRECT, no provider prefix. */
    snprintf(input, sizeof(input), "X%sY", v2_token); extraction_case(v2, input, strlen(input), v2_token);
    snprintf(input, sizeof(input), "%sABCDEF", v2_token); extraction_case(v2, input, strlen(input), v2_token);
    snprintf(input, sizeof(input), "%s%s", v2_token, v2_token); extraction_case(v2, input, strlen(input), v2_token); /* Unique identical adjacent matches. */
    memcpy(changed, v2_token, sizeof(v2_token)); changed[0] = 'c'; extraction_case(v2, changed, strlen(changed), NULL);
    memcpy(changed, v2_token, sizeof(v2_token)); changed[10] = '-'; extraction_case(v2, changed, strlen(changed), NULL);
    memcpy(changed, v2_token, sizeof(v2_token)); changed[40] = 'G'; extraction_case(v2, changed, strlen(changed), NULL);
    memcpy(changed, v2_token, sizeof(v2_token)); changed[69] = '\0'; extraction_case(v2, changed, strlen(changed), NULL);
    extraction_case(v1, NULL, 0, NULL); extraction_case(v2, NULL, 0, NULL);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count && http->releases + 1 == http->calls);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://circleci.com/api/v2/me"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 4);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    size_t accept = 0, token = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Accept")) { ++accept; CHECK(!strcmp(header->value, "application/json;")); }
        else if (!strcmp(header->name, "Circle-Token")) { ++token; CHECK(!strcmp(header->value, expected->tokens[http->calls - 1])); }
        else if (!strcmp(header->name, "User-Agent")) { ++agent; CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog circle-test" : "TruffleHog")); }
        else CHECK(!"unexpected Circle header (no Authorization, Content-Type or logical Content-Length)");
    }
    CHECK(accept == 1 && token == 1 && agent == 1);
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *token, bool verified, const char *error)
{
    char input[96]; input_for(input, sizeof(input), detector->version, token);
    br_results results = test_scan(detector, ctx, verify, input, strlen(input)); CHECK(results.len == 1);
    check_result(&results.items[0], detector->version, token, verified, error); br_results_clear(&results);
}

static void unique_case_sensitive_keys(const br_detector *detector, const char *token, const char *other)
{
    char first[96], second[96], input[320]; input_for(first, sizeof(first), detector->version, token); input_for(second, sizeof(second), detector->version, other);
    snprintf(input, sizeof(input), "%s\n%s\n%s", first, second, first);
    const char *tokens[] = {token, other}; expected_requests expected = {.tokens = tokens, .count = 2};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {.response = {.status = 200, .body_error = "ignored read/drain/close error"}, .send_rc = mode == 2 ? 1 : 0,
                          .send_error = mode == 2 ? "lookup synthetic.invalid: no such host" : NULL, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, mode != 0, input, strlen(input));
        CHECK(results.len == 2 && http.calls == (mode ? 2u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 2; ++i) check_result(&results.items[i], detector->version, tokens[i], mode == 1, mode == 2 ? "lookup synthetic.invalid: no such host" : NULL);
        br_results_clear(&results);
    }
}

static void status_and_redaction(const br_detector *detector, const char *token, const char *other)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {201, false, "unexpected status code: 201"},
        {204, false, "unexpected status code: 204"}, {299, false, "unexpected status code: 299"},
        {403, false, "unexpected status code: 403"}, {503, false, status_503},
    };
    const char *tokens[] = {token}; expected_requests expected = {.tokens = tokens, .count = 1};
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body)}, .body_error = "ignored body/read/drain/close error"}, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "circle-test"};
        expect_one(detector, &ctx, true, token, statuses[i].verified, statuses[i].error); CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, token, false, NULL); CHECK(http.calls == 1 && http.releases == 1);
    }
    char cause[512], redacted[256]; const char *partial = token + (detector->version == 1 ? 10 : 30);
    snprintf(cause, sizeof(cause), "token=%s repeat=%s; keep=%s partial=%s", token, token, other, partial);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] repeat=[REDACTED]; keep=%s partial=%s", other, partial);
    const struct { const char *cause, *error; } failures[] = {
        {cause, redacted}, {"lookup synthetic.invalid: no such host", "lookup synthetic.invalid: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        test_http http = {.response = {.status = 200, .body = {body, sizeof(body)}, .body_error = "must not replace transport error"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, token, false, failures[i].error); CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static void context_and_metadata(const br_detector *detector, const char *token)
{
    const char *tokens[] = {token}; expected_requests expected = {.tokens = tokens, .count = 1, .timeout_limit = 2000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http);
    struct timespec now; CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_one(detector, &ctx, true, token, true, NULL); CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 1;
    expect_one(detector, &ctx, true, token, false, "context deadline exceeded"); CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 0; ctx.cancelled = cancelled;
    expect_one(detector, &ctx, true, token, false, "context canceled"); CHECK(!http.calls && http.releases == 1);
    expect_one(detector, &ctx, false, token, false, NULL); CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL; expected.timeout_limit = 0; http.calls = http.releases = 0;
    expect_one(detector, &ctx, true, token, true, NULL); CHECK(http.calls == 1 && http.releases == 1);
    expect_one(detector, NULL, true, token, false, "net/http: nil Context"); expect_one(detector, NULL, false, token, false, NULL);
    br_scan_ctx missing_transport = {0}; expect_one(detector, &missing_transport, true, token, false, "HTTP transport not installed");
}

static void resource_rollback(const br_detector *detector, const char *token, const char *other)
{
    char first[96], second[96], input[256]; input_for(first, sizeof(first), detector->version, token); input_for(second, sizeof(second), detector->version, other);
    snprintf(input, sizeof(input), "%s\n%s", first, second);
    const char *tokens[] = {token, other}; const int statuses[] = {200, 503};
    expected_requests expected = {.tokens = tokens, .count = 2, .statuses = statuses};
    for (int metadata_failure = 0; metadata_failure < 2; ++metadata_failure) {
        test_http http = {.inspect = inspect_request, .user = &expected}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
        br_result sentinel = {.detector_type = 12345, .verified = true};
        sentinel.raw.data = malloc(4); CHECK(sentinel.raw.data); memcpy(sentinel.raw.data, "keep", 4); sentinel.raw.len = 4;
        sentinel.verification_error = strdup("caller-owned"); CHECK(sentinel.verification_error);
        unsigned char *original_raw = sentinel.raw.data; char *original_error = sentinel.verification_error;
        br_results results = {0}; CHECK(br_results_push(&results, &sentinel) == 0); char *error = NULL;
        if (metadata_failure) fail_version_after = 2; else fail_status_copy = true;
        int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && error && !strcmp(error, metadata_failure ? "cannot allocate Circle metadata" : "cannot store Circle verification error"));
        CHECK(!fail_version_after && !fail_status_copy && http.calls == (metadata_failure ? 1u : 2u) && http.releases == http.calls && results.len == 1);
        CHECK(results.items[0].detector_type == 12345 && results.items[0].verified && results.items[0].raw.len == 4);
        CHECK(results.items[0].raw.data == original_raw && !memcmp(original_raw, "keep", 4));
        CHECK(results.items[0].verification_error == original_error && !strcmp(original_error, "caller-owned")); free(error); br_results_clear(&results);
        http.calls = http.releases = 0; results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
        check_result(&results.items[0], detector->version, token, true, NULL);
        check_result(&results.items[1], detector->version, other, false, status_503); br_results_clear(&results);
    }
}

int main(void)
{
    const char alphabet[] = "aB12Cd34Ef56A789";
    for (size_t i = 0; i < 40; ++i) v1_token[i] = alphabet[i % (sizeof(alphabet) - 1)];
    v1_token[40] = '\0'; memcpy(v1_other, v1_token, sizeof(v1_token)); v1_other[0] = 'A'; /* Byte-distinct case variant. */
    char segment[23]; test_secret(segment, 22, 0); segment[2] = 'Q';
    snprintf(v2_token, sizeof(v2_token), "CCIPAT_%s_%s", segment, v1_token);
    snprintf(v2_other, sizeof(v2_other), "CCIPAT_%s_%s", segment, v1_other);
    CHECK(strlen(v1_token) == 40 && strlen(v2_token) == 70);
    const br_detector *v1 = descriptor(1), *v2 = descriptor(2); CHECK(v1 != v2 && v1->state != v2->state && v1->scan == v2->scan);
    extraction(v1, v2);
    unique_case_sensitive_keys(v1, v1_token, v1_other); unique_case_sensitive_keys(v2, v2_token, v2_other);
    status_and_redaction(v1, v1_token, v1_other); status_and_redaction(v2, v2_token, v2_other);
    context_and_metadata(v1, v1_token); context_and_metadata(v2, v2_token);
    resource_rollback(v1, v1_token, v1_other); resource_rollback(v2, v2_token, v2_other);
    return test_finish("Circle v1/v2 boundary-free unique keys + Version metadata + shared verification");
}
