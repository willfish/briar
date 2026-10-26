/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

static char v1_token[41], v1_other[41], v2_token[45], v2_other[45];
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

char *strdup(const char *value)
{
    if (fail_status_copy && !strcmp(value, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(value) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, value, len);
    return copy;
}

typedef struct {
    const char *const *tokens;
    size_t count;
    uint32_t timeout_limit;
    const int *statuses;
} expected_requests;

static const br_detector *init(int version)
{
    int (*factory)(const br_detector **, char **) = version == 1 ? br_brandfetch_v1_init : br_brandfetch_v2_init;
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(factory(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 333 && detector->version == version && !strcmp(detector->name, "Brandfetch"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Brandfetch is a service that provides brand data, including logos, colors, fonts, "
        "and more. Brandfetch API keys can be used to access this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "brandfetch"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *pattern = detector->state;
    CHECK(factory(&again, &error) == 0 && !error && again == detector && again->state == pattern);
    CHECK(factory(&again, NULL) == 0 && again == detector && again->state == pattern);
    CHECK(factory(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, version == 1 ? "invalid Brandfetch v1 detector output" : "invalid Brandfetch v2 detector output"));
    free(error);
    CHECK(factory(NULL, NULL) != 0);
    return detector;
}

static void check_result(const br_result *result, const char *token, int version, bool verified, const char *error)
{
    CHECK(result->detector_type == 333 && !result->detector_name);
    CHECK(result->raw.len == strlen(token) && !memcmp(result->raw.data, token, strlen(token)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == (int)strlen(token) && !memcmp(json_object_get_string(part), token, strlen(token)));
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
    CHECK(json_object_object_get_ex(result->extra_data, "version", &part));
    CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == 1);
    CHECK(!strcmp(json_object_get_string(part), version == 1 ? "1" : "2"));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, detector->version, false, NULL);
    br_results_clear(&results);
}

static void test_v1_extraction(const br_detector *v1)
{
    char input[256], changed[41];
    const struct { const char *format; bool matches; } cases[] = {
        {"brandfetch = '%s'", true}, {"BRANDFETCH: %s", true}, {"preBrAnDfEtChsuffix=%s", true},
        {"%s", false}, {"%s brandfetch", false}, {"brandfetch%s", false},
        {"brandfetch _%s", false}, {"brandfetch %s_", false}, {"brandfetch %sQ", false},
        {"brandfetch %.39s", false}, {"brandfetch\r\n%s", true}, {"brandfetch %s=", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, v1_token);
        extraction_case(v1, input, cases[i].matches ? v1_token : NULL);
    }
    memcpy(changed, v1_token, sizeof(v1_token)); changed[10] = '-';
    snprintf(input, sizeof(input), "brandfetch %s", changed); extraction_case(v1, input, NULL);
    memset(changed, 'a', 40); changed[40] = '\0';
    snprintf(input, sizeof(input), "brandfetch %s", changed); extraction_case(v1, input, changed);
}

static void test_v2_extraction(const br_detector *v2)
{
    char input[256], changed[45];
    snprintf(input, sizeof(input), "brandfetch %s", v2_token); extraction_case(v2, input, v2_token);
    snprintf(input, sizeof(input), "BrAnDfEtCh%s", v2_token); extraction_case(v2, input, v2_token); /* No leading boundary. */
    snprintf(input, sizeof(input), "brandfetch X%sword", v2_token); extraction_case(v2, input, v2_token); /* No trailing boundary. */
    snprintf(input, sizeof(input), "brandfetch %s=", v2_token); extraction_case(v2, input, v2_token); /* No padding validation. */
    snprintf(input, sizeof(input), "brandfetch Q%s", v2_token); extraction_case(v2, input, v2_token); /* Prefix gap consumes extra class byte. */
    extraction_case(v2, v2_token, NULL);
    snprintf(input, sizeof(input), "brandfetch %.43s", v2_token); extraction_case(v2, input, NULL); /* Final literal '=' is mandatory. */
    snprintf(input, sizeof(input), "brandfetch %.42s=", v2_token); extraction_case(v2, input, NULL);
    memcpy(changed, v2_token, sizeof(v2_token)); changed[20] = '?';
    snprintf(input, sizeof(input), "brandfetch %s", changed); extraction_case(v2, input, NULL);
    memset(changed, '=', 44); changed[44] = '\0';
    snprintf(input, sizeof(input), "brandfetch %s", changed); extraction_case(v2, input, changed); /* No entropy/JWT/Base64 check. */
}

static void test_prefix_range(const br_detector *detector, const char *token)
{
    const char prefix[] = "brandfetch";
    char input[160];
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, prefix, sizeof(prefix) - 1);
        memset(input + sizeof(prefix) - 1, ' ', gap);
        memcpy(input + sizeof(prefix) - 1 + gap, token, strlen(token) + 1);
        extraction_case(detector, input, gap == 40 ? token : NULL);
    }
    memcpy(input, prefix, sizeof(prefix));
    memcpy(input + sizeof(prefix), token, strlen(token));
    br_results results = test_scan(detector, NULL, false, input, sizeof(prefix) + strlen(token));
    CHECK(results.len == 1); check_result(&results.items[0], token, detector->version, false, NULL);
    br_results_clear(&results);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls > 0 && http->calls <= expected->count && http->releases + 1 == http->calls);
    const char *token = expected->tokens[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.brandfetch.io/v2/brands/google.com"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 333);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (expected->timeout_limit ? expected->timeout_limit : 5000));
    if (!expected->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    size_t json = 0, auth = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, "Content-Type")) {
            ++json; CHECK(!strcmp(header->value, "application/json"));
        } else if (!strcmp(header->name, "Authorization")) {
            ++auth; CHECK(!strncmp(header->value, "Bearer ", 7) && !strcmp(header->value + 7, token));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent; CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog brandfetch-test" : "TruffleHog"));
        } else CHECK(!"unexpected Brandfetch header (no Accept or Content-Length)");
    }
    CHECK(json == 1 && auth == 1 && agent == 1);
    if (expected->statuses) http->response.status = expected->statuses[http->calls - 1];
}

static void expect_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       const char *token, bool verified, const char *error)
{
    char input[80];
    snprintf(input, sizeof(input), "brandfetch %s", token);
    br_results results = test_scan(detector, ctx, verify, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], token, detector->version, verified, error);
    br_results_clear(&results);
}

static void test_unique_and_nov(const br_detector *detector, const char *token, const char *other)
{
    char input[256], variant[45];
    memcpy(variant, token, strlen(token) + 1);
    variant[detector->version == 1 ? 0 : 42] = detector->version == 1 ? 'a' : 'z';
    snprintf(input, sizeof(input), "brandfetch %s\nbrandfetch %s\nbrandfetch %s\nbrandfetch %s", token, other, token, variant);
    const char *tokens[] = {token, other, variant};
    expected_requests expected = {.tokens = tokens, .count = 3};
    test_http http = {.response = {.status = 200, .body_error = "ignored close-only body error"}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 3 && !http.calls && !http.releases);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], detector->version, false, NULL);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i], detector->version, true, NULL);
    br_results_clear(&results); /* No success break and no version-map replacement. */
}

static void test_status_and_error_metadata(const br_detector *detector, const char *token, const char *other)
{
    const struct { int status; bool verified; const char *error; } statuses[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL},
        {201, false, "unexpected status code: 201"}, {204, false, "unexpected status code: 204"}, {503, false, status_503},
    };
    static const unsigned char body[] = "\xff\0not JSON";
    const char *tokens[] = {token};
    expected_requests expected = {.tokens = tokens, .count = 1};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i].status, .body = {body, sizeof(body) - 1}, .body_error = "ignored body/close error"},
                          .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "brandfetch-test"};
        expect_one(detector, &ctx, true, token, statuses[i].verified, statuses[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
        expect_one(detector, &ctx, false, token, false, NULL);
        CHECK(http.calls == 1 && http.releases == 1);
    }
    char sensitive[224], redacted[160];
    snprintf(sensitive, sizeof(sensitive), "token=%s repeats %s; keep %s", token, token, other);
    snprintf(redacted, sizeof(redacted), "token=[REDACTED] repeats [REDACTED]; keep %s", other);
    const struct { const char *cause, *error; } failures[] = {
        {sensitive, redacted}, {"lookup synthetic: no such host", "lookup synthetic: no such host"},
        {"context canceled", "context canceled"}, {"context deadline exceeded", "context deadline exceeded"},
        {"unsupported: synthetic SANE transport", "unsupported: synthetic SANE transport"}, {NULL, "HTTP transport failed"},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        test_http http = {.response = {.status = 200, .body_error = "must not override transport error"},
                          .send_rc = i % 2 ? -1 : 1, .send_error = failures[i].cause, .inspect = inspect_request, .user = &expected};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        expect_one(detector, &ctx, true, token, false, failures[i].error);
        CHECK(http.calls == 1 && http.releases == 1);
    }
}

static bool cancelled(void *user) { (void)user; return true; }

static void test_context(const br_detector *detector, const char *token)
{
    const char *tokens[] = {token};
    expected_requests expected = {.tokens = tokens, .count = 1, .timeout_limit = 2000};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + expected.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = deadline};
    expect_one(detector, &ctx, true, token, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 1;
    expect_one(detector, &ctx, true, token, false, "context deadline exceeded");
    CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0; ctx.deadline_monotonic_ms = 0; ctx.cancelled = cancelled;
    expect_one(detector, &ctx, true, token, false, "context canceled");
    CHECK(!http.calls && http.releases == 1);
    expect_one(detector, &ctx, false, token, false, NULL);
    CHECK(!http.calls && http.releases == 1);
    ctx.cancelled = NULL; http.calls = http.releases = 0; expected.timeout_limit = 0;
    expect_one(detector, &ctx, true, token, true, NULL);
    CHECK(http.calls == 1 && http.releases == 1);
    expect_one(detector, NULL, true, token, false, "net/http: nil Context"); /* Version still present for BOTH versions. */
    expect_one(detector, NULL, false, token, false, NULL);
}

static void test_setter_failure_rollback(const br_detector *detector, const char *token, const char *other)
{
    char input[160];
    snprintf(input, sizeof(input), "brandfetch %s\nbrandfetch %s", token, other);
    const char *tokens[] = {token, other};
    const int statuses[] = {200, 503};
    expected_requests expected = {.tokens = tokens, .count = 2, .statuses = statuses};
    test_http http = {.inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc != 0 && error && !strcmp(error, "cannot store Brandfetch verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error); br_results_clear(&results);
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && http.releases == 2);
    check_result(&results.items[0], token, detector->version, true, NULL);
    check_result(&results.items[1], other, detector->version, false, status_503);
    br_results_clear(&results);
}

int main(void)
{
    test_secret(v1_token, 40, 0); test_secret(v1_other, 40, 13);
    v1_token[0] = 'A'; v1_token[39] = 'Z'; v1_other[0] = 'B';
    test_secret(v2_token, 43, 3); test_secret(v2_other, 43, 17);
    const char punctuation[] = "=+/-_!@#$%^&*()";
    memcpy(v2_token, punctuation, sizeof(punctuation) - 1);
    v2_token[42] = 'Z'; v2_token[43] = '='; v2_token[44] = '\0';
    v2_other[0] = 'Q'; v2_other[21] = '+'; v2_other[42] = 'X'; v2_other[43] = '='; v2_other[44] = '\0';
    const br_detector *v1 = init(1), *v2 = init(2);
    CHECK(v1 != v2 && v1->state != v2->state && v1->scan == v2->scan);
    test_v1_extraction(v1); test_v2_extraction(v2);
    test_prefix_range(v1, v1_token); test_prefix_range(v2, v2_token);
    test_unique_and_nov(v1, v1_token, v1_other); test_unique_and_nov(v2, v2_token, v2_other);
    test_status_and_error_metadata(v1, v1_token, v1_other); test_status_and_error_metadata(v2, v2_token, v2_other);
    test_context(v1, v1_token); test_context(v2, v2_token);
    test_setter_failure_rollback(v1, v1_token, v1_other); test_setter_failure_rollback(v2, v2_token, v2_other);
    return test_finish("Brandfetch v1/v2 explicit metadata + unique captures + shared verification");
}
