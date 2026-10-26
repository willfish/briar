/* SPDX-License-Identifier: AGPL-3.0-only */
/* Subject authentication can issue tokens. Every HTTP request here is fake. */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <time.h>

#define SLICE(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static char id0[33], id1[33], secret0[33], secret1[33], secret2[33];
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

typedef struct { char data[8192]; size_t len; } fixture;
typedef struct {
    const char *id, *secret, *subject;
    bool verified;
    const char *error;
} expected_result;
typedef struct {
    const char *id, *secret, *subject_type, *subject;
    int status, send_rc;
    br_slice body;
    const char *body_error, *send_error;
    bool cancel_after;
} reply;
typedef struct {
    const reply *steps;
    size_t count, cancel_calls;
    uint32_t timeout_limit;
    bool cancel;
} script;

/* More than 40 gap runes isolate fields. Without this, source PrefixRegex(id)
 * can legitimately discover another field's 32-byte value across short lines. */
static void field(fixture *input, const char *name, const char *value)
{
    int n = snprintf(input->data + input->len, sizeof(input->data) - input->len, "%s %s\n", name, value);
    CHECK(n > 0 && (size_t)n + 65 < sizeof(input->data) - input->len);
    input->len += (size_t)n;
    memset(input->data + input->len, '.', 64);
    input->len += 64;
    input->data[input->len++] = '\n';
    input->data[input->len] = '\0';
}

static fixture pair_input(void)
{
    fixture input = {0};
    field(&input, "id", id0);
    field(&input, "secret", secret0);
    return input;
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_boxoauth_init(&detector, &error) == 0 && !error && detector);
    CHECK(detector->type == 1003 && detector->version == 0);
    CHECK(!strcmp(detector->name, "BoxOauth") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "Box is a service offering various service for secure collaboration, content management, "
        "and workflow. Box Oauth credentials can be used to access and interact with this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "box"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    const void *patterns = detector->state;
    CHECK(br_boxoauth_init(&again, &error) == 0 && !error && again == detector && again->state == patterns);
    CHECK(br_boxoauth_init(&again, NULL) == 0 && again == detector && again->state == patterns);
    CHECK(br_boxoauth_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_boxoauth_init(NULL, NULL) != 0);
    return detector;
}

static void check_text(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK(json_object_get_string_len(value) == (int)strlen(expected));
    CHECK(!memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_result *result, const expected_result *expected)
{
    CHECK(result->detector_type == 1003 && !result->detector_name);
    CHECK(result->raw.len == 32 && !memcmp(result->raw.data, expected->id, 32));
    CHECK(result->raw_v2.len == 64 && !memcmp(result->raw_v2.data, expected->id, 32));
    CHECK(!memcmp(result->raw_v2.data + 32, expected->secret, 32));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == (expected->subject ? 3 : 2));
    check_text(result->secret_parts, "client_id", expected->id);
    check_text(result->secret_parts, "client_secret", expected->secret);
    if (expected->subject) check_text(result->secret_parts, "subject_id", expected->subject);
    else {
        br_json *missing = NULL;
        CHECK(!json_object_object_get_ex(result->secret_parts, "subject_id", &missing));
    }
    CHECK(result->verified == expected->verified);
    if (expected->error) CHECK(result->verification_error && !strcmp(result->verification_error, expected->error));
    else CHECK(!result->verification_error);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_results(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           const fixture *input, const expected_result *expected, size_t count)
{
    br_results results = test_scan(detector, ctx, verify, input->data, input->len);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&results.items[i], &expected[i]);
    br_results_clear(&results);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(http->calls > 0 && http->calls <= steps->count);
    CHECK(http->releases + 1 == http->calls); /* Base and previous probe already released. */
    const reply *step = &steps->steps[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.box.com/oauth2/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1003);
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= (steps->timeout_limit ? steps->timeout_limit : 5000));
    if (!steps->timeout_limit) CHECK(request->timeout_ms == 5000);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    char expected_body[256];
    int n = snprintf(expected_body, sizeof(expected_body), "grant_type=client_credentials&client_id=%s&client_secret=%s", step->id, step->secret);
    CHECK(n > 0 && (size_t)n < sizeof(expected_body));
    if (step->subject) {
        int tail = snprintf(expected_body + n, sizeof(expected_body) - (size_t)n,
            "&box_subject_type=%s&box_subject_id=%s", step->subject_type, step->subject);
        CHECK(tail > 0 && (size_t)tail < sizeof(expected_body) - (size_t)n);
        n += tail;
    } else CHECK(!step->subject_type);
    CHECK(request->body.data && request->body.len == (size_t)n && !memcmp(request->body.data, expected_body, (size_t)n));
    CHECK(request->nheaders == 2);
    size_t form = 0, agent = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        const br_header *header = &request->headers[i];
        if (!strcmp(header->name, step->subject ? "Content-Type" : "content-type")) {
            ++form;
            CHECK(!strcmp(header->value, "application/x-www-form-urlencoded"));
        } else if (!strcmp(header->name, "User-Agent")) {
            ++agent;
            CHECK(!strcmp(header->value, ctx->user_agent ? "TruffleHog boxoauth-test" : "TruffleHog"));
        } else CHECK(!"unexpected BoxOauth header (no explicit length, Accept or Authorization)");
    }
    CHECK(form == 1 && agent == 1);
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->body_error};
    http->send_rc = step->send_rc;
    http->send_error = step->send_error;
    if (step->cancel_after) steps->cancel = true;
}

static bool cancelled(void *user)
{
    script *steps = user;
    ++steps->cancel_calls;
    return steps->cancel;
}

static void run_script(const br_detector *detector, const fixture *input, const reply *replies, size_t calls,
                        const expected_result *expected, size_t count)
{
    script steps = {.steps = replies, .count = calls};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = &steps};
    expect_results(detector, &ctx, true, input, expected, count);
    CHECK(http.calls == calls && http.releases == calls);
}

static void test_extraction_and_products(const br_detector *detector)
{
    fixture input = pair_input();
    expected_result one = {.id = id0, .secret = secret0};
    /* Native FromData needs id/secret prefixes, not its dispatch keyword box. */
    expect_results(detector, NULL, false, &input, &one, 1);
    input = (fixture){0}; field(&input, "box", id0); field(&input, "secret", secret0);
    expect_results(detector, NULL, false, &input, NULL, 0);
    input = (fixture){0}; field(&input, "id", id0); field(&input, "box", secret0);
    expect_results(detector, NULL, false, &input, NULL, 0);
    input = (fixture){0}; field(&input, "CLIENT_ID", id0); field(&input, "CLIENT_SECRET", secret0);
    expect_results(detector, NULL, false, &input, &one, 1);
    char changed[34];
    for (size_t which = 0; which < 2; ++which) {
        const char *value = which ? secret0 : id0;
        memcpy(changed, value, 33); changed[31] = '\0';
        input = (fixture){0}; field(&input, "id", which ? id0 : changed); field(&input, "secret", which ? changed : secret0);
        expect_results(detector, NULL, false, &input, NULL, 0);
        snprintf(changed, sizeof(changed), "%sQ", value);
        input = (fixture){0}; field(&input, "id", which ? id0 : changed); field(&input, "secret", which ? changed : secret0);
        expect_results(detector, NULL, false, &input, NULL, 0);
    }
    input = (fixture){0}; field(&input, "id", id0); field(&input, "secret", id0);
    expect_results(detector, NULL, true, &input, NULL, 0); /* Equal credentials are never emitted or sent. */
    input = (fixture){0}; field(&input, "id", id0); field(&input, "id", id1); field(&input, "id", id0);
    field(&input, "secret", secret0); field(&input, "secret", secret1); field(&input, "secret", secret0);
    field(&input, "enterprise_id", "000123");
    const expected_result products[] = {
        {.id = id0, .secret = secret0}, {.id = id0, .secret = secret1},
        {.id = id1, .secret = secret0}, {.id = id1, .secret = secret1},
    };
    script steps = {0};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    expect_results(detector, &ctx, false, &input, products, 4);
    CHECK(!http.calls && !http.releases); /* NoV never probes or adds subject metadata. */
    input = (fixture){0}; field(&input, "id", id0); field(&input, "id", id1);
    field(&input, "secret", id0); field(&input, "secret", secret0);
    const expected_result unequal[] = {
        {.id = id0, .secret = secret0}, {.id = id1, .secret = id0}, {.id = id1, .secret = secret0},
    };
    expect_results(detector, NULL, false, &input, unequal, 3);
}

static void test_base_status_and_marker_priority(const br_detector *detector)
{
    fixture input = pair_input();
    const struct { int status; br_slice body; bool verified; const char *error; } cases[] = {
        {400, SLICE("unauthorized_client"), true, NULL},
        {400, SLICE("invalid_client"), false, NULL},
        {400, SLICE("invalid_client before unauthorized_client"), true, NULL},
        {400, SLICE("\xff\0unauthorized_client invalid_client"), true, NULL},
        {400, SLICE("\xff\0invalid_client"), false, NULL},
        {400, SLICE("UNAUTHORIZED_CLIENT"), false, "response body missing expected keyword"},
        {400, {NULL, 0}, false, "response body missing expected keyword"},
        {200, SLICE("unauthorized_client"), false, "unexpected HTTP response status 200"},
        {401, SLICE("invalid_client"), false, "unexpected HTTP response status 401"},
        {403, SLICE("unauthorized_client"), false, "unexpected HTTP response status 403"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reply step = {.id = id0, .secret = secret0, .status = cases[i].status, .body = cases[i].body,
                      .body_error = cases[i].status == 400 ? NULL : "ignored outside 400"};
        expected_result expected = {.id = id0, .secret = secret0, .verified = cases[i].verified, .error = cases[i].error};
        run_script(detector, &input, &step, 1, &expected, 1);
    }
    char cause[192], redacted[192];
    snprintf(cause, sizeof(cause), "id=%s secret=%s repeat=%s", id0, secret0, id0);
    snprintf(redacted, sizeof(redacted), "id=[REDACTED] secret=%s repeat=[REDACTED]", secret0);
    reply step = {.id = id0, .secret = secret0, .status = 400, .body = SLICE("\0unauthorized_client invalid_client"), .body_error = cause};
    expected_result expected = {.id = id0, .secret = secret0, .error = redacted};
    run_script(detector, &input, &step, 1, &expected, 1); /* ReadAll error preempts even complete markers. */
    step.body_error = NULL; step.send_rc = 1; step.send_error = cause;
    run_script(detector, &input, &step, 1, &expected, 1); /* Secret stays unredacted; only ID is passed. */
    step.send_rc = -1; step.send_error = NULL; expected.error = "HTTP transport failed";
    run_script(detector, &input, &step, 1, &expected, 1);
    step.send_rc = 1; step.send_error = "unsupported: redirects for native HTTP POST"; expected.error = step.send_error;
    run_script(detector, &input, &step, 1, &expected, 1); /* No profile fallback. */
}

static void add_unsorted_subjects(fixture *input)
{
    field(input, "user", "999999");
    field(input, "enterprise_id", "1000000");
    field(input, "BOX_SUBJECT", "000123");
    field(input, "subject", "000123");
}

static void test_sorted_subjects_and_fallback(const br_detector *detector)
{
    fixture input = pair_input(); add_unsorted_subjects(&input);
    const reply replies[] = {
        {.id = id0, .secret = secret0, .status = 400, .body = SLICE("unauthorized_client")},
        {.id = id0, .secret = secret0, .subject_type = "enterprise", .subject = "000123", .status = 400},
        {.id = id0, .secret = secret0, .subject_type = "user", .subject = "000123", .status = 401},
        {.id = id0, .secret = secret0, .subject_type = "enterprise", .subject = "1000000", .status = 200,
         .send_rc = 1, .send_error = "suppressed synthetic probe error"},
        {.id = id0, .secret = secret0, .subject_type = "user", .subject = "1000000", .status = 200,
         .body = SLICE("\xff\0ignored token data"), .body_error = "ignored probe read error"},
    };
    expected_result expected = {.id = id0, .secret = secret0, .subject = "1000000", .verified = true};
    run_script(detector, &input, replies, 5, &expected, 1); /* No 999999 probes after user succeeds. */
    const reply leading_zero[] = {
        replies[0], {.id = id0, .secret = secret0, .subject_type = "enterprise", .subject = "000123", .status = 200},
    };
    expected.subject = "000123";
    run_script(detector, &input, leading_zero, 2, &expected, 1); /* Preserve zeros; skip user and later subjects. */
    input = pair_input();
    field(&input, "enterprise", "12345"); /* Too short. */
    field(&input, "subject", "123456789012345678901"); /* Too long. */
    field(&input, "user_id", "_123456"); /* Word boundary fails. */
    field(&input, "ENTERPRISE_ID", "00000000000000000001"); /* Exactly 20 bytes. */
    field(&input, "user", "123456");
    const reply bounded[] = {
        replies[0], {.id = id0, .secret = secret0, .subject_type = "enterprise", .subject = "00000000000000000001", .status = 200},
    };
    expected.subject = "00000000000000000001";
    run_script(detector, &input, bounded, 2, &expected, 1);
}

static void test_all_probes_fail_but_base_stays_verified(const br_detector *detector)
{
    fixture input = pair_input(); field(&input, "secret", secret1); add_unsorted_subjects(&input);
    const reply replies[] = {
        {.id = id0, .secret = secret0, .status = 400, .body = SLICE("unauthorized_client")},
        {.id = id0, .secret = secret0, .subject_type = "enterprise", .subject = "000123", .status = 200,
         .send_rc = -1, .send_error = "unsupported: redirects for native HTTP POST"},
        {.id = id0, .secret = secret0, .subject_type = "user", .subject = "000123", .status = 401},
        {.id = id0, .secret = secret0, .subject_type = "enterprise", .subject = "1000000", .status = 200, .send_rc = 1},
        {.id = id0, .secret = secret0, .subject_type = "user", .subject = "1000000", .status = 400, .body_error = "ignored"},
        {.id = id0, .secret = secret0, .subject_type = "enterprise", .subject = "999999", .status = 503},
        {.id = id0, .secret = secret0, .subject_type = "user", .subject = "999999", .status = 201},
    };
    const expected_result expected = {.id = id0, .secret = secret0, .verified = true};
    run_script(detector, &input, replies, 7, &expected, 1); /* Still break secrets; never send secret1. */
}

static void test_inner_break_and_secret_reuse(const br_detector *detector)
{
    fixture input = {0};
    field(&input, "id", id0); field(&input, "id", id1);
    field(&input, "secret", secret0); field(&input, "secret", secret1); field(&input, "secret", secret2);
    const reply replies[] = {
        {.id = id0, .secret = secret0, .status = 400, .body = SLICE("invalid_client")},
        {.id = id0, .secret = secret1, .status = 400, .body = SLICE("unauthorized_client")},
        {.id = id1, .secret = secret0, .status = 400, .body = SLICE("invalid_client")},
        {.id = id1, .secret = secret1, .status = 400, .body = SLICE("unauthorized_client")},
    };
    const expected_result expected[] = {
        {.id = id0, .secret = secret0}, {.id = id0, .secret = secret1, .verified = true},
        {.id = id1, .secret = secret0}, {.id = id1, .secret = secret1, .verified = true},
    };
    run_script(detector, &input, replies, 4, expected, 4); /* secret1 reused across IDs; secret2 never attempted. */
}

static void test_context_and_creation(const br_detector *detector)
{
    fixture input = pair_input();
    reply step = {.id = id0, .secret = secret0, .status = 400, .body = SLICE("unauthorized_client")};
    script steps = {.steps = &step, .count = 1, .timeout_limit = 2000};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = test_transport(&http);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    int64_t deadline = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 + steps.timeout_limit;
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = &steps, .deadline_monotonic_ms = deadline};
    expected_result expected = {.id = id0, .secret = secret0, .verified = true};
    expect_results(detector, &ctx, true, &input, &expected, 1);
    CHECK(http.calls == 1 && http.releases == 1 && ctx.deadline_monotonic_ms == deadline);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 1;
    expected.verified = false; expected.error = "context deadline exceeded";
    expect_results(detector, &ctx, true, &input, &expected, 1);
    CHECK(!http.calls && http.releases == 1);
    http.calls = http.releases = 0;
    ctx.deadline_monotonic_ms = 0; steps.cancel = true;
    expected.error = "context canceled";
    expect_results(detector, &ctx, true, &input, &expected, 1);
    CHECK(!http.calls && http.releases == 1);
    size_t before = steps.cancel_calls;
    expected.error = NULL;
    expect_results(detector, &ctx, false, &input, &expected, 1);
    CHECK(!http.calls && http.releases == 1 && steps.cancel_calls == before);
    expected.error = "net/http: nil Context";
    expect_results(detector, NULL, true, &input, &expected, 1);
    steps.cancel = false; steps.timeout_limit = 0;
    http.calls = http.releases = 0;
    expected.verified = true; expected.error = NULL;
    expect_results(detector, &ctx, true, &input, &expected, 1);
    CHECK(http.calls == 1 && http.releases == 1);
    /* Cancellation becomes active only AFTER a valid base response. Probe Do
     * errors remain suppressed, all enterprise/user attempts still occur. */
    field(&input, "subject", "999999"); field(&input, "enterprise", "000123");
    step.cancel_after = true;
    http.calls = http.releases = 0;
    expect_results(detector, &ctx, true, &input, &expected, 1);
    CHECK(http.calls == 1 && http.releases == 5); /* Base + four rejected probe sends, no subject metadata. */
}

static void test_positive_setter_failure_and_rollback(const br_detector *detector)
{
    fixture input = {0}; field(&input, "id", id0); field(&input, "id", id1); field(&input, "secret", secret0);
    const reply replies[] = {
        {.id = id0, .secret = secret0, .status = 400, .body = SLICE("unauthorized_client")},
        {.id = id1, .secret = secret0, .status = 503},
    };
    script steps = {.steps = replies, .count = 2};
    test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input.data, input.len}, &results, &error);
    CHECK(!fail_status_copy && rc != 0 && error && !strcmp(error, "cannot store BoxOauth verification error"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777);
    free(error); br_results_clear(&results);
    const expected_result expected[] = {
        {.id = id0, .secret = secret0, .verified = true}, {.id = id1, .secret = secret0, .error = status_503},
    };
    run_script(detector, &input, replies, 2, expected, 2);
}

int main(void)
{
    test_secret(id0, 32, 0); test_secret(id1, 32, 7);
    test_secret(secret0, 32, 13); test_secret(secret1, 32, 19); test_secret(secret2, 32, 23);
    id0[0] = 'A'; id1[0] = 'B'; secret0[0] = 'C'; secret1[0] = 'D'; secret2[0] = 'E';
    const br_detector *detector = test_descriptor();
    test_extraction_and_products(detector);
    test_base_status_and_marker_priority(detector);
    test_sorted_subjects_and_fallback(detector);
    test_all_probes_fail_but_base_stays_verified(detector);
    test_inner_break_and_secret_reuse(detector);
    test_context_and_creation(detector);
    test_positive_setter_failure_and_rollback(detector);
    return test_finish("BoxOauth unique pairs + sorted subject probes + response ownership");
}
