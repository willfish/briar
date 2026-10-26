/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

#define SLICE(text) ((br_slice){(const unsigned char *)(text), sizeof(text) - 1})
#define PREFIX "unexpected response body: "
#define UNICODE_BODY "Snowman \xe2\x98\x83 replacement \xef\xbf\xbd globe \xf0\x9f\x8c\x8d controls:\x01\x7f\n\t\r"
static const char key[] = "pri_0123456789abcdef0123456789abcdef";
static const char other[] = "pri_fedcba9876543210fedcba9876543210";
static const char unsupported[] = "unsupported: Besttime non-UTF-8 or NUL response body diagnostic";
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

/* The core setter returns positive 1 here; only this exact copy is injected. */
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_besttime_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Besttime detector output")); free(error); error = NULL;
    CHECK(!br_besttime_init(&detector, &error) && detector && !error);
    CHECK(!br_besttime_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 506 && detector->version == 0 && !strcmp(detector->name, "Besttime"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Besttime is a service used to predict the best time to visit a place. Besttime API keys can be used to access and utilize this service."));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "besttime"));
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (!error) CHECK(!result->verification_error);
    else {
        CHECK(result->verification_error && strlen(result->verification_error) == strlen(error));
        CHECK(!memcmp(result->verification_error, error, strlen(error)));
    }
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) { test_key_result(&results.items[0], 506, expected, "key"); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], value[80];
    snprintf(input, sizeof(input), "besttime %s", key); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "BeStTiMe\r\n(%s)", key); extraction_case(detector, input, key);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "besttime%*s%s", gap, "", key);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    extraction_case(detector, key, NULL); extraction_case(detector, "", NULL);
    memcpy(value, key, sizeof(key)); value[0] = 'P'; snprintf(input, sizeof(input), "besttime %s", value); extraction_case(detector, input, NULL);
    memcpy(value, key, sizeof(key)); value[6] = 'A'; snprintf(input, sizeof(input), "besttime %s", value); extraction_case(detector, input, NULL);
    memcpy(value, key, sizeof(key)); value[6] = 'g'; snprintf(input, sizeof(input), "besttime %s", value); extraction_case(detector, input, NULL);
    memcpy(value, key, sizeof(key)); value[35] = '\0'; snprintf(input, sizeof(input), "besttime %s", value); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "besttime %s0", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "besttime x%s", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "besttime _%s", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "besttime %s_", key); extraction_case(detector, input, NULL);
    memcpy(value, "pri_", 4); memset(value + 4, '0', 32); value[36] = '\0';
    snprintf(input, sizeof(input), "besttime %s", value); extraction_case(detector, input, value); /* No entropy gate. */
    snprintf(input, sizeof(input), "besttime %s\nBESTTIME %s\nbesttime %s", key, key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 3);
    test_key_result(&results.items[0], 506, key, "key"); test_key_result(&results.items[1], 506, key, "key");
    test_key_result(&results.items[2], 506, other, "key"); br_results_clear(&results);
}

typedef struct {
    const char *key, *send_error, *body_error;
    br_slice body;
    int status, send_rc;
} reply;
typedef struct {
    reply replies[3]; size_t count, cancel_calls; bool cancel, expired;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(ctx == steps->expected_ctx && at < steps->count && at < 3 && http->releases == at);
    reply *step = &steps->replies[at];
    char url[128]; snprintf(url, sizeof(url), "https://besttime.app/api/v1/keys/%s", step->key);
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 506 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Authorization") && !header(request, "Accept") && !header(request, "Content-Type") && !header(request, "Content-Length"));
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->body_error};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps,
                       .deadline_monotonic_ms = steps->expired ? 1 : 0};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count);
    CHECK(http.releases == http.calls + (verify && (steps->cancel || steps->expired) ? 1u : 0u));
    return results;
}

static br_results single(const br_detector *detector, reply step)
{
    char input[80]; snprintf(input, sizeof(input), "besttime %s", step.key);
    script steps = {.count = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 1);
    test_key_result(&results.items[0], 506, step.key, "key"); return results;
}

static void markers_and_read_error(const br_detector *detector)
{
    const br_slice bodies[] = {
        SLICE("not JSON: \"status\": \"OK\" trailing"),
        SLICE("\"status\": \"OK\" \"message\": \"Invalid api_key_private"),
        SLICE("\"message\": \"Invalid api_key_private then \"status\": \"OK\""),
        SLICE("\xff\0\"status\": \"OK\""),
        SLICE("\"message\": \"Invalid api_key_private"), /* No closing quote required. */
        SLICE("\xff\0\"message\": \"Invalid api_key_private"),
        SLICE("\xff\"status\": \"OK\""),
        SLICE("\xff\"message\": \"Invalid api_key_private"),
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .status = 200, .body = bodies[i]});
        check_error(&results.items[0], i < 4 || i == 6, NULL); br_results_clear(&results);
    }
    char cause[192], expected[192];
    snprintf(cause, sizeof(cause), "read %s and %s; keep %s", key, key, other);
    snprintf(expected, sizeof(expected), "read [REDACTED] and [REDACTED]; keep %s", other);
    br_results results = single(detector, (reply){.key = key, .status = 200, .body = bodies[3], .body_error = cause});
    check_error(&results.items[0], false, expected); br_results_clear(&results);
}

static void full_diagnostic(const br_detector *detector, br_slice body, const char *expected)
{
    br_results results = single(detector, (reply){.key = key, .status = 200, .body = body});
    check_error(&results.items[0], false, expected); br_results_clear(&results);
}

static void diagnostics(const br_detector *detector)
{
    full_diagnostic(detector, SLICE("ordinary ASCII body"), PREFIX "ordinary ASCII body");
    full_diagnostic(detector, SLICE("{\"status\":\"OK\"}"), PREFIX "{\"status\":\"OK\"}"); /* No JSON parsing/space normalization. */
    full_diagnostic(detector, (br_slice){NULL, 0}, PREFIX); /* NULL/0 must not reach memcpy as a source. */
    full_diagnostic(detector, SLICE(UNICODE_BODY), PREFIX UNICODE_BODY);
    full_diagnostic(detector, SLICE("unknown\0suffix"), unsupported);
    full_diagnostic(detector, SLICE("\xff\nunknown"), unsupported);
    char body[192], expected[192];
    snprintf(body, sizeof(body), "unknown %s and %s; keep %s", key, key, other);
    snprintf(expected, sizeof(expected), PREFIX "unknown [REDACTED] and [REDACTED]; keep %s", other);
    full_diagnostic(detector, (br_slice){(const unsigned char *)body, strlen(body)}, expected);
    /* A full, unbounded supported diagnostic, not a fixed 4K buffer or printf precision. */
    size_t len = 8193; unsigned char *large = malloc(len); char *large_expected = malloc(sizeof(PREFIX) + len);
    CHECK(large && large_expected); memset(large, 'x', len); large[len - 1] = '!';
    memcpy(large_expected, PREFIX, sizeof(PREFIX) - 1); memcpy(large_expected + sizeof(PREFIX) - 1, large, len);
    large_expected[sizeof(PREFIX) - 1 + len] = '\0';
    full_diagnostic(detector, (br_slice){large, len}, large_expected); free(large); free(large_expected);
}

static void other_statuses_and_transport(const br_detector *detector)
{
    const int statuses[] = {201, 400, 401, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .status = statuses[i],
            .body = SLICE("\xff\0\"status\": \"OK\""), .body_error = "must be ignored"});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
        check_error(&results.items[0], false, expected); br_results_clear(&results);
    }
    char cause[256], expected[256];
    snprintf(cause, sizeof(cause), "synthetic https://besttime.app/api/v1/keys/%s: %s; keep %s", key, key, other);
    snprintf(expected, sizeof(expected), "synthetic https://besttime.app/api/v1/keys/[REDACTED]: [REDACTED]; keep %s", other);
    br_results results = single(detector, (reply){.key = key, .status = 200, .send_error = cause,
        .body = SLICE("\"status\": \"OK\""), .body_error = "must not replace transport error"});
    check_error(&results.items[0], false, expected); br_results_clear(&results);
    results = single(detector, (reply){.key = key, .status = 200, .send_rc = -1});
    check_error(&results.items[0], false, "HTTP transport failed"); br_results_clear(&results);
}

static void context_and_continuation(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "besttime %s", key);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline};
        br_results results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls);
        test_key_result(&results.items[0], 506, key, "key"); check_error(&results.items[0], false, NULL); br_results_clear(&results);
        results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        test_key_result(&results.items[0], 506, key, "key");
        check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1);
    test_key_result(&results.items[0], 506, key, "key"); check_error(&results.items[0], false, "net/http: nil Context"); br_results_clear(&results);
    snprintf(input, sizeof(input), "besttime %s\nbesttime %s\nbesttime %s", key, key, other);
    script steps = {.count = 3}; steps.replies[0] = (reply){.key = key, .status = 200, .body = SLICE("unknown\0suffix")};
    steps.replies[1] = (reply){.key = key, .status = 200, .body = SLICE("\"status\": \"OK\"")};
    steps.replies[2] = (reply){.key = other, .status = 200, .body = SLICE("\"message\": \"Invalid api_key_private")};
    results = scan(detector, input, true, &steps); CHECK(results.len == 3);
    test_key_result(&results.items[0], 506, key, "key"); check_error(&results.items[0], false, unsupported);
    test_key_result(&results.items[1], 506, key, "key"); check_error(&results.items[1], true, NULL);
    test_key_result(&results.items[2], 506, other, "key"); check_error(&results.items[2], false, NULL); br_results_clear(&results);
}

static void positive_setter_resource_failure(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "besttime %s\nbesttime %s\nbesttime %s", key, key, other);
    script steps = {.count = 1}; steps.replies[0] = (reply){.key = key, .status = 503};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data; fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && *error);
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    steps.count = 3; steps.replies[1] = (reply){.key = key, .status = 200, .body = SLICE("\"status\": \"OK\"")};
    steps.replies[2] = (reply){.key = other, .status = 401};
    results = scan(detector, input, true, &steps); CHECK(results.len == 3);
    check_error(&results.items[0], false, status_503); check_error(&results.items[1], true, NULL);
    check_error(&results.items[2], false, "unexpected status code: 401"); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = init();
    extraction(detector); markers_and_read_error(detector); diagnostics(detector); other_statuses_and_transport(detector);
    context_and_continuation(detector); positive_setter_resource_failure(detector);
    return test_finish("Besttime occurrences + binary marker precedence + bounded full-body diagnostics");
}
