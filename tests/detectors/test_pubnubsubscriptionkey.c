/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_pubnubsubscriptionkey_init(const br_detector **out, char **error);

static const char key[] = "sub-c-01234567-89ab-cdef-0123-456789abcdef";
static const char other[] = "sub-c-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 42 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[43]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 83, expected, "key");
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(strlen(key) == 42 && strlen(other) == 42);
    CHECK(br_pubnubsubscriptionkey_init(NULL, &error) == -1 && error && !strcmp(error, "invalid PubNubSubscriptionKey detector output"));
    free(error); error = NULL;
    CHECK(!br_pubnubsubscriptionkey_init(&detector, &error) && detector && !error);
    CHECK(!br_pubnubsubscriptionkey_init(&again, &error) && again == detector);
    CHECK(detector->type == 83 && !strcmp(detector->name, "PubNubSubscriptionKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "PubNub is a real-time communication platform. A PubNub Subscription Key allows access to the PubNub API for subscribing to channels and receiving messages."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "sub-c-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->version == 0 && detector->state && detector->scan && !detector->clean);
    return detector;
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[180], changed[43];
    snprintf(input, sizeof(input), "pubnub %s", key); expect_one(detector, input, key);
    expect_one(detector, key, key);
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false, NULL);
    check_result(&results.items[1], key, false, NULL);
    br_results_clear(&results);
    memcpy(changed, key, 43); changed[6] = 'A'; snprintf(input, sizeof(input), " %s ", changed); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "x%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "%sz", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "sub-c-01234567-89AB-cdef-0123-456789abcdef"); expect_one(detector, input, NULL);
}

typedef struct { const char *key, *send_error, *body, *body_error; int status; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    char url[81];
    snprintf(url, sizeof(url), "https://ps.pndsn.com/v2/objects/%s/uuids", step->key);
    CHECK(request->detector_type == 83 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.len && !request->dedup_key.len && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog"));
    http->response = (br_http_response){.status = step->status, .body_error = step->body_error};
    if (step->body) http->response.body = (br_slice){(const unsigned char *)step->body, strlen(step->body)};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : 0;
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count);
    return results;
}

static void verification(const br_detector *detector)
{
    char input[140]; snprintf(input, sizeof(input), "%s %s", key, other);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false, "net/http: nil Context");
    check_result(&results.items[1], other, false, "net/http: nil Context");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "k=%s", key);
    const char *needle = "prefix Objects not enabled for this subscriber key. suffix";
    script cases[] = {
        {.count = 1, .rows = {{.key = key, .status = 200, .body_error = "ignored"}}},
        {.count = 1, .rows = {{.key = key, .status = 401, .body = needle}}},
        {.count = 1, .rows = {{.key = key, .status = 403, .body = needle}}},
        {.count = 1, .rows = {{.key = key, .status = 403, .body = "Objects not enabled"}}},
        {.count = 1, .rows = {{.key = key, .status = 403, .body = needle, .body_error = "read failed"}}},
        {.count = 1, .rows = {{.key = key, .status = 500}}},
    };
    const bool verified[] = {true, false, true, false, false, false};
    const char *causes[] = {NULL, NULL, NULL, NULL, "read failed", "unexpected status code: 500"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        results = run(detector, input, true, &cases[i]);
        CHECK(results.len == 1);
        check_result(&results.items[0], key, verified[i], causes[i]);
        br_results_clear(&results);
    }
    char noisy[80]; snprintf(noisy, sizeof(noisy), "dial %s refused", key);
    script steps = {.count = 1, .rows = {{.key = key, .status = 200, .send_error = noisy}}};
    results = run(detector, input, true, &steps);
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false, noisy); /* No secret was supplied to the setter. */
    br_results_clear(&results);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
}

static void resource_boundary(const br_detector *detector)
{
    char input[120]; snprintf(input, sizeof(input), "%s\n%s", key, other);
    script steps = {.count = 2};
    steps.rows[0] = (reply){.key = key, .status = 200};
    steps.rows[1] = (reply){.key = other, .status = 403, .body = "Objects not enabled for this subscriber key."};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    steps.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0};
    CHECK(!br_finding_key(&prior, 777, "prior", "key"));
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && !br_results_push(&results, &prior));
    char *saved_error = results.items[0].verification_error, *error = NULL;
    fail_finding_after = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create PubNubSubscriptionKey result"));
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1 && results.items[0].verification_error == saved_error);
    free(error); br_results_clear(&results);
    results = run(detector, input, true, &steps);
    CHECK(results.len == 2);
    check_result(&results.items[0], key, true, NULL);
    check_result(&results.items[1], other, true, NULL);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); resource_boundary(detector);
    return test_finish("PubNubSubscriptionKey duplicates + 403 object marker + unredacted setter");
}
