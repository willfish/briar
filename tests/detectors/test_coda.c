/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

static const char key[] = "g1h2i3j4-k5l6-m7n8-o9p0-q1r2s3t4u5v6";
static const char other[] = "z9y8x7w6-v5u4-t3s2-r1q0-p9o8n7m6l5k4";
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_copy;
static size_t fail_finding_after;

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len); if (copy) memcpy(copy, text, len); return copy;
}

/* Existing focused finding-allocation check, not an auth allocation seam. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 36 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[37]; memcpy(copy, value, (size_t)len); copy[len] = '\0'; return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_coda_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Coda detector output")); free(error); error = NULL;
    CHECK(!br_coda_init(&detector, &error) && detector && !error);
    CHECK(!br_coda_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 960 && detector->version == 0 && !strcmp(detector->name, "Coda") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Coda is a platform for building collaborative documents and applications. Coda API keys can be used to access and manipulate data within Coda documents and applications."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "coda"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *error)
{
    test_key_result(result, 960, expected, "key"); CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[38];
    snprintf(input, sizeof(input), "coda '%s'", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "CODA=%s", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "preCoDasuffix\r\n%s", other); expect_one(detector, input, other);
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "co da %s", key); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = 'G'; snprintf(input, sizeof(input), "coda %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[8] = '_'; snprintf(input, sizeof(input), "coda %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[35] = 0; snprintf(input, sizeof(input), "coda %s", changed); expect_one(detector, input, NULL);
    snprintf(changed, sizeof(changed), "%sa", key); snprintf(input, sizeof(input), "coda %s", changed); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coda _%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coda %s_", key); expect_one(detector, input, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "coda%*s%s", gap, "", key); expect_one(detector, input, gap == 40 ? key : NULL);
    }
    const char *low = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"; snprintf(input, sizeof(input), "coda %s", low); expect_one(detector, input, low); /* Nonhex, no UUID-version/entropy validation. */
}

typedef struct { const char *key, *send_error; int status, send_rc; } reply;
typedef struct {
    reply rows[3]; size_t count; bool mutate_error, mutated; char *returned_error;
    const char *borrowed_auth; const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 960 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://coda.io/apis/v1/whoami"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog")); CHECK(!header(request, "Accept") && !header(request, "Content-Type") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization"); CHECK(auth && strlen(auth) == 43 && !memcmp(auth, "Bearer ", 7) && !memcmp(auth + 7, step->key, 36) && auth[43] == '\0'); steps->borrowed_auth = auth;
    static const unsigned char body[] = "\xff\0ignored non-JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/close failure"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static int send_response(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; script *steps = http->user; int rc = test_http_send(user, ctx, request, response, error); steps->returned_error = *error; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && strlen(steps->borrowed_auth) == 43 && !memcmp(steps->borrowed_auth, "Bearer ", 7));
    if (steps->mutate_error && steps->returned_error) { memset(steps->returned_error, '!', strlen(steps->returned_error)); steps->mutated = true; }
    steps->returned_error = NULL; steps->borrowed_auth = NULL; test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, send_response, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); CHECK(http.calls == steps->count && http.releases == steps->count); return results;
}

static void occurrences_and_nil(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "coda %s\ncoda %s\ncoda %s", key, other, key); const char *keys[] = {key, other, key}; script steps = {.count = 3};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {0}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify, NULL);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
}

static void statuses_and_redaction(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "coda %s", key); const int codes[] = {199, 200, 201, 204, 299, 300, 302, 401, 403, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = codes[i]}; br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", codes[i]); bool success = codes[i] >= 200 && codes[i] < 300;
        check_result(&results.items[0], key, success, success || codes[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char cause[256], redacted[192]; snprintf(cause, sizeof(cause), "key=%s repeat=%s keep=%s partial=%s", key, key, other, key + 20); snprintf(redacted, sizeof(redacted), "key=[REDACTED] repeat=[REDACTED] keep=%s partial=%s", other, key + 20);
    script steps = {.count = 1, .mutate_error = true}; steps.rows[0] = (reply){.key = key, .status = 200, .send_error = cause};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 1 && steps.mutated); check_result(&results.items[0], key, false, redacted); br_results_clear(&results);
    const char *causes[] = {"net/http: nil Context", "synthetic Do failure", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        steps = (script){.count = 1}; steps.rows[0] = (reply){.key = key, .status = 200, .send_error = causes[i], .send_rc = 1};
        results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, false, causes[i] ? causes[i] : "HTTP transport failed"); br_results_clear(&results); /* Do text is not a constructor skip. */
    }
}

static void resource_boundary(const br_detector *detector)
{
    br_result probe = {0}; fail_status_copy = true; CHECK(br_result_set_verification_error(&probe, status_503, NULL, 0) == 1 && !fail_status_copy && !probe.verification_error); br_result_clear(&probe);
    char input[128]; snprintf(input, sizeof(input), "coda %s\ncoda %s", key, other);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2}; steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = mode == 0 ? 503 : 200};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error, *error = NULL;
        if (mode == 0) fail_status_copy = true; else fail_finding_after = 2;
        int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && !fail_status_copy && !fail_finding_after && error && !strcmp(error, mode == 0 ? "cannot store Coda verification error" : "cannot create Coda result"));
        CHECK(http.calls == (mode == 0 ? 2u : mode == 1 ? 1u : 0u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); br_json *part = NULL; CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part) && !strcmp(json_object_get_string(part), "prior")); free(error); br_results_clear(&results);
        results = run(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], key, true, NULL); check_result(&results.items[1], other, mode != 0, mode == 0 ? status_503 : NULL); br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); occurrences_and_nil(detector); statuses_and_redaction(detector); resource_boundary(detector);
    return test_finish("Coda nonhex UUID-shaped occurrences + complete Bearer + nil skip/retained errors + setter rollback");
}
