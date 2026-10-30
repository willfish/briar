/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_rootly_init(const br_detector **out, char **error);

static char key[72], other[72];
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 71 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[72]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static void make_key(char out[72], char fill)
{
    memcpy(out, "rootly_", 7);
    memset(out + 7, fill, 64);
    out[71] = '\0';
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 1035, expected, "key");
    CHECK(result->verified == verified);
    if (cause) {
        CHECK(result->verification_error && !strcmp(result->verification_error, cause));
        CHECK(!strstr(result->verification_error, expected));
    } else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    make_key(key, 'a'); make_key(other, 'b');
    CHECK(br_rootly_init(NULL, &error) == -1 && error); free(error);
    CHECK(!br_rootly_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 1035 && detector->version == 0 && !strcmp(detector->name, "Rootly"));
    CHECK(!strcmp(detector->description, "Rootly is an incident management platform. Rootly API keys can be used to access and manage incident data and other services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "rootly_"));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

typedef struct { const char *key, *send_error; int status; } reply;
typedef struct { reply rows[2]; size_t count; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; reply *step = &steps->rows[at];
    CHECK(ctx == steps->expected_ctx && http->releases == at);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.rootly.com/v1/incidents"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1035);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, step->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    http->response = (br_http_response){.status = step->status, .body_error = "ignored close"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : 0;
}

static br_results run(const br_detector *detector, const char *input, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count);
    return results;
}

static void extraction(const br_detector *detector)
{
    char input[240], changed[72];
    snprintf(input, sizeof(input), "%s %s %s", key, other, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false, NULL);
    check_result(&results.items[1], other, false, NULL);
    br_results_clear(&results);
    memcpy(changed, key, 72); changed[7] = 'A'; snprintf(input, sizeof(input), " %s ", changed);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "x%s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[90]; snprintf(input, sizeof(input), "token %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false, "net/http: nil Context");
    br_results_clear(&results);
    const int codes[] = {200, 404, 401, 403, 422, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = codes[i]};
        results = run(detector, input, &steps); CHECK(results.len == 1);
        char cause[80]; const char *expected = NULL;
        bool verified = codes[i] == 200 || codes[i] == 404;
        if (!verified && codes[i] != 401) {
            snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", codes[i]);
            expected = cause;
        }
        check_result(&results.items[0], key, verified, expected);
        br_results_clear(&results);
    }
    char noisy[160]; snprintf(noisy, sizeof(noisy), "token %s rejected", key);
    script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .send_error = noisy};
    results = run(detector, input, &steps);
    check_result(&results.items[0], key, false, "token [REDACTED] rejected");
    br_results_clear(&results);
}

static void resource_boundary(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "%s\n%s", key, other);
    script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = 404};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = {0}; br_result prior = {0};
    CHECK(!br_finding_key(&prior, 777, "prior", "key"));
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(!br_results_push(&results, &prior));
    char *saved = results.items[0].verification_error, *error = NULL;
    fail_finding_after = 2;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Rootly result") && http.calls == 1 && results.len == 1);
    CHECK(results.items[0].verification_error == saved);
    free(error); br_results_clear(&results);
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

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector); resource_boundary(detector);
    return test_finish("Rootly unique lowercase token + 200/404 verified + redacted setter");
}
