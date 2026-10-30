/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_sourcegraphcody_init(const br_detector **out, char **error);

static char key[69], other[69];

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 68 || len == 5);
    char copy[69]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static void make_key(char out[69], char fill)
{
    memcpy(out, "slk_", 4);
    memset(out + 4, fill, 64);
    out[68] = '\0';
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 936, expected, "key");
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
    CHECK(br_sourcegraphcody_init(NULL, &error) == -1); free(error);
    CHECK(!br_sourcegraphcody_init(&detector, &error) && !error);
    CHECK(detector->type == 936 && !strcmp(detector->name, "SourcegraphCody") && detector->version == 0);
    CHECK(!strcmp(detector->description, "Sourcegraph Cody is a tool for integrating code intelligence into your development workflow. The detected key is used for accessing Sourcegraph Cody services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "slk_") && detector->max_credential_span == -1);
    return detector;
}

typedef struct { const char *key, *send_error; int status; } reply;
typedef struct { reply rows[2]; size_t count; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; reply *step = &steps->rows[at];
    CHECK(ctx == steps->expected_ctx && http->releases == at);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://cody-gateway.sourcegraph.com/v1/limits"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 936);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, step->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    http->response = (br_http_response){.status = step->status, .body_error = "ignored close"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : 0;
}

static void extraction_and_panic(const br_detector *detector)
{
    char input[220], changed[69];
    snprintf(input, sizeof(input), "%s\n%s\n%s", key, other, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    check_result(&results.items[0], key, false, NULL);
    check_result(&results.items[1], other, false, NULL);
    check_result(&results.items[2], key, false, NULL);
    br_results_clear(&results);
    memcpy(changed, key, 69); changed[4] = 'A';
    snprintf(input, sizeof(input), " %s ", changed);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s", key);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = (br_results){0}; br_result prior = {0};
    CHECK(!br_finding_key(&prior, 777, "prior", "key"));
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(!br_results_push(&results, &prior));
    char *saved = results.items[0].verification_error, *error = NULL;
    int rc = detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "unsupported upstream panic: SourcegraphCody nil request before Header.Add"));
    CHECK(!http.calls && !http.releases && results.len == 1 && results.items[0].verification_error == saved);
    free(error); br_results_clear(&results);
    (void)ctx;
}

static void verification(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "token %s", key);
    const int codes[] = {200, 299, 401, 403, 404, 500};
    for (size_t i = 0; i < 6; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = codes[i]};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        char cause[80]; const char *expected = NULL;
        bool verified = codes[i] >= 200 && codes[i] < 300;
        if (!verified && codes[i] != 401 && codes[i] != 403) {
            snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", codes[i]);
            expected = cause;
        }
        check_result(&results.items[0], key, verified, expected);
        br_results_clear(&results);
    }
    char noisy[120]; snprintf(noisy, sizeof(noisy), "gateway %s down", key);
    script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .send_error = noisy};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    check_result(&results.items[0], key, false, "gateway [REDACTED] down");
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

int main(void)
{
    const br_detector *detector = descriptor();
    extraction_and_panic(detector); verification(detector);
    return test_finish("SourcegraphCody duplicate tokens + nil Header.Add panic + 2xx/401/403");
}
