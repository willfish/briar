/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_wit_init(const br_detector **out, char **error);

static const char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
static const char other[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[33]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 817, expected, "key");
    CHECK(result->verified == verified);
    if (cause) {
        CHECK(result->verification_error && !strcmp(result->verification_error, cause));
        CHECK(!strstr(result->verification_error, expected));
    } else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_wit_init(NULL, &error) == -1); free(error);
    CHECK(!br_wit_init(&detector, &error) && !error);
    CHECK(detector->type == 817 && !strcmp(detector->name, "Wit") && detector->version == 0);
    CHECK(!strcmp(detector->description, "Wit.ai is a natural language processing service that provides an API for building conversational interfaces. Wit.ai API keys can be used to access and modify this data and compute."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "wit"));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void expect_count(const br_detector *detector, const char *input, size_t n)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == n);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "wit %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
    snprintf(input, sizeof(input), "WIT%*s%s", 40, "", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
    snprintf(input, sizeof(input), "wit%*s%s", 41, "", key); expect_count(detector, input, 0);
    snprintf(input, sizeof(input), "%s wit", key); expect_count(detector, input, 0);
    snprintf(input, sizeof(input), "wit %s", "abcdefghijklmnopqrstuvwxyz012345"); expect_count(detector, input, 0);
    snprintf(input, sizeof(input), "wit %s\nwit %s\nwit %s", key, other, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false, NULL);
    check_result(&results.items[1], other, false, NULL);
    br_results_clear(&results);
}

typedef struct { const char *key, *send_error; int status; } reply;
typedef struct { reply rows[1]; size_t count; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; reply *step = &steps->rows[0];
    CHECK(ctx == steps->expected_ctx && http->releases == 0);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.wit.ai/apps?offset=1&limit=2"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 817);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, step->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    http->response = (br_http_response){.status = step->status, .body_error = "ignored drain"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : 0;
}

static void verification(const br_detector *detector)
{
    char input[48]; snprintf(input, sizeof(input), "wit %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, "net/http: nil Context");
    br_results_clear(&results);
    const int codes[] = {200, 401, 403, 404, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = codes[i]};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        char cause[80]; const char *expected = NULL;
        bool verified = codes[i] == 200;
        if (codes[i] != 200 && codes[i] != 401 && codes[i] != 403) {
            snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", codes[i]);
            expected = cause;
        }
        check_result(&results.items[0], key, verified, expected);
        br_results_clear(&results);
    }
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
    extraction(detector); verification(detector);
    return test_finish("Wit prefixed uppercase key + 401/403 quiet + nil verification error");
}
