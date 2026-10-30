/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_testingbot_init(const br_detector **out, char **error);

static const char id[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char key[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32);
    char copy[33]; memcpy(copy, value, 32); copy[32] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 759, expected, "key");
    CHECK(result->verified == verified);
    if (cause) {
        CHECK(result->verification_error && !strcmp(result->verification_error, cause));
        CHECK(!strstr(result->verification_error, expected));
    } else CHECK(!result->verification_error);
}

typedef struct { const char *id, *key, *send_error; int status; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    const char *user = at == 0 ? steps->id : steps->key;
    const char *secret = at == 0 ? steps->key : steps->id;
    char *expected = NULL; char *error = NULL;
    CHECK(at < 2 && http->releases == at && ctx == steps->expected_ctx);
    CHECK(!br_http_basic_auth((br_slice){(const unsigned char *)user, 32},
                              (br_slice){(const unsigned char *)secret, 32}, &expected, &error) && !error);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.testingbot.com/v1/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 759);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, expected));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    free(expected);
    http->response = (br_http_response){.status = steps->status, .body_error = "ignored drain"};
    http->send_error = steps->send_error; http->send_rc = steps->send_error ? -1 : 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(id) == 32 && strlen(key) == 32);
    CHECK(br_testingbot_init(NULL, &error) == -1); free(error);
    CHECK(!br_testingbot_init(&detector, &error) && !error);
    CHECK(detector->type == 759 && !strcmp(detector->name, "TestingBot") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description, "TestingBot provides cross-browser testing services. TestingBot credentials can be used to automate tests on various browsers and devices."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "testingbot"));
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[140];
    snprintf(input, sizeof(input), "testingbot %s", id);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); /* A token paired only with itself is skipped. */
    br_results_clear(&results);
    snprintf(input, sizeof(input), "testingbot %s testingbot %s testingbot %s", id, key, id);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false, NULL); /* id-major, first-seen. */
    check_result(&results.items[1], id, false, NULL);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[120]; snprintf(input, sizeof(input), "testingbot %s testingbot %s", id, key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false, "net/http: nil Context");
    check_result(&results.items[1], id, false, "net/http: nil Context");
    br_results_clear(&results);
    const int codes[] = {200, 401, 403, 500};
    const char *causes[] = {NULL, NULL, NULL, "unexpected status code: 500"};
    for (size_t i = 0; i < 4; ++i) {
        script steps = {.id = id, .key = key, .status = codes[i]};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 2 && http.releases == 2 && results.len == 2);
        check_result(&results.items[0], key, codes[i] == 200, causes[i]);
        check_result(&results.items[1], id, codes[i] == 200, causes[i]);
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
    return test_finish("TestingBot unequal unique pairs + basic auth + redacted nil error");
}
