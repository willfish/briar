/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int snow_doc_rc;
static int snow_type_null;
static int snow_type_calls;
static int snow_type_fatal_after;
static int snow_type_fatal_rc;
static int snow_visit_calls;
static int snow_visit_fatal_after;

int br_snowflake_json_document(br_slice body, br_json **out, char **cause)
{
    if (snow_doc_rc) {
        if (out) *out = NULL;
        if (cause) *cause = NULL;
        return snow_doc_rc;
    }
    return br_json_document(body, out, cause);
}

int br_snowflake_type_cause(br_json *value, const char *field, const char *type, char **cause)
{
    ++snow_type_calls;
    if (snow_type_fatal_after && snow_type_calls >= snow_type_fatal_after) {
        if (cause) *cause = NULL;
        return snow_type_fatal_rc ? snow_type_fatal_rc : -1;
    }
    if (snow_type_null) {
        if (cause) *cause = NULL;
        return 0;
    }
    return br_json_type_cause(value, field, type, cause);
}

int br_snowflake_visit_success(br_json *value)
{
    (void)value;
    ++snow_visit_calls;
    if (snow_visit_fatal_after && snow_visit_calls >= snow_visit_fatal_after) return 1;
    return 0;
}

int br_snowflake_init(const br_detector **out, char **error);

static const char account[] = "tuacoip-zt74995";
static const char username[] = "alice01";
static const char password[] = "Secret12";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_snowflake_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_snowflake_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 927 && !strcmp(detector->name, "Snowflake"));
    CHECK(!strcmp(detector->description,
                  "Snowflake is a cloud data platform that provides data warehousing, data lakes, data sharing, and data exchange capabilities. Snowflake credentials can be used to access and manipulate data stored in Snowflake."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "snowflake"));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1);
    return detector;
}

static void check_result(const br_result *result, const char *expected_account)
{
    CHECK(result->detector_type == 927);
    CHECK(result->raw.len == strlen(password) && !memcmp(result->raw.data, password, strlen(password)));
    CHECK(!result->raw_v2.data && !result->verification_error);
    CHECK(result->extra_data);
    CHECK(!strcmp(json_object_get_string(json_object_object_get(result->extra_data, "account")),
                  expected_account));
    CHECK(!strcmp(json_object_get_string(json_object_object_get(result->extra_data, "username")),
                  username));
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input),
             "snowflake\naccount=%s\nusername=%s\npassword=%s\n", account, username, password);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], account);
    br_results_clear(&results);
    snprintf(input, sizeof(input),
             "account=%s.privatelink\nusername=%s\npassword=%s\n", account, username, password);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], "tuacoip-zt74995.privatelink");
    br_results_clear(&results);
    snprintf(input, sizeof(input),
             "account=tuacoip-z\nusername=%s\npassword=%s\n", username, password);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], "tuacoip-z");
    br_results_clear(&results);
    snprintf(input, sizeof(input),
             "account=%s\nusername=Spencer@5091.com\npassword=!12\n", account);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input),
             "account=%s\nusername=%s\npassword=short1A\n", account, username);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

static int snow_status;
static const char *snow_body;
static bool snow_transport;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[128];
    snprintf(url, sizeof(url), "https://%s.snowflakecomputing.com/session/v1/login-request", account);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 3000);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") &&
          !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Accept") &&
          !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "X-Snowflake-Authorization-Token-Type") &&
          !strcmp(request->headers[2].value, "BASIC"));
    char expect[160];
    snprintf(expect, sizeof(expect),
             "{\"data\":{\"LOGIN_NAME\":\"%s\",\"PASSWORD\":\"%s\",\"ACCOUNT_NAME\":\"%s\"}}",
             username, password, account);
    CHECK(request->body.len == strlen(expect) && !memcmp(request->body.data, expect, request->body.len));
    if (snow_transport) {
        http->send_error = "dial tcp: connection refused";
        http->send_rc = -1;
        return;
    }
    http->response.status = snow_status;
    if (snow_body) http->response.body = (br_slice){(const unsigned char *)snow_body, strlen(snow_body)};
}

static void verification(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input),
             "account=%s\nusername=%s\npassword=%s\n", account, username, password);
    snow_status = 200;
    snow_body = "{\"success\":true}";
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    snow_body = "{\"success\":false}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    snow_status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    snow_status = 200;
    snow_body = "not-json";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "failed to parse response:"));
    br_results_clear(&results);
    snow_transport = true;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "failed to send request:"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "failed to create request: net/http: nil Context"));
    br_results_clear(&results);

    snow_status = 200;
    snow_transport = false;
    http.send_rc = 0;
    http.send_error = NULL;
    snow_visit_calls = 0;
    snow_body = "{\"success\":true,\"success\":null}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(snow_visit_calls >= 2);
    br_results_clear(&results);

    snow_body = "{\"success\":1,\"success\":\"no\"}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(strstr(results.items[0].verification_error, "failed to parse response: ") &&
          strstr(results.items[0].verification_error, "cannot unmarshal number") &&
          !strstr(results.items[0].verification_error, "cannot unmarshal string"));
    br_results_clear(&results);

    snow_type_null = 1;
    snow_visit_calls = 0;
    snow_body = "{\"success\":1,\"success\":true}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(snow_visit_calls >= 2);
    br_results_clear(&results);
    snow_type_null = 0;
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    snow_status = 200;
    snow_body = "{\"success\":1,\"success\":true}";
    snow_transport = false;
    snow_type_null = 0;
    snow_visit_calls = 0;
    snow_visit_fatal_after = 2;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[256];
    snprintf(input, sizeof(input), "snowflake\naccount=%s\nusername=%s\npassword=%s\n",
             account, username, password);
    br_results fatal = {0};
    char *scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot parse Snowflake response") && !fatal.len);
    CHECK(snow_visit_calls >= 2);
    free(scan_error);
    br_results_clear(&fatal);
    snow_visit_fatal_after = 0;
    snow_body = "{\"success\":1,\"success\":\"no\"}";
    for (int code = 1; code <= 2; ++code) {
        snow_type_calls = 0;
        snow_type_fatal_after = 2;
        snow_type_fatal_rc = code;
        scan_error = NULL;
        CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                             &fatal, &scan_error) != 0);
        CHECK(scan_error && !strcmp(scan_error, "cannot parse Snowflake response") && !fatal.len);
        CHECK(snow_type_calls >= 2);
        free(scan_error);
        br_results_clear(&fatal);
    }
    snow_type_fatal_after = 0;
    snow_type_fatal_rc = 0;

    snow_body = "{}";
    snow_doc_rc = 1;
    br_results ordinary = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(ordinary.len == 1 && !ordinary.items[0].verified && !ordinary.items[0].verification_error);
    br_results_clear(&ordinary);
    snow_doc_rc = 2;
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot parse Snowflake response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    snow_doc_rc = 0;
    return test_finish("snowflake");
}
