/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

#include <dlfcn.h>

static int sg_doc_rc;
static int sg_visit_rc;
static int sg_scope_null;
static int sg_scope_fatal_after;
static int sg_scope_fatal_rc;
static int sg_scope_calls;

int br_sendgrid_json_document(br_slice body, const char *read_error, br_json **out, size_t *end,
                              char **cause)
{
    if (sg_doc_rc) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return sg_doc_rc;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

int br_sendgrid_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    int rc = br_json_each_member(object, callback, user);
    return sg_visit_rc && rc == 0 ? sg_visit_rc : rc;
}

int br_sendgrid_scope_value(br_json *value, bool *type_valid, char **cause)
{
    ++sg_scope_calls;
    if (sg_scope_fatal_after && sg_scope_calls >= sg_scope_fatal_after) {
        if (cause) *cause = NULL;
        if (type_valid) *type_valid = false;
        return sg_scope_fatal_rc ? sg_scope_fatal_rc : -1;
    }
    if (!value || json_object_is_type(value, json_type_null) ||
        json_object_is_type(value, json_type_string)) {
        if (cause) *cause = NULL;
        if (type_valid) *type_valid = true;
        return 0;
    }
    if (type_valid) *type_valid = false;
    if (sg_scope_null) {
        if (cause) *cause = NULL;
        return 0;
    }
    return br_json_type_cause(value, "scopesResponse.Scopes", "string", cause);
}

int br_sendgrid_init(const br_detector **out, char **error);

static const char token[] = "SG.ZV-VYwtHzJJW4wF8yPQk3.ZXg9c9DZuOgUcW1f2inP6SqfEsYG82zAe0wG7brZZ5OvruV-I";
static const char other[] = "SG.aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    static struct json_object *(*real_new)(const char *, int);
    if (!real_new) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
        real_new = dlsym((void *)-1L, "json_object_new_string_len");
#pragma GCC diagnostic pop
    }
    return real_new ? real_new(value, len) : NULL;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(token) == 74 && strlen(other) == 63);
    CHECK(br_sendgrid_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_sendgrid_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 12 && !strcmp(detector->name, "SendGrid") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "SendGrid is a cloud-based service that provides email delivery and marketing campaigns. SendGrid API keys can be used to send emails and manage other email-related tasks."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "SG."));
    CHECK(detector->max_credential_span == -1 && detector->max_secret_size == -1);
    return detector;
}

static void check_plain(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 12, expected, "key");
    CHECK(result->verified == verified && !result->verification_error && !result->extra_data);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "sendgrid token = '%s'", token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_plain(&results.items[0], token, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sendgrid token = '%s' | '%s'", token, token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_plain(&results.items[0], token, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sendgrid = '%s'",
             "SG.ZV-VYwtHzJJW4wF8yPQk3.ZXg9?9DZuOgUcW1f2inP6SqfEsYG82zAe0wG7brZZ5OvruV-I");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "x%s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", token, other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_plain(&results.items[0], token, false);
    check_plain(&results.items[1], other, false);
    br_results_clear(&results);
}

static int send_status;
static const char *send_body;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.sendgrid.com/v3/scopes"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 12);
    CHECK(request->nheaders == 3 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, http->user));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    http->response.status = send_status;
    http->response.body = (br_slice){(const unsigned char *)send_body, send_body ? strlen(send_body) : 0};
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "%s", token);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context") && !results.items[0].extra_data);
    br_results_clear(&results);
    send_status = 200;
    send_body = "{\"scopes\":[\"mail.send\",\"mail.batch\"]}";
    test_http http = {.inspect = inspect, .user = (void *)token};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "rotation_guide", &part) &&
          !strcmp(json_object_get_string(part), "https://howtorotate.com/docs/tutorials/sendgrid/"));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "scopes", &part) &&
          !strcmp(json_object_get_string(part), "mail.send,mail.batch"));
    br_results_clear(&results);
    send_body = "{\"scopes\":[\"mail.send\",null]}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "scopes", &part) &&
          !strcmp(json_object_get_string(part), "mail.send,"));
    br_results_clear(&results);
    send_body = "{\"scopes\":[\"keep\",\"old\"],\"scopes\":[null,\"x\"]}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "scopes", &part) &&
          !strcmp(json_object_get_string(part), "keep,x"));
    br_results_clear(&results);
    send_body = "{\"scopes\":[null]}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "scopes", &part) &&
          !strcmp(json_object_get_string(part), ""));
    br_results_clear(&results);
    send_body = "{\"scopes\":[\"a\",\"b\"],\"scopes\":[null],\"scopes\":[null,null]}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "scopes", &part));
    CHECK(json_object_get_string_len(part) == 3 && !memcmp(json_object_get_string(part), "a,b", 3));
    br_results_clear(&results);
    send_body = "{\"scopes\":[\"a\\u0000b\"]}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "scopes", &part));
    CHECK(json_object_get_string_len(part) == 3 && !memcmp(json_object_get_string(part), "a\0b", 3));
    br_results_clear(&results);
    sg_scope_calls = 0;
    sg_scope_null = 1;
    send_body = "{\"scopes\":[1]}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error &&
          !results.items[0].extra_data);
    br_results_clear(&results);
    sg_scope_null = 0;
    send_body = "{\"scopes\":[]}";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "rotation_guide", &part));
    CHECK(!json_object_object_get_ex(results.items[0].extra_data, "scopes", &part));
    br_results_clear(&results);
    send_status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error &&
          !results.items[0].extra_data);
    br_results_clear(&results);
    send_status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data &&
          !results.items[0].verification_error);
    br_results_clear(&results);
    send_status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    send_status = 200;
    send_body = "not-json";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !results.items[0].extra_data);
    br_results_clear(&results);
    http.send_error = "timeout";
    http.send_rc = -1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "timeout"));
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[180];
    snprintf(input, sizeof(input), "%s %s", token, other);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 2, "prior", "key") && !br_results_push(&results, &prior));
    fail_finding_after = 2;
    char *error = NULL;
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create SendGrid result") && results.len == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    send_status = 200;
    send_body = "{}";
    sg_doc_rc = 2;
    test_http http = {.inspect = inspect, .user = (void *)token};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results fatal = {0};
    char *scan_error = NULL;
    br_slice bytes = {(const unsigned char *)token, strlen(token)};
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode SendGrid response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    sg_doc_rc = 0;
    sg_visit_rc = 1;
    send_body = "{\"scopes\":1}";
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode SendGrid response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    sg_visit_rc = 0;
    sg_scope_calls = 0;
    sg_scope_fatal_after = 2;
    send_body = "{\"scopes\":[1,\"later\"]}";
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode SendGrid response") && !fatal.len);
    CHECK(sg_scope_calls >= 2);
    free(scan_error);
    br_results_clear(&fatal);
    for (int code = 1; code <= 2; ++code) {
        sg_scope_calls = 0;
        sg_scope_fatal_after = 2;
        sg_scope_fatal_rc = code;
        scan_error = NULL;
        CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
        CHECK(scan_error && !strcmp(scan_error, "cannot decode SendGrid response") && !fatal.len);
        CHECK(sg_scope_calls >= 2);
        free(scan_error);
        br_results_clear(&fatal);
    }
    sg_scope_fatal_after = 0;
    sg_scope_fatal_rc = 0;
    return test_finish("SendGrid unprefixed unique token, scopes extra, 200/401/403/unexpected");
}
