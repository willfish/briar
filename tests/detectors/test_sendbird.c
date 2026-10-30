/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int sb_doc_rc;
static int sb_visit_rc;
static int sb_type_null;
static int sb_type_fatal_after;
static int sb_type_fatal_rc;
static int sb_type_calls;

int br_sendbird_json_document(br_slice body, const char *read_error, br_json **out, size_t *end,
                              char **cause)
{
    if (sb_doc_rc) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return sb_doc_rc;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

int br_sendbird_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    int rc = br_json_each_member(object, callback, user);
    return sb_visit_rc && rc == 0 ? sb_visit_rc : rc;
}

int br_sendbird_type_cause(br_json *value, const char *field, const char *expected, char **cause)
{
    ++sb_type_calls;
    if (sb_type_fatal_after && sb_type_calls >= sb_type_fatal_after) {
        if (cause) *cause = NULL;
        return sb_type_fatal_rc ? sb_type_fatal_rc : -1;
    }
    if (sb_type_null) {
        if (cause) *cause = NULL;
        return 0;
    }
    return br_json_type_cause(value, field, expected, cause);
}

int br_sendbird_init(const br_detector **out, char **error);

static const char key[] = "e9aeb40d34e6a7a9fb10e5876be968e344420b0c";
static const char app[] = "FAB7BE5B-E6DD-670A-A3DC-91AF003DB677";
static char seen_url[80], seen_token[48];

static void expect_key(const br_result *result)
{
    br_json *part = NULL;
    CHECK(result->detector_type == 750 && result->raw.len == 40 && !memcmp(result->raw.data, key, 40));
    CHECK(!result->raw_v2.data && json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &part));
    CHECK(!strcmp(json_object_get_string(part), "https://howtorotate.com/docs/tutorials/sendbird/"));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && request->detector_type == 750);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Api-Token"));
    snprintf(seen_url, sizeof(seen_url), "%s", request->url);
    snprintf(seen_token, sizeof(seen_token), "%s", request->headers[0].value);
}

static br_http_response body_status(int status, const char *body)
{
    return (br_http_response){.status = status, .body = {(const unsigned char *)body, body ? strlen(body) : 0}};
}

int main(void)
{
    CHECK(strlen(key) == 40 && strlen(app) == 36);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sendbird_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 750 && !strcmp(detector->name, "Sendbird") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "sendbird"));
    CHECK(!strcmp(detector->description, "Sendbird is a communication platform providing chat, voice, and video services. Sendbird API tokens can be used to access and manage communication services."));
    char input[256];
    snprintf(input, sizeof(input), "sendbird token - '%s'\nsendbird token - '%s'\n", key, app);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    expect_key(&out.items[0]);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "SENDBIRD %s sendbird %s sendbird %s", app, app, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "sendbird %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "sendbird ?9aeb40d34e6a7a9fb10e5876be968e344420b0c sendbird FAB7BE5B?E6DD-670A-A3DC-91AF003DB677");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "sendbird %s sendbird %s", key, app);
    http.response = body_status(204, "ignored");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(!strcmp(seen_url, "https://api-FAB7BE5B-E6DD-670A-A3DC-91AF003DB677.sendbird.com/v3/users"));
    CHECK(!strcmp(seen_token, key));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(400, "{\"code\":400401}");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(400, "{\"Code\":400100}");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "unexpected response code: 400100"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(400, "{}");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "unexpected response code: 0"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(400, "not-json");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error,
                  "error decoding json response body: invalid character 'o' looking for beginning of value"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(400, "[]");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && strstr(out.items[0].verification_error, "sendbird.userResp"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(500, "{\"code\":1}");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&out);
    char noisy[80];
    snprintf(noisy, sizeof(noisy), "bad %s", key);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = noisy;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "bad [REDACTED]"));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    http.send_rc = 0;
    http.send_error = NULL;
    http.response = body_status(400, "null");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "unexpected response code: 0"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(400, "{\"code\":400401,\"code\":null}");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = body_status(400, "{\"code\":400100,\"code\":null}");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "unexpected response code: 400100"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    sb_type_calls = 0;
    sb_type_null = 1;
    http.response = body_status(400, "{\"code\":true}");
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    sb_type_null = 0;
    http.calls = http.releases = 0;
    http.response = body_status(400, "{\"code\":true}");
    sb_doc_rc = 2;
    br_results fatal = {0};
    char *scan_error = NULL;
    br_slice bytes = {(const unsigned char *)input, strlen(input)};
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode Sendbird response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    sb_doc_rc = 0;
    sb_visit_rc = 1;
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode Sendbird response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    sb_visit_rc = 0;
    sb_type_calls = 0;
    sb_type_fatal_after = 2;
    http.response = body_status(400, "{\"code\":true,\"code\":false}");
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode Sendbird response") && !fatal.len);
    CHECK(sb_type_calls >= 2);
    free(scan_error);
    br_results_clear(&fatal);
    for (int code = 1; code <= 2; ++code) {
        sb_type_calls = 0;
        sb_type_fatal_after = 2;
        sb_type_fatal_rc = code;
        scan_error = NULL;
        CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
        CHECK(scan_error && !strcmp(scan_error, "cannot decode Sendbird response") && !fatal.len);
        CHECK(sb_type_calls >= 2);
        free(scan_error);
        br_results_clear(&fatal);
    }
    sb_type_fatal_after = 0;
    sb_type_fatal_rc = 0;
    return test_finish("Sendbird");
}
