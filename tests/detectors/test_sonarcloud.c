/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

int br_sonarcloud_v1_init(const br_detector **out, char **error);
int br_sonarcloud_v2_init(const br_detector **out, char **error);

static const char v1_key[] = "hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye";
static const char v2_key[] = "sqco_FbT1v5HrMX6qyKUkaoLQdYOniAVhbEccERraQABuhBayDOkyCZTa8TDQFRp";
static const char v2_invalid[] = "sqco_FbT1v5HrMX6qyKUkaoLQdYOniAVhbEccERraQABuhBayDOkyCZTa8TDQF==";
static const char v1_url[] = "https://sonarcloud.io/api/authentication/validate";
static const char v2_url[] =
    "https://sonarcloud.io/api/projects/search?organization=nonexistent-org-9f2a7c4e1b8d4a6f";

static int fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char *copy = malloc((size_t)len + 1);
    CHECK(copy);
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    struct json_object *object = json_object_new_string(copy);
    free(copy);
    return object;
}

static void expect_error(const br_result *result, const char *want)
{
    CHECK(result->verification_error);
    if (strcmp(result->verification_error, want)) {
        fprintf(stderr, "verification error\n got: %s\nwant: %s\n", result->verification_error, want);
        CHECK(0);
    }
}

static void expect_version(const br_result *result, const char *want)
{
    struct json_object *version = NULL;
    CHECK(result->extra_data);
    CHECK(json_object_object_get_ex(result->extra_data, "version", &version));
    CHECK(json_object_get_string(version) && !strcmp(json_object_get_string(version), want));
    CHECK(json_object_object_length(result->extra_data) == 1);
}

static void expect_raw(const br_result *result, const char *key)
{
    CHECK(result->raw.len == strlen(key));
    CHECK(!memcmp(result->raw.data, key, result->raw.len));
    CHECK(result->detector_type == 767);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
}

static void scan_text(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      const char *text, br_results *out)
{
    char *error = NULL;
    br_slice input = {(const unsigned char *)text, strlen(text)};
    CHECK(detector->scan(detector, ctx, verify, input, out, &error) == 0);
    CHECK(!error);
}

static void identity(const br_detector *detector, int version, const char *keyword)
{
    CHECK(detector->type == 767 && detector->version == version);
    CHECK(!strcmp(detector->name, "SonarCloud") && !strcmp(detector->custom_name, ""));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], keyword));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == -1 && detector->scan);
    CHECK(strstr(detector->description, "cloud-based code quality"));
}

static void test_v1_extraction(const br_detector *detector)
{
    br_results results = {0};
    scan_text(detector, NULL, false, "sonar token = 'hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye'", &results);
    CHECK(results.len == 1);
    expect_raw(&results.items[0], v1_key);
    expect_version(&results.items[0], "1");
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    scan_text(detector, NULL, false, "SONARCLOUD token = 'hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye'", &results);
    CHECK(results.len == 1);
    br_results_clear(&results);

    char duplicate[160];
    snprintf(duplicate, sizeof(duplicate), "sonar %s | %s", v1_key, v1_key);
    scan_text(detector, NULL, false, duplicate, &results);
    CHECK(results.len == 1);
    br_results_clear(&results);

    char two[192];
    snprintf(two, sizeof(two), "sonar %s sonar %s", v1_key, "abcdefghijklmnopqrstuvwxyz0123456789abcd");
    scan_text(detector, NULL, false, two, &results);
    CHECK(results.len == 2);
    expect_raw(&results.items[0], v1_key);
    expect_raw(&results.items[1], "abcdefghijklmnopqrstuvwxyz0123456789abcd");
    br_results_clear(&results);

    char near[96], far[96];
    memset(near, ' ', 41);
    near[41] = '\0';
    memset(far, ' ', 42);
    far[42] = '\0';
    char input[128];
    snprintf(input, sizeof(input), "sonar%s%s", near, v1_key);
    scan_text(detector, NULL, false, input, &results);
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sonar%s%s", far, v1_key);
    scan_text(detector, NULL, false, input, &results);
    CHECK(results.len == 0);

    scan_text(detector, NULL, false, "sonar @hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye", &results);
    CHECK(results.len == 0);
    scan_text(detector, NULL, false, "hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye", &results);
    CHECK(results.len == 0);
    scan_text(detector, NULL, false, "sonar hxrxxgxt?jxj7ta3dn33c5r5i2h0i6cqjv9kwkye", &results);
    CHECK(results.len == 0);
    scan_text(detector, NULL, false, "sonar HXRXXGXTCJXJ7TA3DN33C5R5I2H0I6CQJV9KWKYE", &results);
    CHECK(results.len == 0);
    scan_text(detector, NULL, false,
              "sonarcloud keyword is not close to the real key in the data\n = 'hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye'",
              &results);
    CHECK(results.len == 0);
}

static void expect_request(const br_http_request *request, const char *url, size_t detector_headers)
{
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 767 && !request->body.len);
    CHECK(request->nheaders == detector_headers + 1);
    CHECK(!strcmp(request->headers[request->nheaders - 1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[request->nheaders - 1].value, "TruffleHog briar-test"));
}

static void inspect_v1(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    expect_request(request, v1_url, 1);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    char *authorization = NULL;
    br_slice key = {(const unsigned char *)v1_key, strlen(v1_key)};
    CHECK(br_http_basic_auth(key, (br_slice){0}, &authorization, NULL) == 0);
    CHECK(!strcmp(request->headers[0].value, authorization));
    free(authorization);
}

static void inspect_v2(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    expect_request(request, v2_url, 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    char want[80];
    snprintf(want, sizeof(want), "Bearer %s", v2_key);
    CHECK(!strcmp(request->headers[1].value, want));
}

static void verify_body(const br_detector *detector, test_http *http, const char *text,
                        const char *body, bool verified, const char *error)
{
    http->response = (br_http_response){.status = 200, .body = {(const unsigned char *)body, body ? strlen(body) : 0}};
    http->calls = http->releases = 0;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "briar-test"};
    br_results results = {0};
    scan_text(detector, &ctx, true, text, &results);
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    CHECK(results.items[0].verified == verified);
    if (error) expect_error(&results.items[0], error);
    else CHECK(!results.items[0].verification_error);
    br_results_clear(&results);
}

static void test_v1_verify(const br_detector *detector)
{
    test_http http = {.inspect = inspect_v1};
    const char *text = "sonar hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye";
    verify_body(detector, &http, text, "{\"valid\":true}", true, NULL);
    verify_body(detector, &http, text, "{\"valid\":false}", false, NULL);
    verify_body(detector, &http, text, "{\"VALID\":true,\"other\":1}", true, NULL);
    verify_body(detector, &http, text, "{\"valid\":true,\"valid\":null}", true, NULL);
    verify_body(detector, &http, text, "null", false, NULL);
    verify_body(detector, &http, text, "{\"valid\":1,\"valid\":false}", false,
                "json: cannot unmarshal number into Go struct field .valid of type bool");
    verify_body(detector, &http, text, "{\"valid\":1,\"valid\":true}", false,
                "json: cannot unmarshal number into Go struct field .valid of type bool");
    verify_body(detector, &http, text, "{\"valid\":1,\"valid\":\"wrong\"}", false,
                "json: cannot unmarshal number into Go struct field .valid of type bool");
    verify_body(detector, &http, text, "[]", false,
                "json: cannot unmarshal array into Go value of type struct { Valid bool \"json:\\\"valid\\\"\" }");
    verify_body(detector, &http, text, "{\"valid\":\"yes\"}", false,
                "json: cannot unmarshal string into Go struct field .valid of type bool");
    verify_body(detector, &http, text, "", false, "unexpected end of JSON input");

    http.response = (br_http_response){.status = 401};
    http.calls = http.releases = 0;
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "briar-test"};
    br_results results = {0};
    scan_text(detector, &ctx, true, text, &results);
    CHECK(results.len == 1 && !results.items[0].verified);
    expect_error(&results.items[0], "unexpected status code: 401");
    expect_version(&results.items[0], "1");
    br_results_clear(&results);

    http.response = (br_http_response){.status = 200, .body_error = "unexpected EOF"};
    scan_text(detector, &ctx, true, text, &results);
    expect_error(&results.items[0], "unexpected EOF");
    CHECK(!results.items[0].verified);
    br_results_clear(&results);

    http.send_rc = 1;
    http.send_error = "dial hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye refused";
    http.calls = 0;
    scan_text(detector, &ctx, true, text, &results);
    expect_error(&results.items[0], "dial [REDACTED] refused");
    br_results_clear(&results);
    http.send_rc = 0;
    http.send_error = NULL;

    http.calls = 0;
    scan_text(detector, NULL, true, text, &results);
    CHECK(results.len == 1 && http.calls == 0 && !results.items[0].verified);
    expect_error(&results.items[0], "net/http: nil Context");
    br_results_clear(&results);

    http.calls = 0;
    scan_text(detector, &ctx, false, text, &results);
    CHECK(results.len == 1 && http.calls == 0 && !results.items[0].verified);
    br_results_clear(&results);
}

static void test_v2(const br_detector *detector)
{
    br_results results = {0};
    char text[160];
    snprintf(text, sizeof(text), "token = '%s'", v2_key);
    scan_text(detector, NULL, false, text, &results);
    CHECK(results.len == 1);
    expect_raw(&results.items[0], v2_key);
    expect_version(&results.items[0], "2");
    br_results_clear(&results);

    snprintf(text, sizeof(text), "token = '%s' | '%s'", v2_key, v2_key);
    scan_text(detector, NULL, false, text, &results);
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(text, sizeof(text), "token = '%s'", v2_invalid);
    scan_text(detector, NULL, false, text, &results);
    CHECK(results.len == 0);
    scan_text(detector, NULL, false, "sqco_not-ascii-or-length", &results);
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect_v2};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "briar-test"};
    int verified_status[] = {200, 403, 404};
    snprintf(text, sizeof(text), "token = '%s'", v2_key);
    for (size_t i = 0; i < sizeof(verified_status) / sizeof(verified_status[0]); ++i) {
        http.response = (br_http_response){.status = verified_status[i]};
        http.calls = http.releases = 0;
        scan_text(detector, &ctx, true, text, &results);
        CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
        expect_version(&results.items[0], "2");
        br_results_clear(&results);
    }
    http.response = (br_http_response){.status = 401};
    scan_text(detector, &ctx, true, text, &results);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response = (br_http_response){.status = 500};
    scan_text(detector, &ctx, true, text, &results);
    CHECK(!results.items[0].verified);
    expect_error(&results.items[0], "unexpected status code: 500");
    br_results_clear(&results);

    http.calls = 0;
    scan_text(detector, NULL, true, text, &results);
    CHECK(results.len == 1 && http.calls == 0);
    expect_error(&results.items[0], "net/http: nil Context");
    br_results_clear(&results);
}

static void test_failure(const br_detector *detector)
{
    br_results results = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "caller", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "briar-test"};
    char *error = NULL;
    const char *text = "sonar hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye";
    br_slice input = {(const unsigned char *)text, strlen(text)};
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(error && http.calls == 0 && results.len == 1);
    CHECK(results.items[0].detector_type == 1);
    free(error);
    br_results_clear(&results);

    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 1}, &results, &error) != 0);
    CHECK(error);
    free(error);
    error = NULL;
    CHECK(br_sonarcloud_v1_init(NULL, &error) != 0 && error);
    free(error);
}

static int sonar_hook_mode, sonar_type_calls;

static int sonar_hook_document(br_slice body, br_json **out, char **cause)
{
    if (sonar_hook_mode == 1) return 2;
    return br_json_document(body, out, cause);
}

static int sonar_hook_visit(br_slice object, br_json_member_fn visit, void *user)
{
    int rc = br_json_each_member(object, visit, user);
    if (!rc && sonar_hook_mode == 2) return 1;
    return rc;
}

static int sonar_hook_type(br_json *value, const char *field, const char *expected, char **cause)
{
    ++sonar_type_calls;
    if (sonar_hook_mode == 3 && sonar_type_calls == 1) {
        if (cause) *cause = NULL;
        return 0;
    }
    if (sonar_hook_mode == 4 && sonar_type_calls == 2) return 1;
    return br_json_type_cause(value, field, expected, cause);
}

#define br_json_document sonar_hook_document
#define br_json_each_member sonar_hook_visit
#define br_json_type_cause sonar_hook_type
#define br_sonarcloud_v1_init sonar_hook_v1
#define br_sonarcloud_v2_init sonar_hook_v2
#define v1_url sonar_file_v1_url
#define v2_url sonar_file_v2_url
#include "../../src/detectors/sonarcloud.c"
#undef br_json_document
#undef br_json_each_member
#undef br_json_type_cause
#undef br_sonarcloud_v1_init
#undef br_sonarcloud_v2_init
#undef v1_url
#undef v2_url

static void sonar_seam(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(sonar_hook_v1(&detector, &error) == 0 && detector && !error);
    const char *text = "sonar hxrxxgxtcjxj7ta3dn33c5r5i2h0i6cqjv9kwkye";
    br_slice input = {(const unsigned char *)text, strlen(text)};
    const char *sticky = "{\"valid\":1,\"valid\":\"wrong\"}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)sticky, strlen(sticky)}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "briar-test"};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);

    sonar_hook_mode = 1;
    br_results results = {0};
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot verify SonarCloud candidate"));
    CHECK(results.len == 1 && results.items[0].detector_type == 9 && !results.items[0].verification_error);
    free(error); error = NULL;
    br_results_clear(&results);

    sonar_hook_mode = 3;
    sonar_type_calls = 0;
    http.response.body = (br_slice){(const unsigned char *)sticky, strlen(sticky)};
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) == 0 && !error);
    CHECK(sonar_type_calls == 2 && results.len == 1 && !results.items[0].verified);
    CHECK(!results.items[0].verification_error);
    br_results_clear(&results);

    sonar_hook_mode = 4;
    sonar_type_calls = 0;
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(sonar_type_calls == 2 && error && results.len == 1);
    CHECK(results.items[0].detector_type == 9);
    free(error); error = NULL;
    br_results_clear(&results);

    sonar_hook_mode = 2;
    sonar_type_calls = 0;
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(sonar_type_calls >= 1 && error && results.len == 1);
    free(error);
    br_results_clear(&results);
    br_result_clear(&prior);
}

int main(void)
{
    const br_detector *v1 = NULL, *v2 = NULL;
    char *error = NULL;
    CHECK(br_sonarcloud_v1_init(&v1, &error) == 0 && v1 && !error);
    CHECK(br_sonarcloud_v1_init(&v1, &error) == 0);
    CHECK(br_sonarcloud_v2_init(&v2, &error) == 0 && v2 && !error);
    identity(v1, 1, "sonar");
    identity(v2, 2, "sqco_");
    test_v1_extraction(v1);
    test_v1_verify(v1);
    test_v2(v2);
    test_failure(v1);
    sonar_seam();
    br_results empty = {0};
    scan_text(v1, NULL, false, "", &empty);
    CHECK(empty.len == 0);
    test_finish("sonarcloud");
}
