/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_pypi_init(const br_detector **out, char **error);

static const char key[] =
    "pypi-AgEIcHlwaS5vcmcCJDQyM2M0Yjg4LWUyNDnnnnhhMy1hNigyLWI2ZWUyMTMwYzI2MgACKlszLCJhOWQwMWE0MS01Nzk4LTQyOWYtOTk4MS1lYzE5NTJhM2E3YzgiXQAABiBeGtDnnnnnV32VpiyeU-YUDKplSv0E5ngmwsnHaV2jGg";
static int fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char *copy = malloc((size_t)len + 1);
    CHECK(copy);
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static bool contains(br_slice body, const char *needle)
{
    return br_slice_find(body, (br_slice){(const unsigned char *)needle, strlen(needle)}, 0) != SIZE_MAX;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://upload.pypi.org/legacy/"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 998);
    CHECK(request->nheaders == 3 && request->body.len && request->body.data);
    char authorization[192];
    snprintf(authorization, sizeof(authorization), "token %s", key);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strncmp(request->headers[1].value, "multipart/form-data; boundary=", 30));
    CHECK(strlen(request->headers[1].value + 30) == 60);
    CHECK(contains(request->body, request->headers[1].value + 30));
    CHECK(contains(request->body, "name=\":action\"") && contains(request->body, "file_upload"));
    CHECK(contains(request->body, "dummy-package") && contains(request->body, "dummy-content"));
    CHECK(contains(request->body, "\r\n0.0.1\r\n") && contains(request->body, "\r\nsdist\r\n"));
    CHECK(request->body.len >= 4 && !memcmp(request->body.data + request->body.len - 4, "--\r\n", 4));
}

static void expect_error(const br_result *result, const char *want)
{
    CHECK(result->verification_error && !strcmp(result->verification_error, want) && !result->verified);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_pypi_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 998 && !strcmp(detector->name, "PyPI"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pypi-AgEIcHlwaS5vcmcCJ"));
    CHECK(strlen(key) >= 172 && strlen(key) <= 179);
    char input[512];
    snprintf(input, sizeof(input), "pypi_token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 998, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, "pypi-AgEIcHlwaS5vcmcCJ", strlen("pypi-AgEIcHlwaS5vcmcCJ"));
    CHECK(results.len == 0);

    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s", key);
    const char *digest = "Include at least one message digest.";
    http.response = (br_http_response){.status = 400, .body = {(const unsigned char *)digest, strlen(digest)}};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && !results.items[0].extra_data);
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response = (br_http_response){.status = 400, .body = {(const unsigned char *)"no digest", 9}};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_error(&results.items[0], "unexpected HTTP response status 400");
    br_results_clear(&results);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_error(&results.items[0], "unexpected HTTP response status 500");
    br_results_clear(&results);
    char *long_line = malloc(65537);
    CHECK(long_line);
    memset(long_line, 'x', 65537);
    http.response = (br_http_response){.status = 400, .body = {(unsigned char *)long_line, 65537}};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_error(&results.items[0], "bufio.Scanner: token too long");
    br_results_clear(&results);
    free(long_line);
    http.response = (br_http_response){.status = 400, .body_error = "unexpected EOF"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_error(&results.items[0], "unexpected EOF");
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial failed";
    http.response.body_error = NULL;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    expect_error(&results.items[0], "dial failed");
    br_results_clear(&results);
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 0);
    expect_error(&results.items[0], "net/http: nil Context");
    br_results_clear(&results);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
    fail_finding_after = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(error && results.len == 1);
    free(error);
    br_results_clear(&results);
    return test_finish("pypi");
}
