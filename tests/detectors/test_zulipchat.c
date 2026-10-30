/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int zu_doc_rc;
static int zu_visit_rc;
static int zu_type_null;
static int zu_type_calls;
static int zu_type_fatal_after;
static int zu_type_fatal_rc;
static int zu_element_rc;

int br_zulipchat_json_document(br_slice body, const char *read_error, br_json **out, size_t *end,
                               char **cause)
{
    if (zu_doc_rc) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return zu_doc_rc;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

int br_zulipchat_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    int rc = br_json_each_member(object, callback, user);
    return zu_visit_rc && rc == 0 ? zu_visit_rc : rc;
}

int br_zulipchat_type_cause(br_json *value, const char *field, const char *expected, char **cause)
{
    ++zu_type_calls;
    if (zu_type_fatal_after && zu_type_calls >= zu_type_fatal_after) {
        if (cause) *cause = NULL;
        return zu_type_fatal_rc ? zu_type_fatal_rc : -1;
    }
    if (zu_type_null) {
        if (cause) *cause = NULL;
        return 0;
    }
    return br_json_type_cause(value, field, expected, cause);
}

int br_zulipchat_each_element(br_slice array, br_json_element_fn callback, void *user)
{
    if (zu_element_rc) return zu_element_rc;
    return br_json_each_element(array, callback, user);
}

int br_zulipchat_init(const br_detector **out, char **error);

static const char key[] = "zwoltpBbfT4QjuNst0Gms4TXnK4rMMKX";
static const char id[] = "aE5f.L1CIrn4WwIq_YB1DsB-E11p_8azu7x@aujstMgjEY5.com";
static const char domain[] = "dwj7s0gr-uedt0sg-ll.zulipchat.com";
static char seen_url[128], seen_auth[160];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && request->detector_type == 811);
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization") && !strncmp(request->headers[2].value, "Basic ", 6));
    snprintf(seen_url, sizeof(seen_url), "%s", request->url);
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[2].value);
}

int main(void)
{
    CHECK(strlen(key) == 32);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zulipchat_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 811 && !strcmp(detector->name, "ZulipChat") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "zulip"));
    CHECK(!strcmp(detector->description, "ZulipChat is a group chat application used for team communication. ZulipChat API keys can be used to access and manage various functionalities of the chat service."));
    char input[256], raw[192];
    snprintf(input, sizeof(input), "%s %s %s %s", key, id, domain, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].raw.len == 32 && !memcmp(out.items[0].raw.data, key, 32));
    snprintf(raw, sizeof(raw), "%s:%s:%s", key, id, domain);
    CHECK(out.items[0].raw_v2.len == strlen(raw) && !memcmp(out.items[0].raw_v2.data, raw, strlen(raw)));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(out.items[0].extra_data, "Domain", &part));
    CHECK(!strcmp(json_object_get_string(part), domain));
    CHECK(json_object_object_get_ex(out.items[0].extra_data, "Id", &part));
    CHECK(!strcmp(json_object_get_string(part), id));
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s Chat.Zulip.Org", key, id);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    CHECK(json_object_object_get_ex(out.items[0].secret_parts, "domain", &part));
    CHECK(!strcmp(json_object_get_string(part), "Chat.Zulip.Org"));
    br_results_clear(&out);
    snprintf(input, sizeof(input), "z?oltpBbfT4QjuNst0Gms4TXnK4rMMKX %s %s", id, domain);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s %s %s", key, id, domain);
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{}", 2}};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(!strcmp(seen_url, "https://dwj7s0gr-uedt0sg-ll.zulipchat.com/api/v1/users"));
    CHECK(!strcmp(seen_auth, "Basic YUU1Zi5MMUNJcm40V3dJcV9ZQjFEc0ItRTExcF84YXp1N3hAYXVqc3RNZ2pFWTUuY29tOnp3b2x0cEJiZlQ0UWp1TnN0MEdtczRUWG5LNHJNTUtY"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"not-json", 8}};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{\"result\":1}", 12}};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 401};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 500};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&out);
    http.calls = 0;
    http.send_rc = 1;
    http.send_error = "down zwoltpBbfT4QjuNst0Gms4TXnK4rMMKX";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "down zwoltpBbfT4QjuNst0Gms4TXnK4rMMKX"));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
    http.send_rc = 0;
    http.send_error = NULL;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"null", 4}};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    {
        const char *accepted =
            "{\"result\":null,\"members\":[null,{\"full_name\":null,\"email\":null}]}";
        http.response = (br_http_response){
            .status = 200, .body = {(const unsigned char *)accepted, strlen(accepted)}};
    }
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    zu_type_null = 1;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{\"result\":1}", 12}};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    zu_type_null = 0;
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{}", 2}};
    zu_doc_rc = 2;
    br_results fatal = {0};
    char *scan_error = NULL;
    br_slice bytes = {(const unsigned char *)input, strlen(input)};
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode ZulipChat users") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    zu_doc_rc = 0;
    zu_visit_rc = 1;
    http.response.body = (br_slice){(const unsigned char *)"{\"result\":1}", 12};
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode ZulipChat users") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    zu_visit_rc = 0;
    zu_element_rc = -1;
    {
        const char *later = "{\"result\":1,\"members\":[{}]}";
        http.response.body = (br_slice){(const unsigned char *)later, strlen(later)};
    }
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode ZulipChat users") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    zu_element_rc = 0;
    {
        const char *later_type = "{\"result\":1,\"result\":false}";
        http.response.body = (br_slice){(const unsigned char *)later_type, strlen(later_type)};
    }
    for (int code = 1; code <= 2; ++code) {
        zu_type_calls = 0;
        zu_type_fatal_after = 2;
        zu_type_fatal_rc = code;
        scan_error = NULL;
        CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
        CHECK(scan_error && !strcmp(scan_error, "cannot decode ZulipChat users") && !fatal.len);
        CHECK(zu_type_calls >= 2);
        free(scan_error);
        br_results_clear(&fatal);
    }
    zu_type_fatal_after = 0;
    zu_type_fatal_rc = 0;
    return test_finish("ZulipChat");
}
