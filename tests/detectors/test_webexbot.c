/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/json.h"

extern int br_webexbot_init(const br_detector **, char **);

static int wx_doc_rc;
static int wx_visit_rc;

int br_webexbot_json_document(br_slice body, const char *read_error, br_json **out, size_t *end,
                              char **cause)
{
    if (wx_doc_rc) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return wx_doc_rc;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

int br_webexbot_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    int rc = br_json_each_member(object, callback, user);
    return wx_visit_rc && rc == 0 ? wx_visit_rc : rc;
}

static char key[128];

static void build(void)
{
    memset(key, 'a', 64);
    key[64] = '_';
    memset(key + 65, 'b', 4);
    key[69] = '_';
    memcpy(key + 70, "ccccccc1-dddd-eeee-ffff-0123456789ab", 36);
    key[106] = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char authorization[160];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(!strcmp(request->url, "https://webexapis.com/v1/people/me"));
    CHECK(request->nheaders == 4 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].value, authorization));
    CHECK(!strcmp(request->headers[3].value, "TruffleHog"));
}

static const char *extra(const br_result *result, const char *name)
{
    br_json *item = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &item)) return NULL;
    return json_object_get_string(item);
}

int main(void)
{
    build();
    CHECK(strlen(key) == 106);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_webexbot_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1033 && detector->nkeywords == 2 && !strcmp(detector->keywords[0], "spark"));
    char input[256];
    snprintf(input, sizeof(input), "%s %s", key, key);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    CHECK(results.items[0].redacted && !strcmp(results.items[0].redacted, "aaaaa..."));
    CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 0);
    br_results_clear(&results);
    const char *body = "{\"type\":\"bot\",\"username\":\"ada\",\"emails\":[\"a@b.c\"]}";
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(!strcmp(extra(&results.items[0], "type"), "bot") && !strcmp(extra(&results.items[0], "username"), "ada"));
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data &&
          !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{", 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data &&
          results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected EOF"));
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"", 0};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data &&
          results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "EOF"));
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"null", 4};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error &&
          extra(&results.items[0], "type") && !extra(&results.items[0], "type")[0] &&
          extra(&results.items[0], "username") && !extra(&results.items[0], "username")[0]);
    br_results_clear(&results);
    const char *folded = "{\"TYPE\":\"bot\",\"UserName\":\"Ada\",\"EMAILS\":[null,\"a@b.c\"]}";
    http.response.body = (br_slice){(const unsigned char *)folded, strlen(folded)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(!strcmp(extra(&results.items[0], "type"), "bot") &&
          !strcmp(extra(&results.items[0], "username"), "Ada"));
    br_results_clear(&results);
    const char *nul_profile = "{\"type\":\"bot\\u0000suffix\",\"username\":\"ada\\u0000x\"}";
    http.response.body = (br_slice){(const unsigned char *)nul_profile, strlen(nul_profile)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_json *type_item = NULL, *user_item = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "type", &type_item));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "username", &user_item));
    CHECK(json_object_get_string_len(type_item) == 10 &&
          !memcmp(json_object_get_string(type_item), "bot\0suffix", 10));
    CHECK(json_object_get_string_len(user_item) == 5 &&
          !memcmp(json_object_get_string(user_item), "ada\0x", 5));
    br_results_clear(&results);
    const char *duplicate = "{\"type\":1,\"type\":\"bot\"}";
    http.response.body = (br_slice){(const unsigned char *)duplicate, strlen(duplicate)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data &&
          results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "response.type") &&
          strstr(results.items[0].verification_error, "number"));
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    wx_doc_rc = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    wx_doc_rc = 2;
    char *scan_error = NULL;
    br_results fatal = {0};
    br_slice bytes = {(const unsigned char *)input, strlen(input)};
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode WebexBot response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    wx_doc_rc = 0;
    wx_visit_rc = 1;
    const char *typed = "{\"type\":1}";
    http.response.body = (br_slice){(const unsigned char *)typed, strlen(typed)};
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot visit WebexBot response") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    wx_visit_rc = 0;
    scan_error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &scan_error) == 0 && results.len == 1 && !scan_error);
    CHECK(strstr(results.items[0].verification_error, "nil Context"));
    br_results_clear(&results);
    printf("webexbot: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
