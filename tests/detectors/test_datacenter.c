/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/datacenter.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static char token[45];

static void structural(void)
{
    unsigned char raw[33];
    memcpy(raw, "123456789012:abcdefghijklmnopqrst", sizeof(raw));
    CHECK(EVP_EncodeBlock((unsigned char *)token, raw, sizeof(raw)) == 44);
    CHECK(br_dc_is_structural_pat44((br_slice){(unsigned char *)token, 44}));
    raw[13] = 0; /* Random bytes need not be text. */
    char encoded[45];
    CHECK(EVP_EncodeBlock((unsigned char *)encoded, raw, sizeof(raw)) == 44);
    CHECK(br_dc_is_structural_pat44((br_slice){(unsigned char *)encoded, 44}));
    memset(raw, '7', sizeof(raw)); raw[1] = ':';
    CHECK(EVP_EncodeBlock((unsigned char *)encoded, raw, sizeof(raw)) == 44);
    CHECK(br_dc_is_structural_pat44((br_slice){(unsigned char *)encoded, 44}));
    for (size_t colon = 0; colon < 33; colon += 32) {
        memset(raw, '7', sizeof(raw)); raw[colon] = ':';
        CHECK(EVP_EncodeBlock((unsigned char *)encoded, raw, sizeof(raw)) == 44);
        CHECK(!br_dc_is_structural_pat44((br_slice){(unsigned char *)encoded, 44}));
    }
    memset(raw, '7', sizeof(raw)); raw[0] = 'x'; raw[3] = ':';
    CHECK(EVP_EncodeBlock((unsigned char *)encoded, raw, sizeof(raw)) == 44);
    CHECK(!br_dc_is_structural_pat44((br_slice){(unsigned char *)encoded, 44}));
    CHECK(!br_dc_is_structural_pat44((br_slice){(unsigned char *)token, 43}));
    encoded[3] = '=';
    CHECK(!br_dc_is_structural_pat44((br_slice){(unsigned char *)encoded, 44}));
}

static void patterns_and_endpoints(void)
{
    const char *const prefixes[] = {"jira", "atlassian"};
    br_regex *pat = NULL, *url = NULL;
    char *error = NULL, input[512];
    CHECK(br_dc_token_pattern(prefixes, 2, &pat, &error) == 0 && !error);
    CHECK(br_dc_url_pattern(prefixes, 2, &url, &error) == 0 && !error);
    br_captures captures = {0};
    snprintf(input, sizeof(input), "jira %s\n", token);
    CHECK(br_captures_find(pat, (br_slice){(unsigned char *)input, strlen(input)}, &captures, false, &error) == 0 && !error);
    CHECK(captures.len == 1 && !strcmp(captures.items[0], token));
    br_captures_clear(&captures);
    snprintf(input, sizeof(input), "jira %s=", token);
    CHECK(br_captures_find(pat, (br_slice){(unsigned char *)input, strlen(input)}, &captures, false, &error) == 0 && !error && !captures.len);
    br_captures_clear(&captures);
    strcpy(input, "jira https://jira.invalid:8443/path?old=1\natlassian https://jira.invalid:8443/\nplain https://ignored.invalid");
    const char *configured[] = {"https://configured.invalid///", "", "///", "https://configured.invalid"};
    br_endpoints settings = {.configured = configured, .nconfigured = 4, .use_found = true};
    br_endpoint_list endpoints = {0};
    CHECK(br_dc_find_endpoints((br_slice){(unsigned char *)input, strlen(input)}, url, &settings, &endpoints, &error) == 0 && !error);
    CHECK(endpoints.len == 3);
    CHECK(!strcmp(endpoints.items[0], "https://configured.invalid"));
    CHECK(!strcmp(endpoints.items[1], ""));
    CHECK(!strcmp(endpoints.items[2], "https://jira.invalid:8443"));
    br_endpoint_list_clear(&endpoints);
    settings = (br_endpoints){0};
    CHECK(br_dc_find_endpoints((br_slice){(unsigned char *)input, strlen(input)}, url, &settings, &endpoints, &error) == 0 && !error && !endpoints.len);
    br_endpoint_list_clear(&endpoints);
    br_regex_free(pat);
    br_regex_free(url);
}

static void request_urls(void)
{
    const struct { const char *base, *query, *expected; } cases[] = {
        {"https://jira.invalid/old?discard=1", "", "https://jira.invalid/rest/api/2/myself"},
        {"http://user:pass@host.invalid:8080/path?old=1#section", "limit=1", "http://user:pass@host.invalid:8080/rest/api/2/myself?limit=1#section"},
        {"https://jira.invalid/path?#section", "", "https://jira.invalid/rest/api/2/myself?#section"},
        {"https://jira.invalid/path#", "", "https://jira.invalid/rest/api/2/myself"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char *url = NULL, *cause = NULL;
        CHECK(br_dc_request_url(cases[i].base, "/rest/api/2/myself", cases[i].query, &url, &cause) == 0 && url && !cause);
        CHECK(!strcmp(url, cases[i].expected));
        free(url);
    }
    const char *unsupported[] = {"relative/path", "ftp://host.invalid", "https://host.invalid:080/path", "http://127.1/path", "https://host.invalid/old%2Fpath"};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
        char *url = NULL, *cause = NULL;
        CHECK(br_dc_request_url(unsupported[i], "/new", "", &url, &cause) == 1 && !url && cause);
        CHECK(!strncmp(cause, "unsupported:", 12));
        free(cause);
    }
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    (void)http;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://unit.invalid/rest"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->detector_type == 1046);
    CHECK(request->nheaders == 3 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, token));
}

static void verification(void)
{
    const struct { int status; const char *body, *read_error; bool verified, map; const char *cause; } cases[] = {
        {200, "{\"displayName\":\"first\",\"displayName\":null,\"emailAddress\":\"e\"} trailing", NULL, true, true, NULL},
        {200, "not json", NULL, true, false, NULL},
        {200, "[]", NULL, true, false, NULL},
        {200, "null", NULL, true, false, NULL},
        {200, "{", "ignored read failure", true, false, NULL},
        {200, "{}", "ignored after object", true, true, NULL},
        {401, "not json", "ignored", false, false, NULL},
        {403, "{}", "ignored", false, false, "unexpected HTTP response status 403"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status,
            .body = {(unsigned char *)cases[i].body, strlen(cases[i].body)}, .body_error = cases[i].read_error}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        bool verified = false;
        br_json *body = NULL;
        char *cause = NULL;
        CHECK(br_dc_verify(&ctx, BR_HTTP_DETECTOR_PUBLIC, 1046, "https://unit.invalid/rest", token, &verified, &body, &cause) == 0);
        CHECK(verified == cases[i].verified && (body != NULL) == cases[i].map);
        if (cases[i].cause) CHECK(cause && !strcmp(cause, cases[i].cause));
        else CHECK(!cause);
        CHECK(http.calls == 1 && http.releases == 1);
        if (i == 0) {
            br_json *value = NULL;
            CHECK(json_object_object_get_ex(body, "displayName", &value) && !value);
            CHECK(json_object_object_get_ex(body, "emailAddress", &value) && !strcmp(json_object_get_string(value), "e"));
        }
        json_object_put(body);
        free(cause);
    }
    for (size_t i = 0; i < 2; ++i) {
        test_http http = {.send_rc = 1, .send_error = i ? NULL : "fixture: no such host", .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        bool verified = true;
        br_json *body = NULL;
        char *cause = NULL;
        CHECK(br_dc_verify(&ctx, BR_HTTP_DETECTOR_PUBLIC, 1046, "https://unit.invalid/rest", token, &verified, &body, &cause) == 0);
        CHECK(!verified && !body && cause);
        CHECK(!strcmp(cause, i ? "HTTP transport failed" : "fixture: no such host"));
        CHECK(http.calls == 1 && http.releases == 1);
        free(cause);
    }
}

int main(void)
{
    structural();
    patterns_and_endpoints();
    request_urls();
    verification();
    return test_finish("Data Center patterns, endpoints and shared HTTP");
}
