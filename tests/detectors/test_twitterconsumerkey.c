/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int tw_doc_rc;
static int tw_visit_rc;
static int tw_type_null;
static int tw_type_fatal_after;
static int tw_type_fatal_rc;
static int tw_type_calls;

int br_twitterconsumerkey_json_document(br_slice body, const char *read_error, br_json **out,
                                        size_t *end, char **cause)
{
    if (tw_doc_rc) {
        if (out) *out = NULL;
        if (end) *end = 0;
        if (cause) *cause = NULL;
        return tw_doc_rc;
    }
    return br_json_first_document(body, read_error, out, end, cause);
}

int br_twitterconsumerkey_each_member(br_slice object, br_json_member_fn callback, void *user)
{
    int rc = br_json_each_member(object, callback, user);
    return tw_visit_rc && rc == 0 ? tw_visit_rc : rc;
}

int br_twitterconsumerkey_type_cause(br_json *value, const char *field, char **cause)
{
    ++tw_type_calls;
    if (tw_type_fatal_after && tw_type_calls >= tw_type_fatal_after) {
        if (cause) *cause = NULL;
        return tw_type_fatal_rc ? tw_type_fatal_rc : -1;
    }
    if (tw_type_null) {
        if (cause) *cause = NULL;
        return 0;
    }
    return br_json_type_cause(value, field, "string", cause);
}

int br_twitterconsumerkey_init(const br_detector **out, char **error);

static char key[26], secret[51];
static int token_status, verify_status;
static const char *access_token;
static const char *token_json;
static int calls;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    memset(key, 'A', 25);
    key[25] = '\0';
    memset(secret, 'B', 50);
    secret[50] = '\0';
    CHECK(br_twitterconsumerkey_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_twitterconsumerkey_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 989 && !strcmp(detector->name, "TwitterConsumerkey"));
    CHECK(!strcmp(detector->description,
                  "Twitter Consumer Keys and Secrets are used to authenticate API requests to Twitter. They allow access to Twitter's API to manage user data and perform actions on behalf of users."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "twitter"));
    CHECK(detector->max_credential_span == 1024);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "key %s secret %s", key, secret);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].detector_type == 989);
    CHECK(results.items[0].raw.len == 25 && !memcmp(results.items[0].raw.data, key, 25));
    CHECK(results.items[0].raw_v2.len == 75 &&
          !memcmp(results.items[0].raw_v2.data, key, 25) &&
          !memcmp(results.items[0].raw_v2.data + 25, secret, 50));
    CHECK(!results.items[0].extra_data && !results.items[0].verification_error);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "secret %s", secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    if (calls == 0) {
        CHECK(!strcmp(request->method, "POST"));
        CHECK(!strcmp(request->url, "https://api.twitter.com/oauth2/token"));
        CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
        CHECK(request->body.len == 29 &&
              !memcmp(request->body.data, "grant_type=client_credentials", 29));
        CHECK(request->nheaders == 3);
        CHECK(!strcmp(request->headers[0].name, "Authorization"));
        CHECK(!strncmp(request->headers[0].value, "Basic ", 6));
        CHECK(!strcmp(request->headers[1].name, "Content-Type"));
        CHECK(!strcmp(request->headers[1].value, "application/x-www-form-urlencoded;charset=UTF-8"));
        http->response.status = token_status;
        if (token_status == 200 && token_json) {
            http->response.body = (br_slice){(const unsigned char *)token_json, strlen(token_json)};
        } else if (token_status == 200 && access_token) {
            char body[128];
            snprintf(body, sizeof(body), "{\"token_type\":\"bearer\",\"access_token\":\"%s\"}", access_token);
            http->response.body = (br_slice){(const unsigned char *)strdup(body), strlen(body)};
        }
    } else {
        CHECK(!strcmp(request->method, "GET"));
        CHECK(!strcmp(request->url, "https://api.twitter.com/2/tweets/20"));
        CHECK(request->nheaders == 2);
        CHECK(!strcmp(request->headers[0].name, "Authorization"));
        CHECK(!strncmp(request->headers[0].value, "Bearer ", 7));
        CHECK(!strcmp(request->headers[0].value + 7, access_token));
        http->response.status = verify_status;
    }
    ++calls;
}

static void verification(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "twitter key %s secret %s", key, secret);
    token_status = 200;
    verify_status = 200;
    access_token = "token-value";
    calls = 0;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && calls == 2);
    br_results_clear(&results);
    verify_status = 403;
    calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && calls == 2);
    br_results_clear(&results);
    verify_status = 401;
    calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    token_status = 400;
    calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && calls == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unexpected HTTP response status 400"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "nil Context"));
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    token_status = 200;
    verify_status = 200;
    access_token = "token-value";
    token_json = NULL;
    calls = 0;
    tw_doc_rc = 2;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[160];
    snprintf(input, sizeof(input), "twitter key %s secret %s", key, secret);
    br_results fatal = {0};
    char *scan_error = NULL;
    br_slice bytes = {(const unsigned char *)input, strlen(input)};
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode TwitterConsumerkey token") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    tw_doc_rc = 0;
    tw_visit_rc = 1;
    token_json = "{\"access_token\":1}";
    calls = 0;
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode TwitterConsumerkey token") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    tw_visit_rc = 0;
    br_results results = {0};
    token_json = "{\"access_token\":\"kept-token\",\"access_token\":null}";
    access_token = "kept-token";
    token_status = 200;
    verify_status = 200;
    calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && calls == 2);
    br_results_clear(&results);
    token_json = "{\"access_token\":\"ab\\u0000cd\"}";
    calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && calls == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unsupported: Twitter access token contains NUL"));
    br_results_clear(&results);
    tw_type_calls = 0;
    tw_type_null = 1;
    token_json = "{\"access_token\":1}";
    calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && calls == 1 && !results.items[0].verified &&
          !results.items[0].verification_error);
    br_results_clear(&results);
    tw_type_null = 0;
    tw_type_calls = 0;
    tw_type_fatal_after = 2;
    token_json = "{\"token_type\":1,\"access_token\":1}";
    calls = 0;
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot decode TwitterConsumerkey token") && !fatal.len);
    CHECK(tw_type_calls >= 2);
    free(scan_error);
    br_results_clear(&fatal);
    for (int code = 1; code <= 2; ++code) {
        tw_type_calls = 0;
        tw_type_fatal_after = 2;
        tw_type_fatal_rc = code;
        calls = 0;
        scan_error = NULL;
        CHECK(detector->scan(detector, &ctx, true, bytes, &fatal, &scan_error) != 0);
        CHECK(scan_error && !strcmp(scan_error, "cannot decode TwitterConsumerkey token") && !fatal.len);
        CHECK(tw_type_calls >= 2);
        free(scan_error);
        br_results_clear(&fatal);
    }
    tw_type_fatal_after = 0;
    tw_type_fatal_rc = 0;
    token_json = NULL;
    return test_finish("twitterconsumerkey");
}
