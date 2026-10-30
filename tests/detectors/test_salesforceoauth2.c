/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/json.h"

static int force_doc;
static int (*real_document)(br_slice, br_json **, char **) = br_json_document;
static int doc_hook(br_slice body, br_json **out, char **cause)
{
    if (force_doc) { *out = NULL; *cause = NULL; return force_doc; }
    return real_document(body, out, cause);
}
#define br_json_document doc_hook
#include "../../src/detectors/salesforceoauth2.c"
#undef br_json_document

static char key[90];
static char secret[65];
static int calls;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    calls++;
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(strstr(request->url, "/services/oauth2/token"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(request->body.len > 10 && !memcmp(request->body.data, "client_id=", 10));
    CHECK(request->body.data && strstr((const char *)request->body.data, "grant_type=client_credentials"));
    (void)http;
}

static void fill(char *input, size_t cap, const char *host)
{
    snprintf(input, cap, "salesforce %s %s secret %s", host, key, secret);
}

int main(void)
{
    memcpy(key, "3MVG9", 5);
    memset(key + 5, 'A', 80);
    key[85] = 0;
    memset(secret, 'b', 64);
    secret[64] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_salesforceoauth2_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 47 && detector->max_credential_span == -1);
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "salesforce"));
    char input[320];
    fill(input, sizeof(input), "org.my.salesforce.com");
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(results.items[0].raw.len == 64);
    CHECK(results.items[0].raw_v2.len == strlen("org.my.salesforce.com") + 1 + 85 + 1 + 64);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "unexpected status code: 401"));
    br_results_clear(&results);
    static const char client_body[] = "{\"error\":\"invalid_client_id\",\"error_description\":\"no\"}";
    http.response.status = 400;
    http.response.body = (br_slice){(const unsigned char *)client_body, sizeof(client_body) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    static const char grant_body[] = "{\"error\":\"invalid_grant\",\"error_description\":\"bad secret\"}";
    http.response.body = (br_slice){(const unsigned char *)grant_body, sizeof(grant_body) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "verification failed: bad secret"));
    br_results_clear(&results);
    fill(input, sizeof(input), "fresh.my.salesforce.com");
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    fill(input, sizeof(input), "folded.my.salesforce.com");
    static const char folded[] = "{\"Error\":\"invalid_grant\",\"Error_Description\":\"folded desc\"}";
    http.send_rc = 0;
    http.send_error = NULL;
    http.response.status = 400;
    http.response.body = (br_slice){(const unsigned char *)folded, sizeof(folded) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "verification failed: folded desc"));
    br_results_clear(&results);
    static const char last[] = "{\"error\":\"invalid_client\",\"error\":\"invalid_grant\",\"error_description\":\"b\"}";
    http.response.body = (br_slice){(const unsigned char *)last, sizeof(last) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "verification failed: b"));
    br_results_clear(&results);
    static const char typed[] = "{\"error\":1,\"error_description\":\"still visited\"}";
    http.response.body = (br_slice){(const unsigned char *)typed, sizeof(typed) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "oauthErrorResponse.error"));
    CHECK(!strstr(results.items[0].verification_error, "failed to unmarshal"));
    br_results_clear(&results);
    static const char syntax[] = "{";
    http.response.body = (br_slice){(const unsigned char *)syntax, 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected end of JSON input"));
    br_results_clear(&results);
    fill(input, sizeof(input), "transport.my.salesforce.com");
    http.response.status = 0;
    http.response.body = (br_slice){0};
    http.send_rc = 1;
    http.send_error = "dial tcp: refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "dial tcp: refused"));
    br_results_clear(&results);
    fill(input, sizeof(input), "nul.my.salesforce.com");
    http.send_rc = 0;
    http.send_error = NULL;
    http.response.status = 400;
    static const char nul_client[] = "{\"error\":\"invalid_client\\u0000X\",\"error_description\":\"no\"}";
    http.response.body = (br_slice){(const unsigned char *)nul_client, sizeof(nul_client) - 1};
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len && scan_error && strstr(scan_error, "not representable"));
    free(scan_error);
    br_results_clear(&failed);
    static const char nul_desc[] = "{\"error\":\"invalid_grant\",\"error_description\":\"bad\\u0000secret\"}";
    http.response.body = (br_slice){(const unsigned char *)nul_desc, sizeof(nul_desc) - 1};
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len && scan_error && strstr(scan_error, "not representable"));
    free(scan_error);
    br_results_clear(&failed);
    static const char quiet_desc[] = "{\"error\":\"invalid_client\",\"error_description\":\"no\\u0000pe\"}";
    http.response.body = (br_slice){(const unsigned char *)quiet_desc, sizeof(quiet_desc) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    force_doc = 1;
    http.send_rc = 0;
    http.send_error = NULL;
    http.response.status = 400;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verification_error);
    br_results_clear(&results);
    force_doc = 2;
    scan_error = NULL;
    failed = (br_results){0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    force_doc = 0;
    fill(input, sizeof(input), "missing.my.salesforce.com");
    http.send_rc = 1;
    http.send_error = "dial tcp: lookup missing.my.salesforce.com: no such host";
    int before = calls;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && calls == before + 1);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && calls == before + 1);
    br_results_clear(&results);
    return test_finish("SalesforceOauth2");
}
