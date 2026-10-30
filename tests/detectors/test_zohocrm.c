/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int force_doc;
static int (*real_document)(br_slice, br_json **, char **) = br_json_document;
static int doc_hook(br_slice body, br_json **out, char **cause)
{
    if (force_doc) { *out = NULL; *cause = NULL; return force_doc; }
    return real_document(body, out, cause);
}
#define br_json_document doc_hook
static int later_type;
static int type_calls;
static int (*real_type_cause)(br_json *, const char *, const char *, char **) = br_json_type_cause;
static int type_hook(br_json *value, const char *field, const char *expected, char **cause)
{
    int n = ++type_calls;
    if (later_type && n > 1) { if (cause) *cause = NULL; return 1; }
    return real_type_cause(value, field, expected, cause);
}
#define br_json_type_cause type_hook
#include "../../src/detectors/zohocrm.c"
#undef br_json_type_cause
#undef br_json_document

static const char token[] =
    "1000.0123456789abcdef0123456789abcdef.fedcba9876543210fedcba9876543210";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[88];
    snprintf(authorization, sizeof(authorization), "Zoho-oauthtoken %s", token);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len);
    CHECK(!strcmp(request->url, "https://www.zohoapis.com/crm/v7/Leads?fields=Email&per_page=1"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, authorization));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zohocrm_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1006 && !strcmp(detector->name, "ZohoCRM"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "1000."));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Zoho CRM is a platform for managing sales, marketing, and customer support. Zoho CRM API access tokens allow access to these services through their REST API."));
    return detector;
}

int main(void)
{
    CHECK(strlen(token) == 70);
    const br_detector *detector = descriptor();
    char input[180];
    snprintf(input, sizeof(input), "%s %s", token, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 1006, token, "key");
    br_results_clear(&results);
    const char upper[] = "1000.0123456789ABCDEF0123456789ABCDEF.fedcba9876543210fedcba9876543210";
    results = test_scan(detector, NULL, false, upper, sizeof(upper) - 1);
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "token %s", token);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);
    const char scope[] = "{\"code\":\"OAUTH_SCOPE_MISMATCH\"}";
    http.response = (br_http_response){.status = 401, .body = {(const unsigned char *)scope, sizeof(scope) - 1}};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    const char invalid[] = "{\"code\":\"INVALID_TOKEN\"}";
    http.response.body = (br_slice){(const unsigned char *)invalid, sizeof(invalid) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    const char other[] = "{\"code\":\"OTHER\"}";
    http.response.body = (br_slice){(const unsigned char *)other, sizeof(other) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected error code: OTHER"));
    br_results_clear(&results);
    http.response.body = (br_slice){0};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "failed to parse JSON response: unexpected end of JSON input"));
    br_results_clear(&results);
    http.response.status = 500;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    char echoed[96];
    snprintf(echoed, sizeof(echoed), "dial %s", token);
    http.send_rc = -1;
    http.send_error = echoed;
    http.response.status = 0;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "[REDACTED]"));
    CHECK(!strstr(results.items[0].verification_error, token));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    const char nul_token[] = "{\"code\":\"INVALID_TOKEN\\u0000X\"}";
    http.send_rc = 0; http.send_error = NULL;
    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)nul_token, sizeof(nul_token) - 1};
    http.response.body_error = NULL;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(strstr(results.items[0].verification_error, "unexpected error code: "));
    CHECK(!strstr(results.items[0].verification_error, "failed to parse JSON response:"));
    br_results_clear(&results);
    const char nul_scope[] = "{\"code\":\"OAUTH_SCOPE_MISMATCH\\u0000\"}";
    http.response.body = (br_slice){(const unsigned char *)nul_scope, sizeof(nul_scope) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(strstr(results.items[0].verification_error, "unexpected error code: "));
    br_results_clear(&results);
    later_type = 1;
    type_calls = 0;
    http.send_rc = 0; http.send_error = NULL;
    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)"{\"code\":1,\"code\":true}", 22};
    http.response.body_error = NULL;
    br_results kept_prior = {0};
    br_result prior = {0};
    CHECK(br_finding_key_bytes(&prior, detector->type, (br_slice){(const unsigned char *)"prior", 5}, "key") == 0);
    CHECK(br_results_push(&kept_prior, &prior) == 0);
    br_result_clear(&prior);
    char *scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &kept_prior, &scan_error) != 0);
    CHECK(type_calls == 2 && kept_prior.len == 1 && kept_prior.items[0].raw.len == 5);
    CHECK(!memcmp(kept_prior.items[0].raw.data, "prior", 5));
    free(scan_error);
    br_results_clear(&kept_prior);
    later_type = 0;
    force_doc = 2;
    http.send_rc = 0; http.send_error = NULL;
    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    http.response.body_error = NULL;
    scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("ZohoCRM");
}
