/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int force_doc;
static int sf_type_mode;
static int (*real_document)(br_slice, br_json **, char **) = br_json_document;
static int (*real_type)(br_json *, const char *, const char *, char **) = br_json_type_cause;
static int doc_hook(br_slice body, br_json **out, char **cause)
{
    if (force_doc) { *out = NULL; *cause = NULL; return force_doc; }
    return real_document(body, out, cause);
}
static int type_hook(br_json *value, const char *field, const char *expected, char **cause)
{
    if (sf_type_mode == 1) { if (cause) *cause = NULL; return 0; }
    if (sf_type_mode == 2) return 1;
    return real_type(value, field, expected, cause);
}
#define br_json_document doc_hook
#define br_json_type_cause type_hook
#include "../../src/detectors/salesforcerefreshtoken.c"
#undef br_json_document
#undef br_json_type_cause

static const char token[] = "5Aep861eN26Sp9j0R5QPjh0AAAABBBBCCCCjcNqfo5kVBplkpP5tzyWXyVGAivx26AAAABBBBjYE133BBBBAAAA";
static const char key[] = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7";
static const char secret[] = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char body[320];
    snprintf(body, sizeof(body), "client_id=%s&client_secret=%s&token=%s", key, secret, token);
    CHECK(ctx && !strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !strcmp(request->url, "https://login.salesforce.com/services/oauth2/introspect"));
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_salesforcerefreshtoken_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 1031 && !strcmp(detector->name, "SalesforceRefreshToken"));
    CHECK(detector->nkeywords == 3 && !strcmp(detector->keywords[0], "salesforce"));
    CHECK(!strcmp(detector->keywords[1], "5AEP861") && !strcmp(detector->keywords[2], "3MVG9"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Salesforce is a customer relationship management (CRM) platform that provides a suite of applications and APIs. OAuth 2.0 refresh tokens are long-lived credentials that allow applications to obtain new access tokens without requiring user interaction. They enable continuous access to an organization's data and must be handled securely."));
    return detector;
}

static void check_parts(const br_result *result)
{
    char joined[256];
    snprintf(joined, sizeof(joined), "%s:%s:%s", token, key, secret);
    CHECK(result->detector_type == 1031 && result->raw.len == strlen(token) && !memcmp(result->raw.data, token, strlen(token)));
    CHECK(result->raw_v2.len == strlen(joined) && !memcmp(result->raw_v2.data, joined, strlen(joined)));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "refresh_token", &part) && !strcmp(json_object_get_string(part), token));
    CHECK(json_object_object_get_ex(result->secret_parts, "consumer_key", &part) && !strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_get_ex(result->secret_parts, "consumer_secret", &part) && !strcmp(json_object_get_string(part), secret));
}

int main(void)
{
    CHECK(strlen(token) == 87 && strlen(key) == 85 && strlen(secret) == 64);
    const br_detector *detector = descriptor();
    char input[512];
    snprintf(input, sizeof(input),
             "salesforce_refresh_token = \"%s\" salesforce_key = \"%s\" salesforce_secret = \"%s\"",
             token, key, secret);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_parts(&results.items[0]);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "salesforce %s %s", token, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s %s salesforce %s", token, key, secret);
    const char active[] = "{\"active\":true}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)active, sizeof(active) - 1}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);
    const char inactive[] = "{\"active\":false}";
    http.response.body = (br_slice){(const unsigned char *)inactive, sizeof(inactive) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response = (br_http_response){.status = 400};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unauthorized: invalid client credentials"));
    br_results_clear(&results);
    http.response.status = 500;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);
    const char bad[] = "{";
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)bad, 1}};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "failed to unmarshal error response:"));
    CHECK(strstr(results.items[0].verification_error, "(body: {"));
    br_results_clear(&results);
    char echoed[96];
    snprintf(echoed, sizeof(echoed), "dial %s", secret);
    http.send_rc = -1;
    http.send_error = echoed;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "failed to perform request:"));
    CHECK(strstr(results.items[0].verification_error, "[REDACTED]") && !strstr(results.items[0].verification_error, secret));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "failed to create request: net/http: nil Context"));
    br_results_clear(&results);
    force_doc = 2;
    http.send_rc = 0; http.send_error = NULL;
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    http.response.body_error = NULL;
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);

    force_doc = 0;
    http.send_rc = 0; http.send_error = NULL;
    const char overwritten[] = "{\"active\":1,\"active\":\"no\"}";
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)overwritten, sizeof(overwritten) - 1}};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "cannot unmarshal number") &&
          !strstr(results.items[0].verification_error, "cannot unmarshal string") &&
          strstr(results.items[0].verification_error, "failed to unmarshal error response:") &&
          strstr(results.items[0].verification_error, "(body: "));
    br_results_clear(&results);

    sf_type_mode = 1;
    const char kept_active[] = "{\"active\":true,\"active\":1}";
    http.response.body = (br_slice){(const unsigned char *)kept_active, sizeof(kept_active) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    sf_type_mode = 0;

    sf_type_mode = 2;
    http.response.body = (br_slice){(const unsigned char *)"{\"active\":1}", 12};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &scan_error) != 0);
    CHECK(kept.len == 1 && kept.items[0].detector_type == 9);
    free(scan_error);
    br_results_clear(&kept);
    br_result_clear(&prior);
    return test_finish("SalesforceRefreshToken");
}
