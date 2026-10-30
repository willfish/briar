/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/json.h"

int br_tableau_init(const br_detector **out, char **error);
static void tableau_seam(void);

static const char name[] = "mytoken";
static const char secret[] = "AAAAAAAAAAAAAAAAAAAAAA==:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char host[] = "pod.online.tableau.com";
static const char body[] =
    "{\"credentials\":{\"personalAccessTokenName\":\"mytoken\","
    "\"personalAccessTokenSecret\":\"AAAAAAAAAAAAAAAAAAAAAA==:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"site\":{}}}";

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx;
    test_http *http = user;
    http->calls++;
    if (http->send_rc && error) *error = http->send_error ? strdup(http->send_error) : NULL;
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://pod.online.tableau.com/api/3.26/auth/signin"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1034);
    *response = http->response;
    return http->send_rc;
}

static void release(void *user, br_http_response *response)
{
    ((test_http *)user)->releases++;
    memset(response, 0, sizeof(*response));
}

static void expect_identity(const br_result *result)
{
    char raw_v2[128];
    snprintf(raw_v2, sizeof(raw_v2), "%s:%s:%s", name, secret, host);
    CHECK(result->detector_type == 1034);
    CHECK(result->raw.len == strlen(name) && !memcmp(result->raw.data, name, result->raw.len));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "pat_secret", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    CHECK(json_object_object_get_ex(result->secret_parts, "endpoint", &part));
    CHECK(!strcmp(json_object_get_string(part), host));
}

static void expect_extra(const br_result *result, bool network)
{
    br_json *part = NULL;
    CHECK(result->extra_data);
    CHECK(json_object_object_get_ex(result->extra_data, "verification_endpoint", &part));
    CHECK(!strcmp(json_object_get_string(part), "https://pod.online.tableau.com/api/3.26/auth/signin"));
    CHECK(json_object_object_get_ex(result->extra_data, "verification_method", &part));
    CHECK(!strcmp(json_object_get_string(part), "tableau_pat_auth"));
    CHECK(json_object_object_get_ex(result->extra_data, "tableau_endpoint", &part));
    CHECK(!strcmp(json_object_get_string(part), host));
    bool has_network = json_object_object_get_ex(result->extra_data, "network_error", &part);
    CHECK(has_network == network);
    if (network) CHECK(!strcmp(json_object_get_string(part), "true"));
}

int main(void)
{
    const br_detector *d = NULL;
    char *error = NULL;
    CHECK(br_tableau_init(&d, NULL) == 0);
    CHECK(d->type == 1034 && !strcmp(d->name, "TableauPersonalAccessToken"));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[1], "online.tableau.com") &&
          d->max_credential_span == 1024);
    CHECK(d->validate_endpoints && !d->cloud_endpoint[0]);
    const char *none[] = {0};
    CHECK(d->validate_endpoints(&(br_endpoints){.configured = none, .nconfigured = 0}, &error) != 0 && error);
    free(error);
    char text[256];
    snprintf(text, sizeof(text), "tableau company tableau %s %s %s", name, secret, host);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1);
    expect_identity(&results.items[0]);
    CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 0);
    br_results_clear(&results);
    snprintf(text, sizeof(text), "tableau %s", name);
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(text, sizeof(text), "tableau %s %s %s", name, secret, host);
    const char *ok = "{}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)ok, 2}}};
    br_transport transport = {.user = &http, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    expect_extra(&results.items[0], false);
    br_results_clear(&results);
    const char *typed = "{\"credentials\":{\"token\":1}}";
    http = (test_http){.response = {.status = 200, .body = {(const unsigned char *)typed, strlen(typed)}}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error,
                  "json: cannot unmarshal number into Go struct field .credentials.token of type string"));
    expect_extra(&results.items[0], false);
    br_results_clear(&results);
    const char *goldens[] = {
        "{\"credentials\":{\"site\":{\"id\":1,\"contentUrl\":false},\"token\":2}}",
        "{\"credentials\":{\"site\":{\"id\":1,\"id\":\"later\"}}}",
        "{\"CREDENTIALS\":{\"SITE\":{\"ID\":false}}}",
        "{\"credentials\":{\"site\":{\"contentUrl\":5}}}",
        "{\"credentials\":{\"user\":{\"id\":false}}}",
        "{\"credentials\":[],\"credentials\":{\"token\":5}}",
    };
    const char *golden_errors[] = {
        "json: cannot unmarshal number into Go struct field .credentials.site.id of type string",
        "json: cannot unmarshal number into Go struct field .credentials.site.id of type string",
        "json: cannot unmarshal bool into Go struct field .credentials.site.id of type string",
        "json: cannot unmarshal number into Go struct field .credentials.site.contentUrl of type string",
        "json: cannot unmarshal bool into Go struct field .credentials.user.id of type string",
        "json: cannot unmarshal array into Go struct field TableauAuthResponse.credentials of type struct { Site struct { ID string \"json:\\\"id\\\"\"; ContentURL string \"json:\\\"contentUrl\\\"\" } \"json:\\\"site\\\"\"; User struct { ID string \"json:\\\"id\\\"\" } \"json:\\\"user\\\"\"; Token string \"json:\\\"token\\\"\" }",
    };
    for (size_t i = 0; i < sizeof(goldens) / sizeof(goldens[0]); ++i) {
        http = (test_http){.response = {.status = 200,
            .body = {(const unsigned char *)goldens[i], strlen(goldens[i])}}};
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
        CHECK(results.items[0].verified && results.items[0].verification_error);
        CHECK(!strcmp(results.items[0].verification_error, golden_errors[i]));
        expect_extra(&results.items[0], false);
        br_results_clear(&results);
    }
    http = (test_http){.response = {.status = 401}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    expect_extra(&results.items[0], false);
    br_results_clear(&results);
    http = (test_http){.response = {.status = 500}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    expect_extra(&results.items[0], false);
    br_results_clear(&results);
    http = (test_http){.response = {.status = 200, .body_error = "short read"}};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(!results.items[0].verified && results.items[0].extra_data &&
          json_object_object_length(results.items[0].extra_data) == 0);
    CHECK(!strcmp(results.items[0].verification_error, "failed to read response body: short read"));
    br_results_clear(&results);
    http = (test_http){.send_rc = -1, .send_error = "dial tcp: connection refused"};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    expect_extra(&results.items[0], true);
    br_results_clear(&results);
    http = (test_http){.send_rc = -1, .send_error = "HTTP transport not installed"};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(!strcmp(results.items[0].verification_error, "request failed: HTTP transport not installed"));
    CHECK(json_object_object_length(results.items[0].extra_data) == 0);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "failed to create request: net/http: nil Context"));
    CHECK(json_object_object_length(results.items[0].extra_data) == 0);
    br_results_clear(&results);
    const char *configured[] = {"bad%zz.example"};
    br_endpoints settings = {.configured = configured, .nconfigured = 1, .use_found = false};
    br_scan_ctx configured_ctx = {.transport = &transport, .endpoints = &settings};
    snprintf(text, sizeof(text), "tableau %s %s", name, secret);
    http.calls = 0;
    CHECK(d->scan(d, &configured_ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && http.calls == 0);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "invalid URL escape \"%zz\""));
    br_results_clear(&results);
    tableau_seam();
    return test_finish("tableau");
}

static int tableau_hook_mode, tableau_type_calls;

static int tableau_hook_document(br_slice body, br_json **out, char **cause)
{
    if (tableau_hook_mode == 1) return 2;
    return br_json_document(body, out, cause);
}

static int tableau_hook_visit(br_slice object, br_json_member_fn visit, void *user)
{
    int rc = br_json_each_member(object, visit, user);
    if (!rc && tableau_hook_mode == 2) return 1;
    return rc;
}

static int tableau_hook_type(br_json *value, const char *field, const char *expected, char **cause)
{
    ++tableau_type_calls;
    if (tableau_hook_mode == 3 && tableau_type_calls == 1) {
        if (cause) *cause = NULL;
        return 0;
    }
    if (tableau_hook_mode == 4 && tableau_type_calls == 2) return 1;
    return br_json_type_cause(value, field, expected, cause);
}

#define br_json_document tableau_hook_document
#define br_json_each_member tableau_hook_visit
#define br_json_type_cause tableau_hook_type
#define br_tableau_init tableau_hook_init
#include "../../src/detectors/tableau.c"
#undef br_json_document
#undef br_json_each_member
#undef br_json_type_cause
#undef br_tableau_init

static void tableau_seam(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(tableau_hook_init(&detector, &error) == 0 && detector && !error);
    char text[256];
    snprintf(text, sizeof(text), "tableau %s %s %s", name, secret, host);
    const char *sticky = "{\"credentials\":[],\"credentials\":{\"token\":5}}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)sticky, strlen(sticky)}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_slice input = {(const unsigned char *)text, strlen(text)};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    br_results results = {0};

    tableau_hook_mode = 1;
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot decode Tableau auth response"));
    CHECK(results.len == 1 && results.items[0].detector_type == 9 && !results.items[0].verified);
    free(error); error = NULL;
    br_results_clear(&results);

    tableau_hook_mode = 3;
    tableau_type_calls = 0;
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) == 0 && !error);
    CHECK(tableau_type_calls >= 2 && results.len == 1 && results.items[0].verified);
    CHECK(!results.items[0].verification_error);
    br_results_clear(&results);

    tableau_hook_mode = 4;
    tableau_type_calls = 0;
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(tableau_type_calls >= 2 && error && !strcmp(error, "cannot classify Tableau auth response"));
    CHECK(results.len == 1 && results.items[0].detector_type == 9);
    free(error); error = NULL;
    br_results_clear(&results);

    tableau_hook_mode = 2;
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    CHECK(br_results_push(&results, &prior) == 0);
    CHECK(detector->scan(detector, &ctx, true, input, &results, &error) != 0);
    CHECK(error && results.len == 1);
    free(error);
    br_results_clear(&results);
    br_result_clear(&prior);
}
