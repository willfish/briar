/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int force_json;
static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
static int first_hook(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (force_json) { *out = NULL; if (end) *end = 0; *cause = NULL; return force_json; }
    return real_first_document(body, read_error, out, end, cause);
}
#define br_json_first_document first_hook
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
#include "../../src/detectors/opsgenie.c"
#undef br_json_type_cause
#undef br_json_first_document

static const char key1[] = "1c73ff35-2415-fc58-8712-3d24f00cbe2a";
static const char key2[] = "9f8e7d6c-5b4a-3928-1706-fedcba098765";

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value) ||
        !json_object_is_type(value, json_type_string)) return NULL;
    return json_object_get_string(value);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[48];
    snprintf(authorization, sizeof(authorization), "GenieKey %s", key1);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len && request->nheaders == 2);
    CHECK(!strcmp(request->url, "https://api.opsgenie.com/v2/account"));
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_opsgenie_init(&detector, &error) == 0 && !error);
    CHECK(br_opsgenie_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 875 && !strcmp(detector->name, "Opsgenie"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "opsgenie"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Opsgenie is an alerting and incident management platform. Opsgenie API keys can be used to interact with the Opsgenie API to manage alerts and incidents."));
    return detector;
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[256];
    snprintf(input, sizeof(input), "OPSGENIE%*s%s opsgenie %s opsgenie %s", 40, "", key1, key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 875, key1, "key");
    test_key_result(&results.items[1], 875, key2, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "opsgenie%*s%s", 41, "", key1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    const char low[] = "opsgenie 00000000-0000-0000-0000-000000000000";
    results = test_scan(detector, NULL, false, low, sizeof(low) - 1);
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "https://opsgenie.com/alert/detail/%s opsgenie %s", key1, key2);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !memcmp(results.items[0].raw.data, key2, 36));
    br_results_clear(&results);
    const char upper[] = "opsgenie 1C73FF35-2415-FC58-8712-3D24F00CBE2A";
    results = test_scan(detector, NULL, false, upper, sizeof(upper) - 1);
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "opsgenie %s", key1);
    const char body[] = "{\"data\":{\"name\":\"Acme\",\"userCount\":3,\"plan\":{\"name\":\"Enterprise\"}}} trailing";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    CHECK(extra(&results.items[0], "account") && !strcmp(extra(&results.items[0], "account"), "Acme"));
    CHECK(extra(&results.items[0], "plan") && !strcmp(extra(&results.items[0], "plan"), "Enterprise"));
    CHECK(!json_object_object_get_ex(results.items[0].extra_data, "userCount", NULL));
    br_results_clear(&results);

    http.response = (br_http_response){.status = 403};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].extra_data && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    http.response = (br_http_response){.status = 200};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "EOF"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    const char root_body[] = "[]";
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)root_body, sizeof(root_body) - 1}};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(strstr(results.items[0].verification_error, "cannot unmarshal array"));
    br_results_clear(&results);
    const char trail[] = "{\"data\":{\"name\":\"A\",\"plan\":{\"name\":\"P\"}}}{\"data\":{\"name\":\"B\"}}";
    http.response.body = (br_slice){(const unsigned char *)trail, sizeof(trail) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(extra(&results.items[0], "account"), "A") && !strcmp(extra(&results.items[0], "plan"), "P"));
    br_results_clear(&results);
    const char named[] = "{\"data\":{\"name\":\"A\\u0000B\",\"plan\":{\"name\":\"P\\u0000Q\"}}}";
    http.response.body = (br_slice){(const unsigned char *)named, sizeof(named) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "account", &part));
    CHECK(json_object_get_string_len(part) == 3 && !memcmp(json_object_get_string(part), "A\0B", 3));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "plan", &part));
    CHECK(json_object_get_string_len(part) == 3 && !memcmp(json_object_get_string(part), "P\0Q", 3));
    br_results_clear(&results);
    later_type = 1;
    type_calls = 0;
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{\"data\":{\"name\":1,\"plan\":1}}", 28};
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
    force_json = 2;
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("Opsgenie");
}
