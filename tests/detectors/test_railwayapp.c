/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

int br_railwayapp_init(const br_detector **out, char **error);
static void railway_seams(const char *input);

static const char key1[] = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
static const char key2[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
static const char body[] = "{\"query\":\"query me {me {email}}\"}";

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value)) return NULL;
    return json_object_get_string(value);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[48];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key1);
    CHECK(ctx && !strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && request->body.len == sizeof(body) - 1);
    CHECK(!memcmp(request->body.data, body, sizeof(body) - 1));
    CHECK(!strcmp(request->url, "https://backboard.railway.app/graphql/v2"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].value, authorization));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_railwayapp_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 999 && !strcmp(detector->name, "RailwayApp"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "railway"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Railway is a deployment platform designed to streamline the software development life-cycle, starting with instant deployments and effortless scale, extending to CI/CD integrations and built-in observability."));
    return detector;
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[180];
    snprintf(input, sizeof(input), "RAILWAY%*s%s railway %s railway %s", 40, "", key1, key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    CHECK(results.items[0].detector_type == 999 && results.items[0].raw.len == 36);
    CHECK(extra(&results.items[0], "rotation_guide") &&
          !strcmp(extra(&results.items[0], "rotation_guide"), "https://howtorotate.com/docs/tutorials/railwayapp/"));
    CHECK(!results.items[0].verified);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "railway%*s%s", 41, "", key1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "railway %s", key1);
    const char ok[] = "{\"data\":{\"me\":{\"email\":\"a@b.c\"}}}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)ok, sizeof(ok) - 1}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);
    const char errors[] = "{\"errors\":[{\"message\":\"no\"}]}";
    http.response.body = (br_slice){(const unsigned char *)errors, sizeof(errors) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    const br_header limited[] = {{"X-RateLimit-Remaining", "0"}};
    http.response.headers = limited;
    http.response.nheaders = 1;
    http.response.body = (br_slice){(const unsigned char *)ok, sizeof(ok) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response = (br_http_response){.status = 401};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "railway app verification failed with status code 401"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    const char overflow[] = "{\"data\":1e10000,\"errors\":[]}";
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)overflow, sizeof(overflow) - 1}};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error,
                  "json: cannot unmarshal number 1e10000 into Go struct field graphQLResponse.data of type float64"));
    br_results_clear(&results);
    railway_seams(input);
    return test_finish("RailwayApp");
}

static int railway_hook_mode;
static int railway_float_calls;
static int (*railway_real_float)(br_slice, char **) = br_json_check_float64_numbers;
static int (*railway_real_visit)(br_slice, br_json_member_fn, void *) = br_json_each_member;

static int railway_hook_float(br_slice document, char **cause)
{
    ++railway_float_calls;
    if (railway_hook_mode == 1 && railway_float_calls == 1) {
        if (cause) *cause = NULL;
        return 1;
    }
    return railway_real_float(document, cause);
}

static int railway_hook_visit(br_slice object, br_json_member_fn visit, void *user)
{
    if (railway_hook_mode == 2) return 1;
    return railway_real_visit(object, visit, user);
}

#define br_json_check_float64_numbers railway_hook_float
#define br_json_each_member railway_hook_visit
#define br_railwayapp_init railway_seam_init
#include "../../src/detectors/railwayapp.c"
#undef br_json_check_float64_numbers
#undef br_json_each_member
#undef br_railwayapp_init

static void railway_seams(const char *input)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(railway_seam_init(&detector, &error) == 0 && detector && !error);
    const char body[] = "{\"data\":1,\"errors\":[]}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, sizeof(body) - 1}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    railway_hook_mode = 1;
    railway_float_calls = 0;
    br_results quiet = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(railway_float_calls >= 2);
    CHECK(quiet.len == 1 && !quiet.items[0].verified && !quiet.items[0].verification_error);
    br_results_clear(&quiet);

    railway_hook_mode = 2;
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot decode RailwayApp response"));
    CHECK(kept.len == 1 && kept.items[0].detector_type == 9 && !kept.items[0].verified);
    free(error);
    br_results_clear(&kept);
    br_result_clear(&prior);
}
