/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_surveyanyplace_init(const br_detector **out, char **error);

static const char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
static const char id[] = "11111111-2222-3333-4444-555555555555";
static const char body[] =
    "{\n\t\t\t\t\t\"codes\": [\n\t\t\t\t\t\"code1\",\n\t\t\t\t\t\"code2\"\n\t\t\t\t\t]\n\t\t\t\t\t}";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_surveyanyplace_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_surveyanyplace_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 233 && !strcmp(detector->name, "SurveyAnyplace"));
    CHECK(!strcmp(detector->description,
                  "SurveyAnyplace is a platform for creating surveys and quizzes. The detected credential can be used to access and manage surveys on this platform."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "surveyanyplace"));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1);
    CHECK(strlen(key) == 32 && strlen(id) == 36 && sizeof(body) - 1 == 58);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "survey %s survey %s", key, id);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 233, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "anyplace %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "survey %s survey %s survey %s", key, key, id);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
}

static int survey_status;
static const char *seen_url;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    (void)http;
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, seen_url));
    CHECK(request->body.len == 58 && !memcmp(request->body.data, body, 58));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "API ", 4) &&
          !strcmp(request->headers[0].value + 4, key));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") &&
          !strcmp(request->headers[1].value, "application/json"));
    http->response.status = survey_status;
}

static void verification(const br_detector *detector)
{
    char input[256], url[128];
    snprintf(input, sizeof(input), "survey %s survey %s", key, id);
    snprintf(url, sizeof(url), "https://api.surveyanyplace.com/v1/surveys/%s/accesscodes", id);
    seen_url = url;
    survey_status = 201;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    survey_status = 404;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("surveyanyplace");
}
