/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_surveybot_init(const br_detector **out, char **error);

static char key[81], other[81];

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 234, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    test_secret(key, 80, 1);
    test_secret(other, 80, 6);
    key[3] = '-';
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_surveybot_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_surveybot_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_surveybot_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 234 && !strcmp(detector->name, "SurveyBot"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "surveybot"));
    CHECK(!strcmp(detector->description,
                  "SurveyBot is a service used for conducting surveys. SurveyBot API keys can be used to access and manage surveys."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[280];
    snprintf(input, sizeof(input), "surveybot %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "surveybot %s\nsurveybot %s\nsurveybot %s", key, other, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    result_is(&out.items[2], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "surveybot %s", key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://app.surveybot.io/api/v1/surveys?page=1&per_page=20&offset=0"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 234);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && !strcmp(request->headers[1].value, key));
    (void)http;
}

static br_results once(const br_detector *detector, int status, const char *body, const char *read_error, int send_rc)
{
    test_http http = {.response = {.status = status, .body_error = read_error}, .send_rc = send_rc, .inspect = inspect};
    if (body) http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    if (send_rc) http.send_error = "synthetic transport failure";
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "survey-test"};
    char input[96];
    snprintf(input, sizeof(input), "surveybot %s", key);
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1);
    return out;
}

static void verification(const br_detector *detector)
{
    br_results out = once(detector, 200, "{\"surveys\":[{},null],\"extra\":1} trailing", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, true);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":[]}", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    out = once(detector, 200, "null", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":1}", NULL, 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "", NULL, 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":[1e9999]}", NULL, 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":3,\"surveys\":[1]}", NULL, 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":3,\"surveys\":null}", NULL, 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":[1e9999],\"surveys\":[1]}", NULL, 0);
    CHECK(!out.len);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":null,\"surveys\":[1]}", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, true);
    br_results_clear(&out);
    out = once(detector, 200, "{\"surveys\":[1],\"surveys\":null}", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    out = once(detector, 401, "{\"surveys\":[{}]}", NULL, 0);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    out = once(detector, 200, "", NULL, 1);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("SurveyBot");
}
