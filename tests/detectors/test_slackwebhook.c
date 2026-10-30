/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_slackwebhook_init(const br_detector **out, char **error);

static const char *hook = "https://hooks.slack.com/services/T123/B456/abcdefghijklmnopqrstuvw";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, hook));
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(request->body.len == strlen("intentionally malformed JSON from TruffleHog scan"));
    CHECK(!memcmp(request->body.data, "intentionally malformed JSON from TruffleHog scan", request->body.len));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_slackwebhook_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 30 && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "hooks.slack.com"));
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, hook, strlen(hook));
    CHECK(results.len == 1 && results.items[0].verified);
    br_json *guide = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "rotation_guide", &guide));
    CHECK(!strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/slack-webhook/"));
    br_results_clear(&results);
    http.response.status = 400;
    http.response.body = (br_slice){(const unsigned char *)"invalid_payload", 15};
    results = test_scan(detector, &ctx, true, hook, strlen(hook));
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"nope invalid_token", 18};
    results = test_scan(detector, &ctx, true, hook, strlen(hook));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 404;
    http.response.body = (br_slice){0};
    results = test_scan(detector, &ctx, true, hook, strlen(hook));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    http.response.body = (br_slice){(const unsigned char *)"nope", 4};
    results = test_scan(detector, &ctx, true, hook, strlen(hook));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "nope"));
    br_results_clear(&results);
    http.response.body = (br_slice){0};
    http.response.body_error = "read reset";
    results = test_scan(detector, &ctx, true, hook, strlen(hook));
    CHECK(!results.len);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, hook, strlen(hook));
    CHECK(!results.len);
    br_results_clear(&results);
    const char *workflow = "https://hooks.slack.com/workflows/T123/A456/12345678901234567/abcdefghijklmnopqrstuvw";
    results = test_scan(detector, NULL, false, workflow, strlen(workflow));
    CHECK(results.len == 1);
    br_results_clear(&results);
    char raw[128];
    memcpy(raw, hook, strlen(hook));
    br_result candidate = {.raw = {(unsigned char *)raw, strlen(hook)}};
    char *why = NULL;
    CHECK(detector->false_positive(detector, &candidate, &why) == false);
    memcpy(raw, "example", 7);
    candidate.raw = (br_bytes){(unsigned char *)raw, 7};
    CHECK(detector->false_positive(detector, &candidate, &why) == true);
    return test_finish("SlackWebhook");
}
