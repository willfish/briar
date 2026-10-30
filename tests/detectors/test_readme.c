/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

int br_readme_init(const br_detector **out, char **error);

static char key[76], other[76];

static void fill(char *out, size_t shift)
{
    memcpy(out, "rdme_", 5);
    test_secret(out + 5, 70, shift);
    out[5] = 'a';
}

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 495, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    fill(key, 3);
    fill(other, 11);
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_readme_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_readme_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_readme_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 495 && !strcmp(detector->name, "ReadMe"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "rdme_"));
    CHECK(!strcmp(detector->description,
                  "ReadMe is a documentation platform that helps you build out your API and product documentation. ReadMe API keys can be used to access and modify your documentation data."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[240];
    br_results out = test_scan(detector, NULL, false, key, 75);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "X%sY", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memcpy(input, key, 74);
    out = test_scan(detector, NULL, false, input, 74);
    CHECK(!out.len);
    br_results_clear(&out);
    memcpy(input, key, 75);
    input[75] = 'a';
    out = test_scan(detector, NULL, false, input, 76);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    input[9] = 'A';
    out = test_scan(detector, NULL, false, input, 75);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s %s", key, other, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    result_is(&out.items[2], key, false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, key, 75);
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char *authorization = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)key, 75}, (br_slice){0},
                             &authorization, &error) == 0 && authorization && !error);
    CHECK(ctx && ctx->user_agent && !ctx->deadline_monotonic_ms);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://dash.readme.com/api/v1"));
    CHECK(request->profile == BR_HTTP_PRIVATE_DEFAULT_CLIENT && !request->timeout_ms);
    CHECK(request->detector_type == 495 && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "Accept"));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    free(authorization);
    (void)http;
}

static void verification(const br_detector *detector)
{
    const int statuses[] = {199, 200, 299, 300, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "must-not-be-copied"};
        br_results out = test_scan(detector, &ctx, true, key, 75);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    test_http http = {.send_rc = 4, .send_error = "synthetic transport failure", .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "must-not-be-copied"};
    br_results out = test_scan(detector, &ctx, true, key, 75);
    CHECK(out.len == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    br_scan_ctx bare = {0};
    out = test_scan(detector, &bare, true, key, 75);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("ReadMe");
}
