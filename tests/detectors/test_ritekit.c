/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_ritekit_init(const br_detector **out, char **error);

static char key[45], other[45];

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 461, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    test_secret(key, 44, 4);
    test_secret(other, 44, 6);
    for (size_t i = 0; i < 44; ++i) {
        if (key[i] > 'f' && key[i] <= 'z') key[i] = 'a' + (char)(i % 6);
        if (other[i] > 'f' && other[i] <= 'z') other[i] = '0' + (char)(i % 10);
    }
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_ritekit_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_ritekit_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_ritekit_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 461 && !strcmp(detector->name, "RiteKit"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ritekit"));
    CHECK(!strcmp(detector->description,
                  "RiteKit is a social media toolkit that provides various APIs for managing social media content and analytics. RiteKit API keys can be used to access and manage social media data."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[180];
    snprintf(input, sizeof(input), "ritekit %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, 44);
    CHECK(!out.len);
    br_results_clear(&out);
    memcpy(input, "RITEKIT", 7);
    memset(input + 7, '-', 40);
    memcpy(input + 47, key, 44);
    out = test_scan(detector, NULL, false, input, 91);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memset(input + 7, '-', 41);
    memcpy(input + 48, key, 44);
    out = test_scan(detector, NULL, false, input, 92);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ritekit %sA", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ritekit %s\nritekit %s\nritekit %s", key, other, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    result_is(&out.items[2], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "ritekit %s", key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char url[128];
    snprintf(url, sizeof(url),
             "https://api.ritekit.com/v1/stats/multiple-hashtags?tags=hello&client_id=%s", key);
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 461 && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "ritekit %s", key);
    const int statuses[] = {200, 299, 300, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "ritekit-test"};
        br_results out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result_is(&out.items[0], key, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    test_http http = {.send_rc = 1, .send_error = "synthetic transport failure", .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.releases == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("RiteKit");
}
