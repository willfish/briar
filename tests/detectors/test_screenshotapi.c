/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
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
#include "../../src/detectors/screenshotapi.c"
#undef br_json_first_document

static int shot_type_calls, shot_type_fatal_after, shot_type_null;
static int shot_type_hook(br_json *value, char **cause)
{
    ++shot_type_calls;
    if (shot_type_fatal_after && shot_type_calls >= shot_type_fatal_after) {
        if (cause) *cause = NULL;
        return -1;
    }
    if (shot_type_null) {
        if (cause) *cause = NULL;
        return 1;
    }
    return screenshot_type_cause_real(value, cause);
}

static const char key[] = "5QCXUYE-B9LNS58-X62XLXO-CHZJZDO";
static const char url[] = "https://shot.screenshotapi.net/screenshot?token=5QCXUYE-B9LNS58-X62XLXO-CHZJZDO&url=https://google.com&width=1920&height=1080";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 451);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog screenshotapi-offline"));
}

int main(void)
{
    CHECK(strlen(key) == 31);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_screenshotapi_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 451 && !strcmp(detector->name, "ScreenshotAPI"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "screenshotapi"));
    CHECK(!strcmp(detector->description,
        "A service for taking screenshots of websites. Websites can include internal or sensitive websites, API keys can access the screenshots."));
    CHECK(br_screenshotapi_init(NULL, &error) != 0 && error); free(error);
    char input[160];
    snprintf(input, sizeof(input), "screenshotapi token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 451, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "screenshotapi keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "screenshotapi = '%s'", "5QCXUYE?B9LNS58-X62XLXO-CHZJZDO");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "SCREENSHOTAPI %s screenshotapi %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2); br_results_clear(&results);
    snprintf(input, sizeof(input), "screenshotapi %s", key);
    const char *shot = "{\"screenshot\":\"https://example.test/a.png\"}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)shot, strlen(shot)}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "screenshotapi-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"{\"screenshot\":\"\"}", 18};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"[]", 2};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{\"screenshot\":1}", 17};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    static const char kept_shot[] = "{\"screenshot\":\"keep\",\"screenshot\":null}";
    http.response.body = (br_slice){(const unsigned char *)kept_shot, sizeof(kept_shot) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    static const char nul_shot[] = "{\"screenshot\":\"\\u0000abc\"}";
    http.response.body = (br_slice){(const unsigned char *)nul_shot, sizeof(nul_shot) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    screenshot_type_cause = shot_type_hook;
    shot_type_calls = 0; shot_type_null = 1; shot_type_fatal_after = 0;
    static const char later_shot[] = "{\"screenshot\":\"keep\",\"screenshot\":1}";
    http.response.body = (br_slice){(const unsigned char *)later_shot, sizeof(later_shot) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && shot_type_calls >= 1);
    br_results_clear(&results);
    shot_type_calls = 0; shot_type_null = 0; shot_type_fatal_after = 2;
    static const char fatal_shot[] = "{\"screenshot\":1,\"screenshot\":false}";
    http.response.body = (br_slice){(const unsigned char *)fatal_shot, sizeof(fatal_shot) - 1};
    char *typed_error = NULL;
    br_results typed_failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &typed_failed, &typed_error) != 0);
    CHECK(!typed_failed.len && shot_type_calls >= 2);
    free(typed_error);
    br_results_clear(&typed_failed);
    screenshot_type_cause = screenshot_type_cause_real;
    shot_type_calls = shot_type_null = shot_type_fatal_after = 0;
    http.send_rc = 1; http.send_error = "dial screenshot"; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    force_json = 2;
    http.send_rc = 0; http.send_error = NULL; http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("ScreenshotAPI");
}
