/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_uclassify_init(const br_detector **out, char **error);

static char key[13];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    test_secret(key, 12, 2);
    key[1] = 'A';
    CHECK(br_uclassify_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_uclassify_init(&detector, &error) == 0 && detector && detector->type == 871);
    CHECK(!strcmp(detector->name, "Uclassify") && !strcmp(detector->keywords[0], "uclassify"));
    CHECK(!strcmp(detector->description,
                  "Uclassify is a text classification service. Uclassify API keys can be used to "
                  "classify text into various categories such as sentiment, topic, etc."));
    CHECK(detector->max_credential_span == -1 && !detector->clean && !detector->validate_endpoints);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char authorization[24];
    (void)http;
    snprintf(authorization, sizeof(authorization), "Token %s", key);
    CHECK(ctx && !strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.uclassify.com/v1/uClassify/Sentiment/classify"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 871);
    CHECK(request->body.len == 33 && !memcmp(request->body.data, "{\"texts\":[\"I am so happy today\"]}", 33));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
}

static void run(const br_detector *detector)
{
    char input[48], bad[13];
    snprintf(input, sizeof(input), "uclassify %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 871, key, "key");
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, key, 12);
    CHECK(!results.len);
    br_results_clear(&results);
    memcpy(bad, key, sizeof(bad));
    bad[4] = '-';
    snprintf(input, sizeof(input), "uclassify %s", bad);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "uclassify %s", key);
    const int codes[] = {200, 204, 401, 500};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        test_http http = {.response = {.status = codes[i]}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1);
        CHECK(results.items[0].verified == (codes[i] >= 200 && codes[i] < 300) && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    run(descriptor());
    return test_finish("Uclassify");
}
