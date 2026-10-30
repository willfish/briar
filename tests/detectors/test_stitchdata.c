/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_stitchdata_init(const br_detector **out, char **error);

static char key[36], other[36];

static void result_is(const br_result *result, const char *capture, bool verified)
{
    test_key_result(result, 591, capture, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static const br_detector *descriptor(void)
{
    test_secret(key, 35, 2);
    test_secret(other, 35, 5);
    key[4] = '_';
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_stitchdata_init(NULL, &error) == -1 && error);
    free(error);
    CHECK(br_stitchdata_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_stitchdata_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 591 && !strcmp(detector->name, "Stitchdata"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "stitchdata"));
    CHECK(!strcmp(detector->description,
                  "Stitchdata is a cloud ETL service for consolidating data from various sources into a data warehouse. Stitchdata API keys can be used to manage and automate data pipelines."));
    CHECK(detector->max_credential_span == -1 && detector->state && detector->scan);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[220];
    snprintf(input, sizeof(input), "stitchdata %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memcpy(input, "STITCHDATA", 10);
    memset(input + 10, '.', 40);
    memcpy(input + 50, key, 35);
    out = test_scan(detector, NULL, false, input, 85);
    CHECK(out.len == 1);
    result_is(&out.items[0], key, false);
    br_results_clear(&out);
    memset(input + 10, '.', 41);
    memcpy(input + 51, key, 35);
    out = test_scan(detector, NULL, false, input, 86);
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "stitchdata %s\nstitchdata %s\nstitchdata %s", key, other, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 3);
    result_is(&out.items[0], key, false);
    result_is(&out.items[1], other, false);
    result_is(&out.items[2], key, false);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "stitchdata %s", key);
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char authorization[48];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, "https://api.stitchdata.com/v4/sources"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 591);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    (void)http;
}

static void verification(const br_detector *detector)
{
    char input[56];
    snprintf(input, sizeof(input), "stitchdata %s", key);
    const int statuses[] = {200, 299, 300, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "stitch-test"};
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
    return test_finish("Stitchdata");
}
