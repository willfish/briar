/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_segmentapikey_init(const br_detector **out, char **error);

static void fill(char *out, size_t n, char seed)
{
    for (size_t i = 0; i < n; ++i) out[i] = (char)('A' + ((seed + i) % 26));
    out[3] = '_';
    out[9] = '-';
    out[n] = 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_segmentapikey_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_segmentapikey_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 122 && !strcmp(detector->name, "SegmentApiKey"));
    CHECK(!strcmp(detector->keywords[0], "segment") && detector->nkeywords == 1);
    CHECK(!strcmp(detector->description,
        "Segment is a customer data platform that helps you collect, clean, and control your customer data. Segment API keys can be used to access and manage this data."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char expect[96];
    snprintf(expect, sizeof(expect), "Bearer %s", (const char *)http->user);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://platform.segmentapis.com/v1beta/workspaces"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 122);
    CHECK(!request->body.len && request->nheaders == 2);
    size_t auth = 0;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization")) {
            ++auth;
            CHECK(!strcmp(request->headers[i].value, expect));
        }
    CHECK(auth == 1);
}

static void extraction(const br_detector *detector)
{
    char left[44], right[44], key[88], input[256];
    fill(left, 43, 1);
    fill(right, 43, 4);
    snprintf(key, sizeof(key), "%s.%s", left, right);
    snprintf(input, sizeof(input), "segment token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 122, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "SEGMENT%s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s segment", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "segment %s\nsegment %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    left[42] = '.';
    snprintf(key, sizeof(key), "%s.%s", left, right);
    snprintf(input, sizeof(input), "segment %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char left[44], right[44], key[88], input[160];
    fill(left, 43, 2);
    fill(right, 43, 7);
    snprintf(key, sizeof(key), "%s.%s", left, right);
    snprintf(input, sizeof(input), "segment %s", key);
    const int statuses[] = {200, 299, 401, 500};
    for (size_t i = 0; i < 4; ++i) {
        test_http http = {.response = {.status = statuses[i]}, .inspect = inspect, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1);
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http http = {.send_rc = 1, .send_error = "context canceled", .inspect = inspect, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("SegmentApiKey");
}
