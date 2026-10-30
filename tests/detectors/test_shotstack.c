/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_shotstack_init(const br_detector **out, char **error);

static const char key1[] = "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS";
static const char key2[] = "shotstackSHOTSTACK0123456789abcdefghijXX";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && !strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && request->body.len == 598);
    CHECK(request->body.data[0] == '{' && request->body.data[597] == '}');
    bool found = false;
    for (size_t i = 0; i + 32 <= request->body.len; ++i)
        if (!memcmp(request->body.data + i, "shotstack-assets/music/moment.mp3", 32)) found = true;
    CHECK(found);
    CHECK(!strcmp(request->url, "https://api.shotstack.io/edit/v1/render"));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && !strcmp(request->headers[1].value, key1));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shotstack_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 674 && !strcmp(detector->name, "Shotstack"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "shotstack"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Shotstack is a video editing API service. Shotstack API keys can be used to access and utilize the video rendering and editing capabilities of the Shotstack platform."));
    return detector;
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[180];
    snprintf(input, sizeof(input), "SHOTSTACK%*s%s shotstack %s", 40, "", key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 674, key1, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "shotstack %s", key1);
    test_http http = {.response = {.status = 201}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("Shotstack");
}
