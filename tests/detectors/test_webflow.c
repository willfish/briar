/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_webflow_init(const br_detector **out, char **error);

static char key[65], seen_auth[80];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.webflow.com/info"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 218);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept-Version") && !strcmp(request->headers[0].value, "1.0.0"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[1].value);
}

int main(void)
{
    memset(key, 'a', 64);
    key[0] = 'A';
    key[64] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_webflow_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 218 && !strcmp(detector->name, "Webflow") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->keywords[0], "webflow"));
    CHECK(!strcmp(detector->description, "Webflow is a web design tool that allows users to design, build, and launch responsive websites visually. Webflow API keys can be used to access and manipulate data within Webflow projects."));
    char input[96];
    snprintf(input, sizeof(input), "WEBFLOW %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 218, key, "key");
    br_results_clear(&out);
    key[1] = 'B';
    snprintf(input, sizeof(input), "webflow %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    key[1] = 'a';

    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "webflow %s", key);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !strncmp(seen_auth, "Bearer ", 7) && !strcmp(seen_auth + 7, key));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("Webflow");
}
