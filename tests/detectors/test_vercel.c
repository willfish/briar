/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_vercel_init(const br_detector **out, char **error);

static const char key[] = "gGP4GJRR3TOpU7wzTY9UiSTQ";
static char seen_auth[48];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.vercel.com/www/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 160);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

int main(void)
{
    CHECK(strlen(key) == 24);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_vercel_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 160 && !strcmp(detector->name, "Vercel") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->keywords[0], "vercel"));
    CHECK(!strcmp(detector->description, "Vercel is a platform for frontend frameworks and static sites, built to integrate with your headless content, commerce, or database. Vercel API keys can be used to access and manage your Vercel projects and deployments."));
    char input[128];
    snprintf(input, sizeof(input), "VERCEL %s vercel %s", key, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 160, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "vercel gGP4GJRR3TOp?7wzTY9UiSTQ");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, 24);
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "vercel %s", key);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !strcmp(seen_auth, "Bearer gGP4GJRR3TOpU7wzTY9UiSTQ"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 300;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("Vercel");
}
