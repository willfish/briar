/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_shutterstockoauth_init(const br_detector **out, char **error);

static char key[392], seen_auth[420];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.shutterstock.com/v2/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 519);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[1].value);
}

int main(void)
{
    memcpy(key, "v2/", 3);
    memset(key + 3, 'A', 388);
    key[391] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shutterstockoauth_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 519 && !strcmp(detector->name, "ShutterstockOAuth"));
    CHECK(!strcmp(detector->keywords[0], "shutterstock") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description, "A service for saving and accessing photos. OAuth credentials can be used to potentially access user photos."));
    char input[480];
    snprintf(input, sizeof(input), "SHUTTERSTOCK %s", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 519, key, "key");
    br_results_clear(&out);
    key[3] = '+';
    snprintf(input, sizeof(input), "shutterstock %s", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    key[3] = 'A';
    out = test_scan(detector, NULL, false, key, 391);
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "shutterstock %s", key);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !strncmp(seen_auth, "Bearer ", 7) && !strcmp(seen_auth + 7, key));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 401;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("ShutterstockOAuth");
}
