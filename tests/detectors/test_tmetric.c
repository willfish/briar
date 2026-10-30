/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_tmetric_init(const br_detector **out, char **error);

static char key[65], seen_auth[80];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://app.tmetric.com/api/v3/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 446);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

int main(void)
{
    for (int i = 0; i < 64; ++i) key[i] = "379NU8"[i % 6];
    key[64] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tmetric_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 446 && !strcmp(detector->name, "Tmetric") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->keywords[0], "tmetric"));
    CHECK(!strcmp(detector->description, "Tmetric is a time tracking service. Tmetric API keys can be used to access and manage time tracking data."));
    char input[160], lower[80];
    snprintf(input, sizeof(input), "TMETRIC %s tmetric %s", key, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 446, key, "key");
    br_results_clear(&out);
    snprintf(lower, sizeof(lower), "tmetric %s", key);
    lower[8] = 'a';
    out = test_scan(detector, NULL, false, lower, strlen(lower));
    CHECK(!out.len);
    br_results_clear(&out);
    char gap[48];
    memset(gap, '.', 41);
    gap[41] = '\0';
    snprintf(input, sizeof(input), "tmetric%s%s", gap, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 204};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "tmetric %s", key);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(!strncmp(seen_auth, "Bearer ", 7) && !strcmp(seen_auth + 7, key));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 401;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error && http.releases == 1);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("Tmetric");
}
