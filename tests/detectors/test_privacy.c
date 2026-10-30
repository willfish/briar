/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_privacy_init(const br_detector **out, char **error);

static const char key[] = "sccqe60k-nsak-h1m1-vzq8-vr7u4gxihiwl";
static char seen_auth[64];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.privacy.com/v1/card?page=1&page_size=50"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 938);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!request->body.data);
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

int main(void)
{
    CHECK(strlen(key) == 36);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_privacy_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 938 && !strcmp(detector->name, "Privacy"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "privacy"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description, "Privacy provides virtual cards for secure online payments. Privacy API keys can be used to manage and create these virtual cards."));
    char input[160], gap[48];
    snprintf(input, sizeof(input), "PRIVACY %s privacy %s", key, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 938, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "privacy SCCQE60K-nsak-h1m1-vzq8-vr7u4gxihiwl");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    memset(gap, '.', 41);
    gap[41] = '\0';
    snprintf(input, sizeof(input), "privacy%s%s", gap, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, key, 36);
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "privacy %s", key);
    http.response.status = 200;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error);
    CHECK(!strcmp(seen_auth, "api-key sccqe60k-nsak-h1m1-vzq8-vr7u4gxihiwl"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 401;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 500;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !strcmp(out.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "down";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !strcmp(out.items[0].verification_error, "down"));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("Privacy");
}
