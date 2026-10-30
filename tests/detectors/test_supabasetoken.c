/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_supabasetoken_init(const br_detector **out, char **error);

static const char key[] = "sbp_6corwd8ltv0m2hx5av0bqswrldi43hk8qdtnxcs7";
static char seen_auth[64];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.supabase.com/v1/projects"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 915);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

int main(void)
{
    CHECK(strlen(key) == 44);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_supabasetoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 915 && !strcmp(detector->name, "SupabaseToken") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->keywords[0], "sbp_"));
    CHECK(!strcmp(detector->description, "Supabase is an open source Firebase alternative. Supabase tokens can be used to access and manage Supabase projects and data."));
    br_results out = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 915, key, "key");
    br_results_clear(&out);
    char bad[] = "sbp_6corwd8ltv?m2hx5av0bqswrldi43hk8qdtnxcs7";
    out = test_scan(detector, NULL, false, bad, strlen(bad));
    CHECK(!out.len);
    br_results_clear(&out);
    char upper[] = "sbp_6CORWD8LTV0M2HX5AV0BQSWRLdi43hk8qdtnxcs7";
    out = test_scan(detector, NULL, false, upper, strlen(upper));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(out.len == 1 && out.items[0].verified && !strcmp(seen_auth, "Bearer sbp_6corwd8ltv0m2hx5av0bqswrldi43hk8qdtnxcs7"));
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response.status = 401;
    out = test_scan(detector, &ctx, true, key, strlen(key));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, key, strlen(key));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("SupabaseToken");
}
