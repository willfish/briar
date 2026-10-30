/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_sslmate_init(const br_detector **out, char **error);

static const char key[] = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
static char seen_auth[64];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://sslmate.com/api/v2/certs/example.com?expand=current.crt"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 109);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    snprintf(seen_auth, sizeof(seen_auth), "%s", request->headers[0].value);
}

int main(void)
{
    CHECK(strlen(key) == 36);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sslmate_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 109 && !strcmp(detector->name, "SslMate") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->keywords[0], "sslmate"));
    CHECK(!strcmp(detector->description, "SslMate is a service that helps manage and automate SSL certificates. SslMate API keys can be used to access and manage SSL certificates."));
    char input[96];
    snprintf(input, sizeof(input), "SSLMATE %s sslmate %s", key, key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 109, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "sslmate %s?", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);

    test_http http = {.inspect = inspect, .response.status = 299};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "sslmate %s", key);
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && out.items[0].verified);
    CHECK(!strcmp(seen_auth, "Basic a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"));
    CHECK(strcmp(seen_auth, "Basic YTFCMmMzRDRlNUY2ZzdIOGk5SjBrMUwybTNONW81UDZxN1I4"));
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    return test_finish("SslMate");
}
