/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_openvpn_init(const br_detector **out, char **error);

static const char *ident = "client.identifier";
static const char *secret = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab";
static const char *domain = "https://tenant.api.openvpn.com";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    char url[96];
    snprintf(url, sizeof(url), "%s/api/beta/oauth/token", domain);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strncmp(request->headers[0].value, "Basic ", 6));
    CHECK(!strcmp(request->headers[1].name, "content-type"));
    CHECK(!strcmp(request->headers[1].value, "application/x-www-form-urlencoded"));
    CHECK(request->body.len == strlen("grant_type=client_credentials"));
    CHECK(!memcmp(request->body.data, "grant_type=client_credentials", request->body.len));
}

int main(void)
{
    CHECK(strlen(secret) == 64);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_openvpn_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 945 && detector->max_credential_span == 1024);
    char input[256];
    snprintf(input, sizeof(input), "openvpn %s %s %s", ident, secret, domain);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(results.items[0].raw.len == 64 && !memcmp(results.items[0].raw.data, secret, 64));
    CHECK(results.items[0].raw_v2.len == strlen(ident) + 64);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "client_secret", &part));
    CHECK(!strcmp(json_object_get_string(part), secret));
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strstr(results.items[0].verification_error, secret));
    CHECK(strstr(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial tcp: connection refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strstr(results.items[0].verification_error, secret));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "openvpn %s %s", ident, secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    return test_finish("OpenVpn");
}
