/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_ramp_init(const br_detector **, char **);

static char id[49], other[49], secret[58];
static const br_http_request *seen;

static void fill(void)
{
    memcpy(id, "ramp_id_", 8);
    memset(id + 8, 'a', 40);
    id[48] = 0;
    memcpy(other, "ramp_id_", 8);
    memset(other + 8, 'c', 40);
    other[48] = 0;
    memcpy(secret, "ramp_sec_", 9);
    memset(secret + 9, 'b', 48);
    secret[57] = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    seen = request;
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://api.ramp.com/developer/v1/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->body.len == strlen("grant_type=client_credentials&scope=user%3Aread"));
    CHECK(!memcmp(request->body.data, "grant_type=client_credentials&scope=user%3Aread", request->body.len));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strncmp(request->headers[0].value, "Basic ", 6));
    CHECK(!strcmp(request->headers[1].name, "Content-Type"));
    CHECK(!strcmp(request->headers[1].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

static void check_pair(const br_result *result, const char *key, const char *sec)
{
    char raw[128];
    snprintf(raw, sizeof(raw), "%s:%s", key, sec);
    CHECK(result->detector_type == 934);
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, strlen(key)));
    CHECK(result->raw_v2.len == strlen(raw) && !memcmp(result->raw_v2.data, raw, strlen(raw)));
    CHECK(json_object_object_length(result->secret_parts) == 2);
}

int main(void)
{
    fill();
    char *error = NULL;
    const br_detector *detector = NULL;
    CHECK(br_ramp_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 934 && !strcmp(detector->name, "Ramp"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ramp_"));
    char input[256];
    snprintf(input, sizeof(input), "%s %s", id, secret);
    br_scan_ctx ctx = {.transport = NULL};
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    ctx.transport = &transport;
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    check_pair(&results.items[0], id, secret);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s", id, other, secret);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2);
    check_pair(&results.items[0], id, secret);
    check_pair(&results.items[1], other, secret);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s", id, id, secret);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, false, id, strlen(id));
    CHECK(!results.len);
    http.response.status = 200;
    snprintf(input, sizeof(input), "%s %s", id, secret);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.calls == 1);
    br_results_clear(&results);
    http.response.status = 401;
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unexpected HTTP response status 403"));
    br_results_clear(&results);
    http.send_error = id;
    http.send_rc = -1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "[REDACTED]") &&
          !strstr(results.items[0].verification_error, id));
    br_results_clear(&results);
    http.send_error = NULL;
    http.send_rc = 0;
    http.calls = 0;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && !http.calls);
    printf("ramp: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
