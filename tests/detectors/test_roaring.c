/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_roaring_init(const br_detector **out, char **error);

static const char client[] = "-3o_mYkUEBbUKtKjGCg5tgnkzU4T";
static const char secret[] = "XqTQqnAkyH6We_TEK1CRjhwRV51h";
static const char *expected_auth;

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(client) == 28 && strlen(secret) == 28);
    CHECK(br_roaring_init(&detector, &error) == 0 && detector && detector->type == 480);
    CHECK(!strcmp(detector->name, "Roaring") && !strcmp(detector->keywords[0], "roaring"));
    CHECK(!strcmp(detector->description,
                  "Roaring credentials can be used to access the Roaring API, which provides "
                  "services for high-performance, compressed bitmaps."));
    CHECK(detector->max_credential_span == 1024 && detector->state && !detector->clean);
    return detector;
}

static void check_pair(const br_result *result, const char *left, const char *right, bool verified)
{
    char raw_v2[57];
    snprintf(raw_v2, sizeof(raw_v2), "%s%s", left, right);
    CHECK(result->detector_type == 480 && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == 28 && !memcmp(result->raw.data, left, 28));
    CHECK(result->raw_v2.len == 56 && !memcmp(result->raw_v2.data, raw_v2, 56));
    CHECK(!result->redacted && !result->extra_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "client_id", &part) &&
          !strcmp(json_object_get_string(part), left));
    CHECK(json_object_object_get_ex(result->secret_parts, "client_secret", &part) &&
          !strcmp(json_object_get_string(part), right));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && !strcmp(request->method, "POST") && !strcmp(request->url, "https://api.roaring.io/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 480);
    CHECK(request->body.len == 29 && !memcmp(request->body.data, "grant_type=client_credentials", 29));
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, expected_auth));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
}

static void run(const br_detector *detector)
{
    char input[160], *authorization = NULL, *error = NULL;
    snprintf(input, sizeof(input), "roaring token - '%s'\nroaring token - '%s'\n", client, secret);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_pair(&results.items[0], secret, secret, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "roaring %s\nroaring %s", secret, "abcdefghijklmnopqrstuvwxyz01");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 4);
    check_pair(&results.items[0], secret, secret, false);
    check_pair(&results.items[3], "abcdefghijklmnopqrstuvwxyz01", "abcdefghijklmnopqrstuvwxyz01", false);
    br_results_clear(&results);
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)secret, 28},
                             (br_slice){(const unsigned char *)secret, 28}, &authorization, &error) == 0);
    free(error);
    expected_auth = authorization;
    snprintf(input, sizeof(input), "roaring token - '%s'\nroaring token - '%s'\n", client, secret);
    test_http http = {.response = {.status = 201}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && results.items[0].verified);
    br_results_clear(&results);
    http = (test_http){.response = {.status = 401}, .send_rc = 1, .send_error = "down", .inspect = inspect};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    free(authorization);
}

int main(void)
{
    run(descriptor());
    return test_finish("Roaring");
}
