/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

int br_user_init(const br_detector **out, char **error);

static const char key[] = "9UgOsRfud4RTyBQpJQFOQiwNQcfeLGHH1DDoxhgzCvBmccmVQ7MYB0ai3LXGZNMf";
static const char host[] = "testdetector.user.com";

typedef struct { const char *url; const char *dedup; const char *token; } user_expect;

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                      br_http_response *response, char **error)
{
    test_http *http = user;
    user_expect *expect = http->user;
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= 10000 && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->detector_type == 274 && !request->body.len);
    CHECK(!ctx->cancelled && !strcmp(ctx->user_agent, "user-offline"));
    CHECK(!strcmp(request->url, expect->url));
    CHECK(request->dedup_key.len == strlen(expect->dedup) &&
          !memcmp(request->dedup_key.data, expect->dedup, request->dedup_key.len) &&
          !memchr(request->dedup_key.data, 0, request->dedup_key.len));
    char authorization[80];
    snprintf(authorization, sizeof(authorization), "Token %s", expect->token);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog user-offline"));
    return test_http_send(http, ctx, request, response, error);
}

static void owned_release(void *user, br_http_response *response)
{
    test_http_release(user, response);
}

static void check_pair(const br_result *result, const char *token, const char *endpoint)
{
    char raw_v2[160];
    snprintf(raw_v2, sizeof(raw_v2), "%s:%s", token, endpoint);
    CHECK(result->detector_type == 274 && !result->verified && !result->verification_error);
    CHECK(result->raw.len == 64 && !memcmp(result->raw.data, token, 64));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, strlen(raw_v2)));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), token));
    CHECK(json_object_object_get_ex(result->secret_parts, "endpoint", &part) &&
          !strcmp(json_object_get_string(part), endpoint));
    CHECK(!result->redacted && !result->extra_data && !result->primary_secret.data);
}

int main(void)
{
    CHECK(strlen(key) == 64);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_user_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 274 && !strcmp(detector->name, "User"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "user.com"));
    CHECK(detector->max_credential_span == 1024 && !strcmp(detector->cloud_endpoint, ""));
    CHECK(br_user_init(NULL, &error) != 0 && error); free(error);
    char input[220];
    snprintf(input, sizeof(input), "user token = '%s'\nurl = https://%s", key, host);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], key, "https://testdetector.user.com");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "user %s user %s https://%s", key, key, host);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); br_results_clear(&results);
    snprintf(input, sizeof(input), "https://%s", host);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "user %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "user%*s%s https://%s", 41, "", key, host);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    const char *configured[] = {"https://configured.user.com"};
    br_endpoints endpoints = {.configured = configured, .nconfigured = 1, .use_found = false};
    br_scan_ctx quiet = {.endpoints = &endpoints};
    snprintf(input, sizeof(input), "user %s https://%s", key, host);
    results = test_scan(detector, &quiet, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], key, "https://configured.user.com");
    br_results_clear(&results);
    const char *spaced[] = {"bad host"};
    br_endpoints spaced_endpoints = {.configured = spaced, .nconfigured = 1, .use_found = false};
    quiet.endpoints = &spaced_endpoints;
    results = test_scan(detector, &quiet, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], key, "https://bad%20host");
    br_results_clear(&results);

    user_expect expect = {.url = "https://testdetector.user.com/api/public/users/",
                          .dedup = "9UgOsRfud4RTyBQpJQFOQiwNQcfeLGHH1DDoxhgzCvBmccmVQ7MYB0ai3LXGZNMf:testdetector.user.com",
                          .token = key};
    test_http http = {.response = {.status = 200}, .user = &expect};
    br_http_owned_backend backend = {.transport = {&http, owned_send, owned_release}};
    br_http_client *client = NULL;
    CHECK(br_http_client_init(&client, backend, BR_HTTP_DETECTOR_PUBLIC, &error) == 0 && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "user-offline"};
    snprintf(input, sizeof(input), "user token = '%s'\nurl = https://%s", key, host);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verification_error); br_results_clear(&results);
    http.response.status = 410; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verification_error); br_results_clear(&results);
    http.response.status = 500; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    http.response.status = 200; http.send_rc = 1; http.send_error = "dial 9UgOsRfud4RTyBQpJQFOQiwNQcfeLGHH1DDoxhgzCvBmccmVQ7MYB0ai3LXGZNMf";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "dial [REDACTED]"));
    br_results_clear(&results);
    test_http borrowed = {.response = {.status = 200}};
    br_transport transport = test_transport(&borrowed);
    br_scan_ctx borrowed_ctx = {.transport = &transport};
    results = test_scan(detector, &borrowed_ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified &&
          !strcmp(results.items[0].verification_error, "unsupported HTTP request coalescing") && !borrowed.calls);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);

    user_expect missing = {.url = "https://missing.user.com/api/public/users/",
                           .dedup = "9UgOsRfud4RTyBQpJQFOQiwNQcfeLGHH1DDoxhgzCvBmccmVQ7MYB0ai3LXGZNMf:missing.user.com",
                           .token = key};
    http.user = &missing; http.send_rc = 1; http.send_error = "lookup missing.user.com: no such host";
    http.calls = http.releases = 0;
    snprintf(input, sizeof(input), "user %s https://missing.user.com", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.calls = http.releases = 0; http.send_rc = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls);
    br_results_clear(&results);
    CHECK(br_http_client_drain(client, &error) == 0 && !error);
    br_http_client_destroy(client);
    return test_finish("User");
}
