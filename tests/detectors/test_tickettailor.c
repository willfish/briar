/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/http_internal.h"
#include "../support/detector_test.h"

int br_tickettailor_init(const br_detector **out, char **error);

static const char key[] = "sk_test_abc123_0123456789abcdef0123456789abcdef";

static int owned_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    test_http *http = user;
    CHECK(request->timeout_ms > 0 && request->timeout_ms <= 5000 && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.tickettailor.com/v1/events"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 840);
    CHECK(!ctx->cancelled && !strcmp(ctx->user_agent, "tickettailor-offline"));
    unsigned char dedup[51];
    memcpy(dedup, "840:", 4); memcpy(dedup + 4, key, 47);
    CHECK(request->dedup_key.len == 51 && !memcmp(request->dedup_key.data, dedup, 51));
    char *authorization = NULL; char *auth_error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)key, 47}, (br_slice){0}, &authorization, &auth_error) == 0 && !auth_error);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog tickettailor-offline"));
    free(authorization);
    return test_http_send(http, ctx, request, response, error);
}

static void owned_release(void *user, br_http_response *response)
{
    test_http_release(user, response);
}

int main(void)
{
    CHECK(strlen(key) == 47);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tickettailor_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 840 && !strcmp(detector->name, "Tickettailor"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
        "Tickettailor is an online ticketing platform that allows event organizers to sell tickets. Tickettailor API keys can be used to manage events, orders, and tickets programmatically."));
    CHECK(br_tickettailor_init(NULL, &error) != 0 && error); free(error);
    char input[160];
    snprintf(input, sizeof(input), "tickettailor %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 840, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "tickettailor %sAA", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].raw.len == 47);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "tickettailor %s tickettailor %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); br_results_clear(&results);
    snprintf(input, sizeof(input), "tickettailor keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "tickettailor %s", key);
    test_http http = {.response = {.status = 200}};
    br_http_owned_backend backend = {.transport = {&http, owned_send, owned_release}};
    br_http_client *client = NULL;
    CHECK(br_http_client_init(&client, backend, BR_HTTP_SANE, &error) == 0 && client && !error);
    br_scan_ctx ctx = {.transport = br_http_client_transport(client), .user_agent = "tickettailor-offline"};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 401; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 500; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);
    http.send_rc = 1; http.send_error = "dial tickettailor"; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    test_http borrowed = {.response = {.status = 200}};
    br_transport transport = test_transport(&borrowed);
    br_scan_ctx borrowed_ctx = {.transport = &transport};
    results = test_scan(detector, &borrowed_ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && !borrowed.calls);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    CHECK(br_http_client_drain(client, &error) == 0 && !error);
    br_http_client_destroy(client);
    return test_finish("TicketTailor");
}
