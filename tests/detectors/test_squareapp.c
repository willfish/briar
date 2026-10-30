/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_squareapp_init(const br_detector **out, char **error);

static const char prod_id[] = "sq0ige-a9khwVJOSwlzBvX0wp4j8t90s2d";
static const char prod_id2[] = "sq0idp-0123456789abcdefghijklmn";
static const char prod_secret[] = "sq0csp-0123456789abcdefghijABCDEFGHIJ0123456789";
static const char sandbox_id[] = "sandbox-sq0idb-hFAKEQrhLGgFAKELZEDgpo";
static const char sandbox_secret[] = "sandbox-sq0csb-o6cs8xFAKExEgIDGbzn2hFAKEZPbzhe713Q-FAKEfbY";
static const char *expect_url;
static const char *expect_secret;

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value)) return NULL;
    return json_object_get_string(value);
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[80], body[160], other[160];
    const char *id = strstr(expect_url, "sandbox") ? sandbox_id : prod_id;
    snprintf(authorization, sizeof(authorization), "Client %s", expect_secret);
    snprintf(body, sizeof(body),
             "{\"access_token\":\"fakeTruffleHogAccessTokenForVerification\",\"client_id\":\"%s\"}", id);
    snprintf(other, sizeof(other),
             "{\"access_token\":\"fakeTruffleHogAccessTokenForVerification\",\"client_id\":\"%s\"}", prod_id2);
    CHECK(ctx && !strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !strcmp(request->url, expect_url));
    bool id_match = request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len);
    bool other_match = request->body.len == strlen(other) && !memcmp(request->body.data, other, request->body.len);
    CHECK(id_match || other_match);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_squareapp_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 25 && !strcmp(detector->name, "SquareApp"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "sq0i"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description,
                  "Square is a financial services and mobile payment company. Square credentials can be used to access and manage payment processing and other financial services."));
    return detector;
}

static void check_id(const br_result *result, const char *id)
{
    CHECK(result->detector_type == 25 && result->raw.len == strlen(id) && !memcmp(result->raw.data, id, strlen(id)));
    CHECK(result->redacted && !strcmp(result->redacted, id) && !result->raw_v2.data);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), id));
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[320];
    snprintf(input, sizeof(input), "%s %s %s %s", prod_id, sandbox_id, prod_secret, sandbox_secret);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_id(&results.items[0], prod_id);
    CHECK(results.items[0].extra_data && !extra(&results.items[0], "Env") && !results.items[0].verified);
    check_id(&results.items[1], sandbox_id);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s %s %s", prod_id, prod_id2, prod_secret);
    expect_url = "https://connect.squareup.com/oauth2/revoke";
    expect_secret = prod_secret;
    test_http http = {.response = {.status = 404}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    CHECK(extra(&results.items[0], "Env") && !strcmp(extra(&results.items[0], "Env"), "Production"));
    br_results_clear(&results);

    http.response.status = 200;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !results.items[0].verified && !results.items[1].verified && http.calls == 2);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "unexpected status code: 200"));
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s %s", sandbox_id, sandbox_secret);
    expect_url = "https://connect.squareupsandbox.com/oauth2/revoke";
    expect_secret = sandbox_secret;
    http.response.status = 404;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(extra(&results.items[0], "Env") && !strcmp(extra(&results.items[0], "Env"), "Sandbox"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    CHECK(extra(&results.items[0], "Env") && !strcmp(extra(&results.items[0], "Env"), "Sandbox"));
    br_results_clear(&results);
    return test_finish("SquareApp");
}
