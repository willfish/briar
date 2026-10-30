/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_wiz_init(const br_detector **out, char **error);

static const char *id = "lmSlx1fe6yCfwAbDa8pMp9sJDM9rZzDblmSlx1fe6yCfwAbDa8pMp";
static const char *secret = "lmSlx1fe6yCfwAbDa8pMp9sJDM9rZzDblmSlx1fe6yCfwAbDa8pMp9sJDM9rZzDb";
static const char *other = "nmSlx1fe6yCfwAbDa8pMp9sJDM9rZzDblmSlx1fe6yCfwAbDa8pMp9sJDM9rZzDb";

typedef struct { const char *id, *secret; } expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *want = http->user;
    char body[256];
    snprintf(body, sizeof(body),
             "audience=wiz-api&client_id=%s&client_secret=%s&grant_type=client_credentials",
             want->id, want->secret);
    CHECK(ctx && !strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://auth.app.wiz.io/oauth/token"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 984);
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Encoding") && !strcmp(request->headers[0].value, "UTF-8"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type"));
    CHECK(!strcmp(request->headers[1].value, "application/x-www-form-urlencoded"));
}

static void expect_pair(const br_result *result, const char *want_id, const char *want_secret)
{
    char raw_v2[160];
    snprintf(raw_v2, sizeof(raw_v2), "%s%s", want_id, want_secret);
    CHECK(result->detector_type == 984);
    CHECK(result->raw.len == strlen(want_id) && !memcmp(result->raw.data, want_id, result->raw.len));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &value));
    CHECK(!strcmp(json_object_get_string(value), want_id));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &value));
    CHECK(!strcmp(json_object_get_string(value), want_secret));
    CHECK(!result->extra_data);
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_wiz_init(&detector, &error) == 0 && !error && detector->type == 984);
    CHECK(!strcmp(detector->name, "Wiz") && !strcmp(detector->keywords[0], "wiz") &&
          detector->max_credential_span == 1024);
    CHECK(strlen(id) == 53 && strlen(secret) == 64 && strlen(other) == 64);
    char input[512];
    snprintf(input, sizeof(input), "wiz_client_id = '%s'\nwiz_client_secret = '%s'\n", id, secret);
    expected want = {id, secret};
    test_http http = {.inspect = inspect, .user = &want, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "wiz-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    expect_pair(&results.items[0], id, secret);
    br_results_clear(&results);

    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "wiz %s\nwiz %s\nwiz %s", id, secret, other);
    http.inspect = NULL;
    http.calls = http.releases = 0;
    http.response.status = 200;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    expect_pair(&results.items[0], id, secret);
    br_results_clear(&results);

    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    CHECK(!results.items[1].verified && !results.items[1].verification_error);
    br_results_clear(&results);

    http.response.status = 500;
    http.calls = http.releases = 0;
    snprintf(input, sizeof(input), "wiz %s\nwiz %s", id, secret);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);

    /* The sample secret starts with the id, so id is replaced first, as in Go. */
    char leaked[160];
    snprintf(leaked, sizeof(leaked), "denied %s", secret);
    http.send_rc = -1;
    http.send_error = leaked;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "denied [REDACTED]9sJDM9rZzDb"));
    CHECK(!strstr(results.items[0].verification_error, id));
    br_results_clear(&results);

    br_results nil_results = {0};
    char *nil_error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &nil_results, &nil_error) == 0 && !nil_error && nil_results.len == 1);
    CHECK(nil_results.items[0].verification_error &&
          !strcmp(nil_results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil_results);

    snprintf(input, sizeof(input), "wiz %s\nwiz %s\nwiz %s", id, id, secret);
    http.send_rc = 0;
    http.send_error = NULL;
    http.response.status = 401;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1);
    br_results_clear(&results);
    return test_finish("Wiz");
}
