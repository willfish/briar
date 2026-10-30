/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_textmagic_init(const br_detector **out, char **error);

static const char *key = "hnNIvpj0lNNChF5z5sAzsgku4CuL0u";
static const char *user = "kKVO9ZYWvpcZS0Zozc";

typedef struct { const char *key, *user; } expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *want = http->user;
    char *basic = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)want->user, strlen(want->user)},
                             (br_slice){(const unsigned char *)want->key, strlen(want->key)},
                             &basic, NULL) == 0);
    CHECK(ctx && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://rest.textmagic.com/api/v2/user"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 612);
    CHECK(request->nheaders == 3 && !request->body.data);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, basic));
    free(basic);
}

static void expect_pair(const br_result *result, const char *want_key, const char *want_user)
{
    char raw_v2[80];
    snprintf(raw_v2, sizeof(raw_v2), "%s%s", want_key, want_user);
    CHECK(result->raw.len == strlen(want_key) && !memcmp(result->raw.data, want_key, result->raw.len));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &value));
    CHECK(!strcmp(json_object_get_string(value), want_key));
    CHECK(json_object_object_get_ex(result->secret_parts, "username", &value));
    CHECK(!strcmp(json_object_get_string(value), want_user));
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_textmagic_init(&detector, &error) == 0 && !error && detector->type == 612);
    CHECK(!strcmp(detector->name, "Textmagic") && !strcmp(detector->keywords[0], "textmagic") &&
          detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description,
                  "Textmagic is a service for sending and receiving text messages. Textmagic API keys can be used to access and manage text messaging services."));
    char input[256];
    snprintf(input, sizeof(input), "textmagic '%s'\n'%s'\n", key, user);
    expected want = {key, user};
    test_http http = {.inspect = inspect, .user = &want, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "textmagic-test"};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    expect_pair(&results.items[0], key, user);
    br_results_clear(&results);

    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    http.calls = http.releases = 0;
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = -1;
    http.send_error = "context canceled";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    br_results skipped = {0};
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &skipped, &error) == 0 && !error && !skipped.len);

    snprintf(input, sizeof(input), "textmagic '%s'\n'%s'\n", "hnNIvpj0lNNChF5?5sAzsgku4CuL0u", "?KVO9ZYWvp?ZS0Zozc");
    http.send_rc = 0;
    http.send_error = NULL;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "textmagic %s\n%*s\ntextmagic alice\n%*s\ntextmagic bob", key, 41, "", 41, "");
    http.inspect = NULL;
    http.response.status = 299;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2);
    expect_pair(&results.items[0], key, "alice");
    expect_pair(&results.items[1], key, "bob");
    CHECK(results.items[0].verified && results.items[1].verified);
    br_results_clear(&results);
    return test_finish("Textmagic");
}
