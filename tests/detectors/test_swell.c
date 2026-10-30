/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_swell_init(const br_detector **out, char **error);

static const char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
static const char id[] = "store123";

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32);
    char copy[33]; memcpy(copy, value, 32); copy[32] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, bool verified)
{
    test_key_result(result, 365, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

typedef struct { int status; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    char *expected = NULL; char *error = NULL;
    CHECK(!br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                              (br_slice){(const unsigned char *)key, 32}, &expected, &error) && !error);
    CHECK(ctx == steps->expected_ctx);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.swell.store/products?limit=100"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 365);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, expected));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    free(expected);
    http->response = (br_http_response){.status = steps->status};
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(id) == 8);
    CHECK(br_swell_init(NULL, &error) == -1); free(error);
    CHECK(!br_swell_init(&detector, &error) && !error);
    CHECK(detector->type == 365 && !strcmp(detector->name, "Swell") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description, "Swell is an eCommerce platform that allows businesses to create and manage online stores. Swell API keys can be used to access and modify store data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "swell"));
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "swell %s %s", id, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], false); br_results_clear(&results);
    snprintf(input, sizeof(input), "swell %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); /* A 32-byte key is outside the 6-24 id window. */
    br_results_clear(&results);
    snprintf(input, sizeof(input), "swell %s %s", id, key);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "swell %s %s", id, key);
    script steps = {.status = 200};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
    check_result(&results.items[0], true);
    br_results_clear(&results);
    steps.status = 401;
    http = (test_http){.inspect = inspect, .user = &steps};
    transport = test_transport(&http); ctx.transport = &transport;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    check_result(&results.items[0], false);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("Swell id-password basic auth + key-only raw + nil drop");
}
