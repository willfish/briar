/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_sheety_init(const br_detector **out, char **error);

static const char key[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char other[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char id[] = "0123456789abcdef0123456789abcdef";

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 64);
    char copy[65]; memcpy(copy, value, 64); copy[64] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 469, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

typedef struct { const char *key, *id; int status; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    char url[80];
    snprintf(url, sizeof(url), "https://api.sheety.co/%s/restaurantMenu/menuItems", steps->id);
    CHECK(ctx == steps->expected_ctx && strlen(url) == 79);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 469);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, steps->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    http->response = (br_http_response){.status = steps->status};
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(key) == 64 && strlen(id) == 32);
    CHECK(br_sheety_init(NULL, &error) == -1); free(error);
    CHECK(!br_sheety_init(&detector, &error) && !error);
    CHECK(detector->type == 469 && !strcmp(detector->name, "Sheety") && detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description, "Sheety is a service that allows you to turn Google Sheets into a REST API. Sheety API keys can be used to access and modify the data in your Google Sheets."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "sheety"));
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[220];
    snprintf(input, sizeof(input), "sheety %s %s", id, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    snprintf(input, sizeof(input), "sheety %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "sheety %s %s\nsheety %s %s", id, key, id, other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 4); /* Two keys times two ids, key-major. */
    check_result(&results.items[0], key, false);
    check_result(&results.items[1], key, false);
    check_result(&results.items[2], other, false);
    check_result(&results.items[3], other, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sheety %s %s", id, key);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[120]; snprintf(input, sizeof(input), "sheety %s %s", id, key);
    script steps = {.key = key, .id = id, .status = 204};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);
    steps.status = 404;
    http = (test_http){.inspect = inspect, .user = &steps};
    transport = test_transport(&http); ctx.transport = &transport;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("Sheety key-only raw pairs + id URL + nil pair drop");
}
