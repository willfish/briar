/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_unplugg_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char body[] =
    "{\"data\":[{\"timestamp\":1466640000,\"value\":0.27589941523037853},"
    "{\"timestamp\":1466640900,\"value\":0.4059699097648263}],"
    "\"forecast_to\":1458136800,\"callback\":\"https://yourdomain.com/samplecallback\"}";

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 64);
    char copy[65]; memcpy(copy, value, 64); copy[64] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, bool verified)
{
    test_key_result(result, 539, key, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

typedef struct { int status; const char *send_error; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(ctx == steps->expected_ctx && http->releases == 0);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.unplu.gg/forecast"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 539);
    CHECK(request->body.len == 191 && !memcmp(request->body.data, body, 191));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Access-Token") && !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    http->response = (br_http_response){.status = steps->status};
    http->send_error = steps->send_error; http->send_rc = steps->send_error ? -1 : 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(key) == 64 && strlen(body) == 191);
    CHECK(br_unplugg_init(NULL, &error) == -1); free(error);
    CHECK(!br_unplugg_init(&detector, &error) && !error);
    CHECK(detector->type == 539 && !strcmp(detector->name, "Unplugg"));
    CHECK(!strcmp(detector->description, "Unplugg is a service for forecasting and data analysis. Unplugg API keys can be used to access and manipulate forecast data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "unplu") && detector->max_credential_span == -1);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[120];
    snprintf(input, sizeof(input), "unplugg %s", key); /* Keyword is the unplu prefix, not unplugg. */
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], false); br_results_clear(&results);
    snprintf(input, sizeof(input), "plug %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "unplu %s", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef0123456789abcdef012345");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "unplu %s", key);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "unplu %s", key);
    const int codes[] = {200, 201, 400};
    for (size_t i = 0; i < 3; ++i) {
        script steps = {.status = codes[i]};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        check_result(&results.items[0], codes[i] >= 200 && codes[i] < 300);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("Unplugg unplu keyword + exact forecast body + nil drop");
}
