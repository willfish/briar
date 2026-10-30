/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_simplynoted_init(const br_detector **out, char **error);

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len >= 340 && len <= 360);
    char *copy = malloc((size_t)len + 1); CHECK(copy);
    memcpy(copy, value, (size_t)len); copy[len] = '\0';
    struct json_object *object = json_object_new_string(copy);
    free(copy);
    return object;
}

static char *token(size_t len, char fill)
{
    char *out = malloc(len + 1); CHECK(out);
    memset(out, fill, len); out[len] = '\0';
    return out;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 661, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

typedef struct { const char *key, *send_error; int status; } reply;
typedef struct { reply row; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(ctx == steps->expected_ctx && http->releases == 0);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.simplynoted.com/api/products"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 661);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[0].value + 7, steps->row.key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    http->response = (br_http_response){.status = steps->row.status};
    http->send_error = steps->row.send_error; http->send_rc = steps->row.send_error ? -1 : 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(br_simplynoted_init(NULL, &error) == -1); free(error);
    CHECK(!br_simplynoted_init(&detector, &error) && !error);
    CHECK(detector->type == 661 && !strcmp(detector->name, "SimplyNoted"));
    CHECK(!strcmp(detector->description, "SimplyNoted is a service used for sending personalized handwritten notes. SimplyNoted API keys can be used to access and send these notes programmatically."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "simplynoted") && detector->max_credential_span == -1);
    return detector;
}

static void expect_len(const br_detector *detector, size_t n, size_t matches)
{
    char *value = token(n, 'a');
    char *input = malloc(n + 32); CHECK(input);
    snprintf(input, n + 32, "simplynoted %s", value);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == matches);
    if (matches) check_result(&results.items[0], value, false);
    br_results_clear(&results);
    free(input); free(value);
}

static void extraction(const br_detector *detector)
{
    expect_len(detector, 339, 0);
    expect_len(detector, 340, 1);
    expect_len(detector, 360, 1);
    expect_len(detector, 361, 0);
    char *value = token(350, 'B');
    char *input = malloc(800); CHECK(input);
    snprintf(input, 800, "SIMPLYNOTED%*s%s", 40, "", value);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], value, false); br_results_clear(&results);
    snprintf(input, 800, "simplynoted%*s%s", 41, "", value);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, 800, "simplynoted %s", value);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    free(input); free(value);
}

static void verification(const br_detector *detector)
{
    char *value = token(350, 'c');
    char *input = malloc(400); CHECK(input);
    snprintf(input, 400, "simplynoted %s", value);
    const int codes[] = {200, 204, 299, 300, 401};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.row = {.key = value, .status = codes[i]}};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        check_result(&results.items[0], value, codes[i] >= 200 && codes[i] < 300);
        br_results_clear(&results);
    }
    script steps = {.row = {.key = value, .status = 200, .send_error = "timeout"}};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    check_result(&results.items[0], value, false);
    br_results_clear(&results);
    free(input); free(value);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("SimplyNoted 340-360 non-whitespace token + nil drop + 2xx");
}
