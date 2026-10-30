/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_transferwise_init(const br_detector **out, char **error);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 36);
    char copy[37]; memcpy(copy, value, 36); copy[36] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 832, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

typedef struct { const char *key, *send_error; int status; } reply;
typedef struct { reply row; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(ctx == steps->expected_ctx && http->releases == 0);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.transferwise.com/v2/profiles"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 832);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.transferwise+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, steps->row.key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    http->response = (br_http_response){.status = steps->row.status};
    http->send_error = steps->row.send_error; http->send_rc = steps->row.send_error ? -1 : 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_transferwise_init(NULL, &error) == -1); free(error);
    CHECK(!br_transferwise_init(&detector, &error) && !error);
    CHECK(detector->type == 832 && !strcmp(detector->name, "Transferwise"));
    CHECK(!strcmp(detector->description, "TransferWise (now known as Wise) is an international money transfer service. TransferWise API keys can be used to access and manage money transfers."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "transferwise") && detector->max_credential_span == -1);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "transferwise %s\nTRANSFERWISE %s", key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false);
    check_result(&results.items[1], other, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "transferwise %s", "01234567-89AB-cdef-0123-456789abcdef");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "transferwise %s", key);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "transferwise %s", key);
    const int codes[] = {200, 299, 300, 401};
    for (size_t i = 0; i < 4; ++i) {
        script steps = {.row = {.key = key, .status = codes[i]}};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        check_result(&results.items[0], key, codes[i] >= 200 && codes[i] < 300);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("Transferwise profile bearer + Accept version header + nil drop");
}
