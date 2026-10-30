/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_requestfinance_init(const br_detector **out, char **error);

static const char key[] = "ABC1234-DEF5678-GHI9012-JKL3456";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_requestfinance_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_requestfinance_init(&detector, &error) == 0 && !error);
    CHECK(br_requestfinance_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 964 && !strcmp(detector->name, "RequestFinance"));
    CHECK(!strcmp(detector->description,
        "Request Finance is a platform for managing and automating invoices and payments. Request Finance credentials can be used to access and manage these financial operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "requestfinance"));
    CHECK(detector->max_credential_span == -1 && detector->scan && detector->state);
    CHECK(!detector->false_positive && !detector->custom_name[0]);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.request.finance/invoices"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 964);
    CHECK(!request->body.len && !request->dedup_key.len && request->nheaders == 2);
    size_t auth = 0;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization")) {
            ++auth;
            CHECK(!strcmp(request->headers[i].value, http->user));
        }
    CHECK(auth == 1);
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "requestfinance token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 964, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s requestfinance", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "REQUESTFINANCE %s\nrequestfinance %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 964, key, "key");
    test_key_result(&results.items[1], 964, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "requestfinance %s", "abc1234-DEF5678-GHI9012-JKL3456");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    memcpy(input, "requestfinance", 14);
    memset(input + 14, '-', 40);
    memcpy(input + 54, key, sizeof(key));
    results = test_scan(detector, NULL, false, input, 54 + sizeof(key) - 1);
    CHECK(results.len == 1);
    br_results_clear(&results);
    input[54] = 'x';
    memmove(input + 55, key, sizeof(key) - 1);
    results = test_scan(detector, NULL, false, input, 55 + sizeof(key) - 1);
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "requestfinance %s", key);
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {299, true, NULL}, {401, false, NULL},
        {400, false, "unexpected HTTP response status 400"},
        {403, false, "unexpected HTTP response status 403"},
        {500, false, "unexpected HTTP response status 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect, .user = (void *)key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char sensitive[80];
    snprintf(sensitive, sizeof(sensitive), "dial %s failed", key);
    test_http http = {.send_rc = 1, .send_error = sensitive, .inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "dial [REDACTED] failed"));
    CHECK(!strstr(results.items[0].verification_error, key));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("RequestFinance");
}
