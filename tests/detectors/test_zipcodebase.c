/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_zipcodebase_init(const br_detector **out, char **error);

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zipcodebase_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_zipcodebase_init(&detector, &error) == 0 && !error && detector->type == 825);
    CHECK(!strcmp(detector->name, "Zipcodebase") && !strcmp(detector->keywords[0], "zipcodebase"));
    CHECK(!strcmp(detector->description, "Zipcodebase is a service that provides access to a database of postal codes. The API keys can be used to query this database for information related to postal codes."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://app.zipcodebase.com/api/v1/search?codes=10005,10006"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 825);
    CHECK(!request->body.len && request->nheaders == 3);
    size_t accept = 0, api = 0;
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Accept")) {
            ++accept;
            CHECK(!strcmp(request->headers[i].value, "application/vnd.zipcodebase+json; version=3"));
        } else if (!strcmp(request->headers[i].name, "apikey")) {
            ++api;
            CHECK(!strcmp(request->headers[i].value, http->user));
        }
    }
    CHECK(accept == 1 && api == 1);
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "zipcodebase %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 825, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zipcodebase %s", "01234567-89AB-cdef-0123-456789abcdef");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zipcodebase %s", key);
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {201, false, "unexpected status code: 201"},
        {401, false, NULL}, {403, false, NULL}, {500, false, "unexpected status code: 500"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect, .user = (void *)key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(!strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char sensitive[80];
    snprintf(sensitive, sizeof(sensitive), "dial %s failed", key);
    test_http http = {.send_rc = 1, .send_error = sensitive, .inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    /* SetVerificationError is called with no secrets, so the key stays in the text. */
    CHECK(!results.items[0].verified && !strcmp(results.items[0].verification_error, sensitive));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, "net/http: nil Context"));
    test_key_result(&results.items[0], 825, key, "key");
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    verification(detector);
    return test_finish("Zipcodebase");
}
