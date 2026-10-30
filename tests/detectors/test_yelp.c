/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_yelp_init(const br_detector **out, char **error);

static void fill(char *out, char seed)
{
    for (size_t i = 0; i < 128; ++i) out[i] = (char)('A' + ((seed + i) % 26));
    out[4] = '\\';
    out[9] = '=';
    out[12] = '.';
    out[20] = '-';
    out[21] = '_';
    out[128] = 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_yelp_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_yelp_init(&detector, &error) == 0 && !error && detector->type == 799);
    CHECK(!strcmp(detector->name, "Yelp") && !strcmp(detector->keywords[0], "yelp"));
    CHECK(!strcmp(detector->description, "Yelp API keys allow access to Yelp's business data and services. Unauthorized access can lead to data breaches and misuse of Yelp's services."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char expect[160];
    snprintf(expect, sizeof(expect), "Bearer %s", (const char *)http->user);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.yelp.com/v3/businesses/search?term=delis&latitude=37.786882&longitude=-122.399972"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 799);
    CHECK(request->nheaders == 2 && !request->body.len);
    size_t auth = 0;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization")) {
            ++auth;
            CHECK(!strcmp(request->headers[i].value, expect));
        }
    CHECK(auth == 1);
}

static void extraction(const br_detector *detector)
{
    char key[129], input[180];
    fill(key, 1);
    snprintf(input, sizeof(input), "yelp token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 799, key, "key");
    br_results_clear(&results);
    memset(key, '\\', 128);
    key[0] = 'A';
    key[127] = 'Z';
    key[128] = 0;
    snprintf(input, sizeof(input), "YELP %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    fill(key, 2);
    key[127] = 0;
    snprintf(input, sizeof(input), "yelp %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    fill(key, 3);
    snprintf(input, sizeof(input), "%s yelp", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char key[129], input[180];
    fill(key, 4);
    snprintf(input, sizeof(input), "yelp %s", key);
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, NULL},
        {404, false, "unexpected HTTP response status 404"},
    };
    for (size_t i = 0; i < 4; ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(!strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results dropped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(dropped.len == 0);
    br_results_clear(&dropped);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Yelp");
}
