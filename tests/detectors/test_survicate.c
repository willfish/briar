/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_survicate_init(const br_detector **out, char **error);

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_survicate_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 204 && !strcmp(detector->name, "Survicate"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "survicate"));
    CHECK(!strcmp(detector->description,
        "Survicate is a survey platform that allows users to collect feedback and insights from customers. "
        "Survicate API keys can be used to access and manage surveys and responses."));
    CHECK(br_survicate_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void expect_one(const br_detector *detector, const char *input, const char *key, size_t count)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == count);
    if (count) test_key_result(&results.items[0], 204, key, "key");
    br_results_clear(&results);
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://data-api.survicate.com/v1/surveys"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 204);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, http->user));
    CHECK(!strncmp(request->headers[0].value, "Basic ", 6));
}

static void test_verification(const br_detector *detector, const char *key)
{
    char input[80];
    snprintf(input, sizeof(input), "survicate %s", key);
    const struct { int status, send_rc; bool verified; } cases[] = {
        {200, 0, true}, {204, 0, true}, {401, 0, false}, {500, 0, false}, {200, 1, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .send_rc = cases[i].send_rc,
                          .send_error = cases[i].send_rc ? "dial failed" : NULL,
                          .inspect = inspect_request, .user = (void *)"Basic "};
        /* The header is the full Basic value. Rebuild the expected value in inspect via user. */
        char basic[64];
        snprintf(basic, sizeof(basic), "Basic %s", key);
        http.user = basic;
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == cases[i].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results skipped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    char key[33], short_key[32];
    test_secret(key, 32, 2);
    test_secret(short_key, 31, 2);
    expect_one(detector, "survicate token", NULL, 0);
    char input[96];
    snprintf(input, sizeof(input), "survicate %s", key);
    expect_one(detector, input, key, 1);
    snprintf(input, sizeof(input), "SURVICATE:%s", key);
    expect_one(detector, input, key, 1);
    snprintf(input, sizeof(input), "%s", key);
    expect_one(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "survicate %s", short_key);
    expect_one(detector, input, NULL, 0);
    char upper[33];
    memcpy(upper, key, 33);
    upper[1] = 'Q';
    snprintf(input, sizeof(input), "survicate %s", upper);
    expect_one(detector, input, NULL, 0);
    snprintf(input, sizeof(input), "survicate %s\nsurvicate %s", key, key);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);
    test_verification(detector, key);
    return test_finish("Survicate");
}
