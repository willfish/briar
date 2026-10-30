/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_sigopt_init(const br_detector **out, char **error);

static char key[49];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    test_secret(key, 48, 1);
    for (char *p = key; *p; ++p) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);
    CHECK(br_sigopt_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_sigopt_init(&detector, &error) == 0 && !error && detector && detector->type == 704);
    CHECK(!strcmp(detector->name, "Sigopt") && !strcmp(detector->keywords[0], "sigopt"));
    CHECK(!strcmp(detector->description,
                  "Sigopt is a platform for optimizing machine learning models. Sigopt API keys "
                  "can be used to access and manage experiments on the Sigopt platform."));
    CHECK(detector->max_credential_span == -1 && detector->state && !detector->clean);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char *authorization = NULL, *error = NULL;
    br_slice password = {0};
    CHECK(ctx && br_http_basic_auth((br_slice){(const unsigned char *)key, 48}, password, &authorization, &error) == 0);
    free(error);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.sigopt.com/v1/experiments"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 704);
    CHECK(!request->body.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, authorization));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    free(authorization);
    (void)http;
}

static void extraction(const br_detector *detector)
{
    char input[128], bad[49];
    const char *one[] = {key};
    snprintf(input, sizeof(input), "sigopt %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 704, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "SIGOPT %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, key, 48);
    CHECK(!results.len);
    br_results_clear(&results);
    memcpy(bad, key, sizeof(bad));
    bad[3] = 'a';
    snprintf(input, sizeof(input), "sigopt %s", bad);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "sigopt %s\nsigopt %s", key, key);
    const char *dups[] = {key, key};
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 704, dups[0], "key");
    test_key_result(&results.items[1], 704, dups[1], "key");
    br_results_clear(&results);
    (void)one;
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "sigopt %s", key);
    const int codes[] = {199, 200, 299, 300, 401};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        test_http http = {.response = {.status = codes[i], .body_error = "ignored"}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (codes[i] >= 200 && codes[i] < 300) && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    test_http http = {.inspect = inspect, .response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !http.calls);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Sigopt");
}
