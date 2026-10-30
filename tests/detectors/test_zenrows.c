/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_zenrows_init(const br_detector **out, char **error);

static char key[41];

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    test_secret(key, 40, 4);
    for (char *p = key; *p; ++p) if (*p >= 'a' && *p <= 'z') {
        if (*p > 'f') *p = (char)('a' + ((*p - 'a') % 6));
    }
    CHECK(br_zenrows_init(&detector, &error) == 0 && detector && detector->type == 824);
    CHECK(!strcmp(detector->name, "ZenRows") && !strcmp(detector->keywords[0], "zenrows"));
    CHECK(!strcmp(detector->description,
                  "ZenRows is a web scraping API service that allows users to extract data from "
                  "websites. ZenRows API keys can be used to access and scrape web data."));
    CHECK(detector->max_credential_span == -1 && detector->state && !detector->clean);
    CHECK(br_zenrows_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char url[120];
    (void)http;
    snprintf(url, sizeof(url), "https://api.zenrows.com/v1/?apikey=%s&url=https://httpbin.org/anything", key);
    CHECK(ctx && !strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 824);
    CHECK(!request->body.len && request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
}

static void run(const br_detector *detector)
{
    char input[80], bad[41], sensitive[96];
    snprintf(input, sizeof(input), "zenrows %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 824, key, "key");
    br_results_clear(&results);
    memcpy(bad, key, sizeof(bad));
    bad[0] = 'A';
    snprintf(input, sizeof(input), "zenrows %s", bad);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zenrows %s", key);
    snprintf(sensitive, sizeof(sensitive), "dial %s", key);
    const struct { int status, send_rc; const char *send_error, *error; bool verified; } cases[] = {
        {200, 0, NULL, NULL, true},
        {401, 0, NULL, NULL, false},
        {402, 0, NULL, NULL, false},
        {403, 0, NULL, "unexpected status code: 403", false},
        {500, 0, NULL, "unexpected status code: 500", false},
        {200, 1, sensitive, "dial [REDACTED]", false},
        {200, 1, NULL, "HTTP transport failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status, .body_error = "ignored drain"},
                          .send_rc = cases[i].send_rc, .send_error = cases[i].send_error, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error &&
                                  !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context") && !results.items[0].verified);
    br_results_clear(&results);
}

int main(void)
{
    run(descriptor());
    return test_finish("ZenRows");
}
