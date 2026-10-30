/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_zenscrape_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://app.zenscrape.com/api/v1/status"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "apikey"));
    CHECK(!strcmp(request->headers[0].value, http->user));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 552);
    CHECK(!request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zenscrape_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 552 && !strcmp(detector->keywords[0], "zenscrape"));
    const char *key = "01234567-89ab-cdef-0123-456789abcdef";
    char input[160];
    snprintf(input, sizeof(input), "zenscrape %s", key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 552, key, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "zenscrape 01234567-89AB-cdef-0123-456789abcdef");
    br_results upper = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(upper.len == 0);
    br_results_clear(&upper);
    snprintf(input, sizeof(input), "zenscrape %s\nzenscrape %s", key, key);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "zenscrape %s", key);
    const struct { int status; bool verified; const char *cause; } cases[] = {
        {200, true, NULL}, {429, true, NULL}, {401, false, NULL}, {403, false, NULL},
        {500, false, "unexpected status code: 500"}, {201, false, "unexpected status code: 201"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect_request, .user = (void *)key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified && http.calls == 1);
        if (cases[i].cause) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].cause));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http failed = {.send_rc = 1, .send_error = "dial failed", .inspect = inspect_request, .user = (void *)key};
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    br_results dial = test_scan(detector, &failed_ctx, true, input, strlen(input));
    CHECK(dial.len == 1 && !dial.items[0].verified);
    CHECK(dial.items[0].verification_error && !strcmp(dial.items[0].verification_error, "dial failed"));
    br_results_clear(&dial);
    br_results nil = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(nil.len == 1 && !nil.items[0].verified);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
    CHECK(nil.items[0].verification_error && !strcmp(nil.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&nil);
    return test_finish("Zenscrape");
}
