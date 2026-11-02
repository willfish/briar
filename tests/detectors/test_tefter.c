/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int tef_doc_rc;

int br_tefter_json_document(br_slice body, br_json **out, char **cause)
{
    if (tef_doc_rc) {
        if (out) *out = NULL;
        if (cause) *cause = NULL;
        return tef_doc_rc;
    }
    return br_json_document(body, out, cause);
}

int br_tefter_init(const br_detector **out, char **error);

static char key[21];
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "POST") &&
          !strcmp(request->url, "https://www.tefter.io/api/bookmarks?url=google.com"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 3);
    bool type = false, token = false;
    for (size_t i = 0; i < request->nheaders; ++i) {
        if (!strcmp(request->headers[i].name, "Content-Type"))
            type = !strcmp(request->headers[i].value, "application/json");
        if (!strcmp(request->headers[i].name, "X-User-Token"))
            token = !strcmp(request->headers[i].value, key);
    }
    CHECK(type && token);
}

int main(void)
{
    for (int i = 0; i < 20; ++i) key[i] = "0123456789abcdefghijklmnopqrstuvwxyz"[i % 36];
    key[20] = '\0';
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tefter_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 826 && !strcmp(detector->name, "Tefter"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "tefter"));
    CHECK(br_detector_is_default(detector, NULL));

    char input[80];
    snprintf(input, sizeof(input), "tefter %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 826, key, "key");
    br_results_clear(&results);
    const char mixed[] = "AbC0123456789defghij";
    snprintf(input, sizeof(input), "tefter %s", mixed);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 826, mixed, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "tefter %s", key);

    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{}", 2}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    http.response.body = (br_slice){(const unsigned char *)"null", 4};
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);

    http.response.body = (br_slice){(const unsigned char *)"not-json", 8};
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.response.status = 401;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);

    http.response.status = 200;
    http.response.body_error = "read failed";
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    http.response.body_error = NULL;
    http.send_rc = 1;
    http.send_error = "dial failed";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    tef_doc_rc = 2;
    http.send_rc = 0;
    http.send_error = NULL;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{}", 2}};
    http.inspect = inspect;
    br_results fatal = {0};
    char *scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot inspect Tefter body") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    tef_doc_rc = 0;
    return test_finish("tefter");
}
