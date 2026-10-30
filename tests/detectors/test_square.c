/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_square_init(const br_detector **out, char **error);

static char token[65];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://connect.squareupsandbox.com/v2/merchants"));
    CHECK(request->nheaders == 3);
    char bearer[80];
    snprintf(bearer, sizeof(bearer), "Bearer %s", token);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, bearer));
    CHECK(!strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
}

int main(void)
{
    memcpy(token, "EAAA", 4);
    memset(token + 4, 'a', 60);
    token[64] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_square_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 14 && !strcmp(detector->keywords[0], "EAAA"));
    CHECK(detector->max_credential_span == -1);
    char input[160];
    snprintf(input, sizeof(input), "square %s", token);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_json *guide = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "rotation_guide", &guide));
    CHECK(!strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/square/"));
    br_results_clear(&results);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.send_rc = 1;
    http.send_error = "dial tcp: connection refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "SQUARE nearby %s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "unrelated %s", token);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    return test_finish("Square");
}
