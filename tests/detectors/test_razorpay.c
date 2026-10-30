/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int razor_doc_rc;
static int razor_doc_calls;

int br_razorpay_json_document(br_slice body, br_json **out, char **cause)
{
    ++razor_doc_calls;
    if (razor_doc_rc) {
        if (out) *out = NULL;
        if (cause) *cause = NULL;
        return razor_doc_rc;
    }
    return br_json_document(body, out, cause);
}

int br_razorpay_init(const br_detector **out, char **error);

static const char key[] = "rzp_live_ABCDEFGHIJKLMN";
static const char secret[] = "abcdefghijklmnopqrstuvwx";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.razorpay.com/v1/items?count=1"));
    CHECK(request->profile == BR_HTTP_SANE && request->nheaders == 2);
    char *expected = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)key, strlen(key)},
                             (br_slice){(const unsigned char *)secret, strlen(secret)}, &expected, NULL) == 0);
    bool auth = false;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization"))
            auth = !strcmp(request->headers[i].value, expected);
    free(expected);
    CHECK(auth);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_razorpay_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 11 && !strcmp(detector->name, "RazorPay") && detector->max_credential_span == 1024);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "rzp_live_"));
    CHECK(detector->state && detector->scan); /* Registry tests own default enablement. */

    char input[128];
    snprintf(input, sizeof(input), "%s %s", key, secret);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(key) && !memcmp(results.items[0].raw.data, key, strlen(key)));
    CHECK(results.items[0].raw_v2.len == strlen(key) + strlen(secret) &&
          !memcmp(results.items[0].raw_v2.data, key, strlen(key)) &&
          !memcmp(results.items[0].raw_v2.data + strlen(key), secret, strlen(secret)));
    CHECK(results.items[0].redacted && !strcmp(results.items[0].redacted, key));
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s %s %s", key, secret, secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);

    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{}", 2}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "%s %s", key, secret);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);

    http.response.body = (br_slice){(const unsigned char *)"[", 1};
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    http.response.body_error = "read failed";
    http.calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    razor_doc_rc = 2;
    razor_doc_calls = 0;
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{}", 2}};
    http.send_rc = 1;
    http.send_error = "send failed";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1 && razor_doc_calls == 0);
    br_results_clear(&results);
    http.send_rc = 0;
    http.send_error = NULL;
    http.calls = http.releases = 0;
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1 && razor_doc_calls == 0);
    br_results_clear(&results);
    http.response.status = 200;
    br_results fatal = {0};
    char *scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot inspect RazorPay body") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    razor_doc_rc = 0;
    return test_finish("razorpay");
}
