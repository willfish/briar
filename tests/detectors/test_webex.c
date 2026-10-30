/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int force_doc;
static int (*real_document)(br_slice, br_json **, char **) = br_json_document;
static int doc_hook(br_slice body, br_json **out, char **cause)
{
    if (force_doc) { *out = NULL; *cause = NULL; return force_doc; }
    return real_document(body, out, cause);
}
#define br_json_document doc_hook
#include "../../src/detectors/webex.c"
#undef br_json_document

static const char key1[] = "abababababababababababababababababababababababababababababababab";
static const char key2[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char id1[] = "Ccdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcc";
static const char *expect_key;
static const char *expect_id;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char body[512];
    snprintf(body, sizeof(body),
             "grant_type=authorization_code&code=362ad374-735c-4f69-aa8e-bf384f8602de&client_id=%s&client_secret=%s&redirect_uri=http%%3A%%2F%%2Flocalhost.com%%2Fb",
             expect_id, expect_key);
    CHECK(ctx && !strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !strcmp(request->url, "https://webexapis.com/v1/access_token"));
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_webex_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 101 && !strcmp(detector->name, "Webex"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "webex"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->description,
                  "Webex is a collaboration tool that provides video conferencing, online meetings, screen share, and webinars. Webex API keys can be used to access and manage these services."));
    return detector;
}

int main(void)
{
    CHECK(strlen(key1) == 64 && strlen(id1) == 65 && id1[0] == 'C');
    const br_detector *detector = descriptor();
    char input[220];
    snprintf(input, sizeof(input), "WEBEX %s webex %s webex %s", key1, key2, id1);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 101, key1, "key");
    test_key_result(&results.items[1], 101, key2, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "webex%*s%s webex %s", 41, "", key1, id1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "webex %s webex %s", key1, id1);
    expect_key = key1;
    expect_id = id1;
    const char matched[] = "{\"message\":\"ERROR: redirect_uri_mismatch\"}";
    test_http http = {.response = {.status = 400, .body = {(const unsigned char *)matched, sizeof(matched) - 1}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);
    const char bare[] = "{\"message\":\"redirect_uri_mismatch\"}";
    http.response.body = (br_slice){(const unsigned char *)bare, sizeof(bare) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    const char bad[] = "{";
    http.response.body = (br_slice){(const unsigned char *)bad, 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    const char folded[] = "{\"MESSAGE\":\"ERROR: redirect_uri_mismatch\"}";
    http.response.body = (br_slice){(const unsigned char *)folded, sizeof(folded) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    const char dup[] = "{\"message\":\"first\",\"message\":\"ERROR: redirect_uri_mismatch\"}";
    http.response.body = (br_slice){(const unsigned char *)dup, sizeof(dup) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    const char typed[] = "{\"message\":1,\"message\":\"ERROR: redirect_uri_mismatch\"}";
    http.response.body = (br_slice){(const unsigned char *)typed, sizeof(typed) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    const char later[] = "{\"message\":1,\"message\":true}";
    http.response.body = (br_slice){(const unsigned char *)later, sizeof(later) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    force_doc = 1;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    force_doc = 2;
    http.calls = http.releases = 0;
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    force_doc = 0;
    http.send_rc = -1;
    http.send_error = "dial failed";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && http.releases == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("Webex");
}
