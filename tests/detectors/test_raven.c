/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int raven_doc_rc;
static int raven_doc_calls;

int br_raven_json_document(br_slice body, br_json **out, char **cause)
{
    ++raven_doc_calls;
    if (raven_doc_rc) {
        if (out) *out = NULL;
        if (cause) *cause = NULL;
        return raven_doc_rc;
    }
    return br_json_document(body, out, cause);
}

int br_raven_init(const br_detector **out, char **error);

static const char key[] = "JJ4ZIC9EJNWVIS86";
static char seen_url[96];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    CHECK(!strcmp(request->method, "GET") && request->nheaders == 1);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 330);
    CHECK(!request->body.data && !strcmp(request->headers[0].name, "User-Agent"));
    snprintf(seen_url, sizeof(seen_url), "%s", request->url);
}

int main(void)
{
    CHECK(strlen(key) == 16);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_raven_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 330 && !strcmp(detector->name, "Raven") && detector->max_credential_span == -1);
    CHECK(!strcmp(detector->keywords[0], "raven"));
    CHECK(!strcmp(detector->description, "Raven credentials can be used to access and manage your Raven account and services."));
    char input[192];
    snprintf(input, sizeof(input), "RAVEN token = '%s'", key);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 330, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "raven token = '%s' | '%s'", key, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "raven %s raven %s", key, key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "raven keyword is not close to the real key in the data\n = '%s'", key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "raven jj4zic9ejnwvis86");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "raven %s", key);
    const char *bodies[] = {"null", "{}", "1", "  {\"ok\":true}  "};
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)bodies[i], strlen(bodies[i])}};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error && http.releases == 1);
        CHECK(!strcmp(seen_url, "https://api.raventools.com/api?key=JJ4ZIC9EJNWVIS86&method=profile_info&format=json"));
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"oops", 4}};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 500, .body = {(const unsigned char *)"null", 4}};
    raven_doc_rc = 2;
    raven_doc_calls = 0;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified);
    CHECK(raven_doc_calls == 0 && http.releases == 1);
    br_results_clear(&out);
    raven_doc_rc = 0;
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 200, .body_error = "short read"};
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!out.len && http.calls == 1 && http.releases == 1);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "down";
    http.response.body_error = NULL;
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error && http.releases == 1);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls);
    br_results_clear(&out);
    raven_doc_rc = 2;
    http.send_rc = 0;
    http.send_error = NULL;
    http.response = (br_http_response){.status = 200, .body = {(const unsigned char *)"{}", 2}};
    br_results fatal = {0};
    char *scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &fatal, &scan_error) != 0);
    CHECK(scan_error && !strcmp(scan_error, "cannot validate Raven response JSON") && !fatal.len);
    free(scan_error);
    br_results_clear(&fatal);
    raven_doc_rc = 0;
    return test_finish("Raven");
}
