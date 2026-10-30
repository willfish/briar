/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

#include <json-c/json.h>
#include <string.h>

int br_uri_init(const br_detector **, char **);

static const char valid[] = "https://kaNydBSAodo87dsm9asuiSAFtsd7.com:1234@qYY3SylY7fHP";
static const char local[] = "http://username:password@127.0.0.1";
static const char pathed[] = "http://user:secret@example.com/foo/";
static char seen_urls[2][160];
static size_t seen;
static int scripted;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000 && request->detector_type == 17);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(seen < 2);
    snprintf(seen_urls[seen], sizeof(seen_urls[seen]), "%s", request->url);
    ++seen;
    if (!scripted) return;
    if (http->calls == 1) http->response = (br_http_response){.status = 200};
    else {
        static const br_header challenge[] = {{"WWW-Authenticate", "Basic realm=\"x\""}};
        http->response = (br_http_response){.status = 401, .headers = challenge, .nheaders = 1};
    }
}

static void check_parts(const br_result *result, const char *host, const char *user, const char *password,
                        const char *raw, const char *raw_v2, const char *redacted)
{
    CHECK(result->detector_type == 17 && result->detector_name && !strcmp(result->detector_name, "URI"));
    CHECK(result->raw.len == strlen(raw) && !memcmp(result->raw.data, raw, result->raw.len));
    CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "host", &part) && !strcmp(json_object_get_string(part), host));
    CHECK(json_object_object_get_ex(result->secret_parts, "username", &part) && !strcmp(json_object_get_string(part), user));
    CHECK(json_object_object_get_ex(result->secret_parts, "password", &part) && !strcmp(json_object_get_string(part), password));
}

static void exercise(const br_detector *detector)
{
    const char *html = "uri token = '<p><a href=\"http://username:password@127.0.0.1\">http://username:password@127.0.0.1</a></p>'";
    br_results out = test_scan(detector, NULL, false, html, strlen(html));
    CHECK(out.len == 1);
    check_parts(&out.items[0], "127.0.0.1", "username", "password", local, local,
                "http://username:********@127.0.0.1");
    br_results_clear(&out);
    char input[256];
    snprintf(input, sizeof(input), "uri token = '%s'", valid);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    check_parts(&out.items[0], "qYY3SylY7fHP", "kaNydBSAodo87dsm9asuiSAFtsd7.com", "1234", valid, valid,
                "https://kaNydBSAodo87dsm9asuiSAFtsd7.com:********@qYY3SylY7fHP");
    br_results_clear(&out);
    const char *invalid = "uri = 'https://kaNydBSAodo87dsm9asuiSAFtsd7.com.1234@qYY3SylY7fHP'";
    out = test_scan(detector, NULL, false, invalid, strlen(invalid));
    CHECK(!out.len);
    br_results_clear(&out);
    const char *skipped[] = {
        "http://user:***@example.com/x",
        "http://user:%2A%2A%2A@example.com/x",
        "http://user:$abc@example.com/x",
        "http://user:pass@httpbin.org/anything",
        "http://user:pass@www.httpwatch.com/httpgallery",
    };
    for (size_t i = 0; i < sizeof(skipped) / sizeof(skipped[0]); ++i) {
        out = test_scan(detector, NULL, false, skipped[i], strlen(skipped[i]));
        CHECK(!out.len);
        br_results_clear(&out);
    }
    /* The trailing slash is outside the final word boundary, so it is not captured. */
    out = test_scan(detector, NULL, false, pathed, strlen(pathed));
    CHECK(out.len == 1);
    check_parts(&out.items[0], "example.com", "user", "secret",
                "http://user:secret@example.com", "http://user:secret@example.com/foo",
                "http://user:********@example.com/foo");
    br_results_clear(&out);
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    seen = 0;
    scripted = 1;
    out = test_scan(detector, &ctx, true, pathed, strlen(pathed));
    scripted = 0;
    CHECK(out.len == 1 && out.items[0].verified && http.calls == 2 && http.releases == 2 && seen == 2);
    CHECK(!strcmp(seen_urls[0], "http://user:secret@example.com/foo"));
    CHECK(!strcmp(seen_urls[1], "http://example.com/foo"));
    br_results_clear(&out);
    seen = 0;
    http.calls = http.releases = 0;
    http.response = (br_http_response){.status = 401};
    out = test_scan(detector, &ctx, true, pathed, strlen(pathed));
    CHECK(out.len == 1 && !out.items[0].verified && http.calls == 1 && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = 0;
    out = test_scan(detector, NULL, true, pathed, strlen(pathed));
    CHECK(out.len == 1 && out.items[0].verification_error &&
          !strcmp(out.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&out);
    char *reason = (char *)"set";
    CHECK(!detector->false_positive(detector, NULL, &reason) && !reason);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_uri_init(&detector, &error) == 0 && detector && detector->type == 17 && detector->nkeywords == 2);
    CHECK(!strcmp(detector->keywords[0], "http://") && !strcmp(detector->keywords[1], "https://"));
    CHECK(detector->false_positive && detector->max_credential_span == -1);
    exercise(detector);
    return test_finish("URI");
}
