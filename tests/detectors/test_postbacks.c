/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_postbacks_init(const br_detector **out, char **error);

static const char key1[] = "1c73ff35-2415-fc58-8712-3d24f00cbe2a";
static const char key2[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
static const char body[] =
    "{\"url\": \"https://foo.com/bar\",\"send_at\": 1579049877,"
    "\"body_string\": \"{ \\\"email_id\\\":\\\"123456789\\\" }\"}";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && !strcmp(request->method, "POST") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 10000 && !request->dedup_key.len);
    CHECK(!strcmp(request->url, "https://api.postbacks.io/v1/requestPostback"));
    CHECK(request->body.len == 100 && !memcmp(request->body.data, body, 100));
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Postbacks-Authorization") && !strcmp(request->headers[1].value, key1));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_postbacks_init(&detector, &error) == 0 && !error);
    CHECK(br_postbacks_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 822 && !strcmp(detector->name, "Postbacks"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "postbacks"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Postbacks are used to send data to a specified URL based on certain events or triggers. Postback URLs are often used in affiliate marketing, ad tracking, and analytics."));
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "POSTBACKS%*s%s postbacks %s", 40, "", key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 822, key1, "key");
    test_key_result(&results.items[1], 822, key2, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "postbacks%*s%s", 41, "", key1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    const char upper[] = "postbacks 1C73FF35-2415-FC58-8712-3D24F00CBE2A";
    results = test_scan(detector, NULL, false, upper, sizeof(upper) - 1);
    CHECK(results.len == 0);
    br_results_clear(&results);
    char raw[64];
    memcpy(raw, "\0postbacks ", 11);
    memcpy(raw + 11, key1, 36);
    results = test_scan(detector, NULL, false, raw, 47);
    CHECK(results.len == 1 && results.items[0].raw.len == 36);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "postbacks %s", key1);
    const int statuses[] = {200, 299, 300, 401};
    for (size_t i = 0; i < 4; ++i) {
        test_http http = {.response = {.status = statuses[i]}, .inspect = inspect};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    _Static_assert(sizeof(body) - 1 == 100, "postbacks body");
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Postbacks");
}
