/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_statuspage_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdef0123456789abcdef0123";
static const char other[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_statuspage_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_statuspage_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 775 && !strcmp(detector->name, "Statuspage") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Statuspage is an incident communication tool that helps you inform your users about outages and scheduled maintenance. Statuspage API keys can be used to manage and update your status pages."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "statuspage"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(strlen(key) == 36 && strlen(other) == 36);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "statuspage %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 775, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "STATUSPAGE=%s", other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 775, other, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "statuspage %s statuspage %s", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "statuspage %c%s", 'A', key + 1);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, key, 36);
    CHECK(!results.len);
    br_results_clear(&results);
}

static int page_status;
static bool page_transport;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api.statuspage.io/v1/pages"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!request->body.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") &&
          !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") &&
          !strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") &&
          !strcmp(request->headers[2].value, "TruffleHog"));
    if (page_transport) {
        http->send_error = "dial tcp: connection refused";
        return;
    }
    http->response.status = page_status;
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "statuspage %s", key);
    page_status = 200;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    br_results_clear(&results);
    page_status = 199;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    page_transport = true;
    http.send_rc = -1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("statuspage");
}
