/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_zendeskapi_init(const br_detector **out, char **error);

static const char token[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
static const char email[] = "agent@mail.com";
static const char domain[] = "acme.zendesk.com";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zendeskapi_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_zendeskapi_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 95 && !strcmp(detector->name, "ZendeskApi"));
    CHECK(!strcmp(detector->description,
                  "Zendesk is a customer service platform. Zendesk API tokens can be used to access and modify customer service data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "zendesk"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(strlen(token) == 40);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "zendesk %s %s %s", token, email, domain);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 95, token, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", email, domain);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zendesk %s zendesk %s %s %s", token,
             "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", email, domain);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);
}

static int zd_status;
static bool zd_transport;
static bool zd_nil;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[80];
    snprintf(url, sizeof(url), "https://%s/api/v2/users.json", domain);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Basic ", 6));
    if (zd_transport) {
        http->send_error = "dial tcp: connection refused";
        return;
    }
    http->response.status = zd_status;
}

static void verification(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "zendesk %s %s %s", token, email, domain);
    zd_status = 200;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    zd_status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    zd_status = 404;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    zd_status = 500;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);
    zd_transport = true;
    http.send_rc = -1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error);
    br_results_clear(&results);
    zd_transport = false;
    zd_nil = true;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "nil Context"));
    br_results_clear(&results);
    (void)zd_nil;
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("zendeskapi");
}
