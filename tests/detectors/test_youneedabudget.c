/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_youneedabudget_init(const br_detector **out, char **error);

static const char key1[] = "abababababababababababababababababababababababababababababababab";
static const char key2[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    char authorization[80];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key1);
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_SANE);
    CHECK(request->timeout_ms == 5000 && !request->body.len);
    CHECK(!strcmp(request->url, "https://api.youneedabudget.com/v1/user"));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_youneedabudget_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 464 && !strcmp(detector->name, "YouNeedABudget"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "youneedabudget"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "YouNeedABudget is a budgeting tool that allows users to manage their personal finances. The API keys can be used to access and modify a user's financial data."));
    return detector;
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[220];
    snprintf(input, sizeof(input), "YOUNEEDABUDGET%*s%s youneedabudget %s", 40, "", key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 464, key1, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "youneedabudget %s", "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "youneedabudget %s", key1);
    test_http http = {.response = {.status = 299}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 300;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("YouNeedABudget");
}
