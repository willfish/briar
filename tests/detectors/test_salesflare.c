/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_salesflare_init(const br_detector **out, char **error);

static const char key[] = "7dgVfsiOYJhYmw5aQc9DfE6V5jLPuhN2LzsTkhn32KRaZ";
static const char other[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.salesflare.com/me/contacts"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 217);
    CHECK(request->nheaders == 2 && !request->body.len && !request->dedup_key.len);
    char authorization[64];
    snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog salesflare-offline"));
}

static void identity(const br_detector *detector)
{
    CHECK(detector->type == 217 && !detector->version && !strcmp(detector->name, "Salesflare"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "salesflare"));
    CHECK(detector->max_credential_span == -1 && detector->scan && !detector->false_positive);
    CHECK(!strcmp(detector->description,
        "Salesflare is a simple yet powerful CRM tool for small businesses. Salesflare API keys can be used to access and manage customer data and interactions."));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_salesflare_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_salesflare_init(NULL, &error) != 0 && error);
    free(error);
    identity(detector);
    char input[128];
    snprintf(input, sizeof(input), "salesflare token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); test_key_result(&results.items[0], 217, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "salesflare %s SALESFLARE %s", key, other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 217, key, "key");
    test_key_result(&results.items[1], 217, other, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "salesflare keyword is not close to the real key in the data\n = '%s'", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "salesflare = '%s'", "7dgVfsiOYJhYmw5aQc9DfE?V5jLPuhN2LzsTkhn32KRaZ");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "salesflare token = '%s' | '%s'", key, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); br_results_clear(&results);
    snprintf(input, sizeof(input), "salesflare %s", key);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "salesflare-offline"};
    static const int statuses[] = {200, 299, 199, 401};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.response.status = statuses[i]; http.calls = http.releases = 0;
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    http.send_rc = 1; http.send_error = "dial salesflare"; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); br_results_clear(&results);
    br_result sentinel = {.detector_type = 7};
    sentinel.raw.data = malloc(1); CHECK(sentinel.raw.data); sentinel.raw.len = 1;
    results = (br_results){0}; CHECK(br_results_push(&results, &sentinel) == 0);
    size_t cap = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Salesflare result") && results.len == 1);
    free(error); results.cap = cap; br_results_clear(&results);
    return test_finish("Salesflare");
}
