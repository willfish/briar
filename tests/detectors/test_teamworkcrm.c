/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_teamworkcrm_init(const br_detector **out, char **error);

static void token(char *out, char tail)
{
    memcpy(out, "tkn.v1_", 7);
    for (size_t i = 0; i < 71; ++i) out[7 + i] = (char)('A' + (i % 26));
    out[7 + 10] = '9';
    out[78] = '=';
    out[79] = tail;
    out[80] = 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_teamworkcrm_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_teamworkcrm_init(&detector, &error) == 0 && !error && detector->type == 628);
    CHECK(!strcmp(detector->name, "TeamworkCRM"));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "teamwork") && !strcmp(detector->keywords[1], "teamworkcrm"));
    CHECK(!strcmp(detector->description, "TeamworkCRM is a customer relationship management tool that helps teams manage their sales pipeline and customer interactions. TeamworkCRM tokens can be used to access and manage CRM data and functionalities."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char expect[96];
    snprintf(expect, sizeof(expect), "Bearer %s", (const char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://example.teamwork.com/crm/api/v2/users.json"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 628);
    CHECK(request->nheaders == 2);
    size_t auth = 0;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, "Authorization")) {
            ++auth;
            CHECK(!strcmp(request->headers[i].value, expect));
        }
    CHECK(auth == 1);
}

static void extraction(const br_detector *detector)
{
    char raw[81], trimmed[80], input[160];
    token(raw, ' ');
    memcpy(trimmed, raw, 79);
    trimmed[79] = 0;
    snprintf(input, sizeof(input), "teamwork token = '%s'", raw);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 628, trimmed, "key");
    br_results_clear(&results);
    token(raw, '\n');
    snprintf(input, sizeof(input), "TEAMWORKCRM %s", raw);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 628, trimmed, "key");
    br_results_clear(&results);
    token(raw, '\r');
    snprintf(input, sizeof(input), "teamwork %snext", raw);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    memcpy(raw + 79, "x", 2);
    snprintf(input, sizeof(input), "teamwork %s", raw);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    token(raw, ' ');
    snprintf(input, sizeof(input), "%s teamwork", raw);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char raw[81], trimmed[80], input[160];
    token(raw, '\n');
    memcpy(trimmed, raw, 79);
    trimmed[79] = 0;
    snprintf(input, sizeof(input), "teamwork %s", raw);
    const int statuses[] = {200, 299, 401};
    for (size_t i = 0; i < 3; ++i) {
        test_http http = {.response = {.status = statuses[i]}, .inspect = inspect, .user = trimmed};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1);
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
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("TeamworkCRM");
}
