/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_prospectcrm_init(const br_detector **out, char **error);

static const char key[] = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3";
static const char other[] = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[40];
    CHECK(len >= 0 && (size_t)len < sizeof(copy));
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_prospectcrm_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_prospectcrm_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 275 && !strcmp(detector->name, "ProspectCRM") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "ProspectCRM is a customer relationship management system. The API keys can be used to access and manage customer data within ProspectCRM."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "prospectcrm"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 275, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[128], changed[40];
    /* Prefix is prospect, not the prospectcrm keyword. */
    snprintf(input, sizeof(input), "prospect %s", key);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "prospectcrm=%s", other);
    expect_one(detector, input, other);
    snprintf(input, sizeof(input), "PROSPECT\n%s", key);
    expect_one(detector, input, key);
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "pro spect %s", key);
    expect_one(detector, input, NULL);
    memcpy(changed, key, 33);
    changed[0] = 'B';
    snprintf(input, sizeof(input), "prospect %s", changed);
    expect_one(detector, input, NULL);
    memcpy(changed, key, 33);
    changed[2] = changed[10] = '-';
    snprintf(input, sizeof(input), "prospect %s", changed);
    expect_one(detector, input, changed);
    snprintf(input, sizeof(input), "prospect %s-", key);
    expect_one(detector, input, key);
    for (int gap = 40; gap <= 41; ++gap) {
        char gap_input[96];
        memcpy(gap_input, "prospect", 8);
        memset(gap_input + 8, '.', gap);
        memcpy(gap_input + 8 + gap, key, 32);
        br_results results = test_scan(detector, NULL, false, gap_input, (size_t)(8 + gap + 32));
        CHECK(results.len == (gap == 40 ? 1u : 0u));
        br_results_clear(&results);
    }
}

static int prospect_status;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    const char *expected = http->user;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://api-batch-v1.prospect365.com/Contacts"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 275);
    CHECK(!request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strncmp(request->headers[0].value, "Bearer ", 7) && !strcmp(request->headers[0].value + 7, expected));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    http->response.status = prospect_status;
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "prospect %s\nprospect %s", key, other);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    prospect_status = 204;
    test_http http = {.inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(input, sizeof(input), "prospect %s", key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);
    http.user = (void *)other;
    prospect_status = 401;
    snprintf(input, sizeof(input), "prospect %s", other);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], other, false);
    br_results_clear(&results);
    http.send_error = "dial failed";
    http.send_rc = -1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], other, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "prospect %s\nprospect %s", key, key);
    http.send_error = NULL;
    http.send_rc = 0;
    http.user = (void *)key;
    prospect_status = 200;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 5 && http.releases == 5);
    check_result(&results.items[0], key, true);
    check_result(&results.items[1], key, true);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "prospect %s\nprospect %s", key, other);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 9, "prior", "key") && !br_results_push(&results, &prior));
    fail_finding_after = 2;
    char *error = NULL;
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create ProspectCRM result") && results.len == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    return test_finish("ProspectCRM prospect prefix, Bearer, 2xx, duplicates, nil skip");
}
