/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_reachmail_init(const br_detector **out, char **error);

static char key[65], other[65];
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[80];
    CHECK(len >= 0 && (size_t)len < sizeof(copy));
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    test_secret(key, 64, 1);
    test_secret(other, 64, 3);
    key[10] = '-';
    key[20] = '_';
    other[5] = 'A';
    CHECK(br_reachmail_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_reachmail_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 814 && !strcmp(detector->name, "Reachmail") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Reachmail is an email marketing service. Reachmail API keys can be used to access and manage email marketing campaigns and user data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "reachmail"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 814, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "reachmail %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "REACHMAIL=%s", other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], other, false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, key, 64);
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "reachmail %.63s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    char changed[65];
    memcpy(changed, key, 65);
    changed[0] = '.';
    snprintf(input, sizeof(input), "reachmail %s", changed);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

static int reach_status;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    const char *expected = http->user;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://services.reachmail.net/administration/users/current"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 814);
    CHECK(request->nheaders == 4 && !request->body.len && !request->dedup_key.len);
    CHECK(!strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "Authorization"));
    CHECK(!strncmp(request->headers[2].value, "Bearer ", 7) && !strcmp(request->headers[2].value + 7, expected));
    CHECK(!strcmp(request->headers[3].name, "User-Agent"));
    http->response.status = reach_status;
}

static void verification(const br_detector *detector)
{
    char input[96];
    snprintf(input, sizeof(input), "reachmail %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    reach_status = 200;
    test_http http = {.inspect = inspect, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);
    reach_status = 300;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    http.send_error = "timeout";
    http.send_rc = -1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[180];
    snprintf(input, sizeof(input), "reachmail %s\nreachmail %s", key, other);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 3, "prior", "key") && !br_results_push(&results, &prior));
    fail_finding_after = 2;
    char *error = NULL;
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create Reachmail result") && results.len == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    return test_finish("Reachmail 64-byte grammar, Bearer headers, 2xx, nil skip");
}
