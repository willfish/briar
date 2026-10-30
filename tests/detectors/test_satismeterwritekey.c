/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_satismeterwritekey_init(const br_detector **out, char **error);

static const char project[] = "AbCdEfGh1234567890IjKlMn";
static const char write_key[] = "abcdefghijklmnopqrstuvwxyz012345";
static const char token[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
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
    CHECK(strlen(project) == 24 && strlen(write_key) == 32 && strlen(token) == 32);
    CHECK(br_satismeterwritekey_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_satismeterwritekey_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 231 && !strcmp(detector->name, "SatismeterWritekey") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Satismeter is a customer feedback platform. Satismeter Writekeys can be used to send event data to Satismeter's API."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "satismeter"));
    CHECK(detector->max_credential_span == -1 && detector->max_secret_size == -1);
    return detector;
}

static void check_pair(const br_result *result, const char *write, bool verified)
{
    CHECK(result->detector_type == 231 && result->verified == verified && !result->verification_error);
    CHECK(result->raw.len == 24 && !memcmp(result->raw.data, project, 24));
    CHECK(result->raw_v2.len == 56 && !memcmp(result->raw_v2.data, project, 24) &&
          !memcmp(result->raw_v2.data + 24, write, 32));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "project_id", &part) &&
          !strcmp(json_object_get_string(part), project));
    CHECK(json_object_object_get_ex(result->secret_parts, "write_key", &part) &&
          !strcmp(json_object_get_string(part), write));
    CHECK(!json_object_object_get_ex(result->secret_parts, "token", &part));
    CHECK(!result->extra_data && !result->redacted);
}

static void extraction(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "satismeter %s %s\nsatismeter %s", project, write_key, token);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_pair(&results.items[0], token, false);
    check_pair(&results.items[1], write_key, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "satismeter %s %s %s", project, write_key, write_key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "satismeter %s %s", project, write_key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, write_key, 32);
    CHECK(!results.len);
    br_results_clear(&results);
}

static int satis_status, satis_step;
static const char *satis_bearers[2], *satis_writes[2];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    (void)http;
    CHECK(satis_step < 2);
    const char *bearer = satis_bearers[satis_step];
    const char *write = satis_writes[satis_step++];
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://app.satismeter.com/api/users?type=track"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 231);
    CHECK(request->nheaders == 3 && !request->dedup_key.len);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, bearer));
    char body[160];
    int n = snprintf(body, sizeof(body),
                     "{\"event\":\"This is the event name\",\"project\":\"%s\",\"type\":\"track\",\"userId\":\"007\",\"writeKey\":\"%s\"}",
                     project, write);
    CHECK(n > 0 && request->body.len == (size_t)n && !memcmp(request->body.data, body, (size_t)n));
    http->response.status = satis_status;
}

static void verification(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "satismeter %s %s\nsatismeter %s", project, write_key, token);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 2 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context") && !results.items[0].verified);
    br_results_clear(&results);
    satis_status = 204;
    satis_step = 0;
    satis_bearers[0] = write_key;
    satis_writes[0] = token;
    satis_bearers[1] = token;
    satis_writes[1] = write_key;
    test_http http = {.inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && http.calls == 2 && satis_step == 2);
    check_pair(&results.items[0], token, true);
    check_pair(&results.items[1], write_key, true);
    br_results_clear(&results);
    satis_status = 401;
    satis_step = 0;
    satis_bearers[0] = token;
    satis_writes[0] = write_key;
    satis_bearers[1] = write_key;
    satis_writes[1] = token;
    snprintf(input, sizeof(input), "satismeter %s %s\nsatismeter %s", project, token, write_key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && satis_step == 2);
    check_pair(&results.items[0], write_key, false);
    br_results_clear(&results);
    satis_status = 500;
    satis_step = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !results.items[0].verified && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "unexpected status code: 500"));
    br_results_clear(&results);
    http.send_error = "dial";
    http.send_rc = -1;
    satis_step = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 2 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "satismeter %s %s\nsatismeter %s", project, write_key, token);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 1, "prior", "key") && !br_results_push(&results, &prior));
    fail_finding_after = 2;
    char *error = NULL;
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create SatismeterWritekey result") && results.len == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    return test_finish("Satismeter unique product, sorted payload, 204/401/unexpected, nil error");
}
