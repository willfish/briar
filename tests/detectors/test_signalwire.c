/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_signalwire_init(const br_detector **out, char **error);

static char key[51], other[51];
static const char id[] = "abcdef12-3456-7890-abcd-ef1234567890";
static const char id2[] = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
static const char host[] = "abc.signalwire.com";
static const char host2[] = "space-1.signalwire.com";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[64];
    CHECK(len >= 0 && (size_t)len < sizeof(copy));
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    test_secret(key, 50, 1);
    test_secret(other, 50, 4);
    key[0] = 'A';
    other[3] = 'Z';
    CHECK(strlen(id) == 36);
    CHECK(br_signalwire_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_signalwire_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 611 && !strcmp(detector->name, "Signalwire") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "SignalWire is a communications platform as a service (CPaaS) provider. SignalWire credentials can be used to access and manage communication services such as voice, messaging, and video."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "signalwire"));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 611, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "signalwire %s %s %s", id, key, host);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s", id, key, host);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "signalwire %s %s ABC.signalwire.com", id, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "signalwire %s %s ab.signalwire.com", id, key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "signalwire ABCDEF12-3456-7890-ABCD-EF1234567890 %s %s", key, host);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

static int wire_status, wire_step;
static const char *wire_hosts[4], *wire_ids[4];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    CHECK(wire_step < 4);
    const char *wire_host = wire_hosts[wire_step];
    const char *wire_id = wire_ids[wire_step++];
    char url[128];
    int n = snprintf(url, sizeof(url), "https://%s/api/laml/2010-04-01/Accounts", wire_host);
    CHECK(n > 0 && !strcmp(request->url, url) && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 611 && request->nheaders == 3 && !request->body.len);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    char *basic = NULL, *error = NULL;
    CHECK(!br_http_basic_auth((br_slice){(const unsigned char *)wire_id, strlen(wire_id)},
                              (br_slice){(const unsigned char *)http->user, strlen(http->user)},
                              &basic, &error) && basic && !error);
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, basic));
    free(basic);
    http->response.status = wire_status;
}

static void verification(const br_detector *detector)
{
    char input[220];
    snprintf(input, sizeof(input), "signalwire %s %s %s", id, key, host);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    wire_status = 200;
    wire_step = 0;
    wire_hosts[0] = host;
    wire_ids[0] = id;
    test_http http = {.inspect = inspect, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);
    wire_status = 401;
    wire_step = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    http.send_error = "refused";
    http.send_rc = -1;
    wire_step = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "signalwire %s %s %s\nsignalwire %s %s", id, key, host, id2, host2);
    http.send_error = NULL;
    http.send_rc = 0;
    wire_status = 204;
    wire_step = 0;
    wire_ids[0] = wire_ids[1] = id;
    wire_ids[2] = wire_ids[3] = id2;
    wire_hosts[0] = wire_hosts[2] = host;
    wire_hosts[1] = wire_hosts[3] = host2;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && wire_step == 4);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[240];
    snprintf(input, sizeof(input), "signalwire %s %s %s\nsignalwire %s %s", id, key, host, id, other);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 4, "prior", "key") && !br_results_push(&results, &prior));
    fail_finding_after = 2;
    char *error = NULL;
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create Signalwire result") && results.len == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    return test_finish("Signalwire triple product, public Basic client, 2xx, nil skip");
}
