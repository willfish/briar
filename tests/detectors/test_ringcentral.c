/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_ringcentral_init(const br_detector **out, char **error);

static const char key[] = "OTXwnia5kOs-SlF3kZEFJK";
static const char other[] = "ABCDEFGHIJKLMNOPQRST_1";
static const char uri[] = "https://wwwSG7$com";
static const char uri2[] = "https://www.example.com";
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
    CHECK(strlen(key) == 22 && strlen(other) == 22);
    CHECK(br_ringcentral_init(NULL, &error) == -1 && error);
    free(error);
    error = NULL;
    CHECK(!br_ringcentral_init(&detector, &error) && detector && !error);
    CHECK(detector->type == 422 && !strcmp(detector->name, "RingCentral") && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "RingCentral is a cloud-based communication system that offers messaging, video conferencing, and phone services. RingCentral API keys can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ringcentral"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 422, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction(const br_detector *detector)
{
    char input[256];
    snprintf(input, sizeof(input), "ringcentral token - '%s'\nringcentral token - '%s'\n", key, uri);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "ringcentral token - '%s'\nringcentral token - '%s'\n",
             "OTXwnia5kOs?SlF3kZEFJK", "https://?wwSG7$com");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "ringcentral %s %s", key, uri2);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", key, uri);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
}

static int ring_status, ring_step;
static const char *ring_uris[4], *ring_keys[4];

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    (void)http;
    CHECK(ring_step < 4);
    const char *ring_uri = ring_uris[ring_step];
    const char *client = ring_keys[ring_step++];
    char url[192];
    int n = snprintf(url, sizeof(url),
                     "https://platform.devtest.ringcentral.com/restapi/oauth/authorize?response_type=code&redirect_uri=%s&client_id=%s",
                     ring_uri, client);
    CHECK(n > 0 && (size_t)n < sizeof(url));
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 422);
    CHECK(request->nheaders == 2 && !request->body.len && !request->dedup_key.len);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    http->response.status = ring_status;
}

static void verification(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "ringcentral %s %s", key, uri);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    ring_status = 200;
    ring_step = 0;
    ring_uris[0] = uri;
    ring_keys[0] = key;
    test_http http = {.inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, true);
    br_results_clear(&results);
    ring_status = 300;
    ring_step = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    http.send_error = "dial";
    http.send_rc = -1;
    ring_step = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "ringcentral %s\nringcentral %s\nringcentral %s\nringcentral %s",
             key, uri, other, uri2);
    http.send_error = NULL;
    http.send_rc = 0;
    ring_status = 204;
    ring_step = 0;
    ring_keys[0] = ring_keys[1] = key;
    ring_keys[2] = ring_keys[3] = other;
    ring_uris[0] = ring_uris[2] = uri;
    ring_uris[1] = ring_uris[3] = uri2;
    size_t before = http.calls;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 4 && http.calls == before + 4 && ring_step == 4);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "ringcentral %s %s\nringcentral %s", key, uri, other);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 3, "prior", "key") && !br_results_push(&results, &prior));
    fail_finding_after = 2;
    char *error = NULL;
    int rc = detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)},
                            &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "cannot create RingCentral result") && results.len == 1);
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    return test_finish("RingCentral key/uri product, raw query URL, 2xx, nil skip");
}
