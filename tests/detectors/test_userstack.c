/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_userstack_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdef0123456789abcdef";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_userstack_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_userstack_init(&detector, &error) == 0 && !error && detector->type == 541);
    CHECK(!strcmp(detector->name, "UserStack") && !strcmp(detector->keywords[0], "userstack"));
    CHECK(!strcmp(detector->description, "UserStack is a service that provides detailed information about the technology stack used by a website. UserStack API keys can be used to access this information."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[96];
    snprintf(url, sizeof(url), "https://api.userstack.com/detect?access_key=%s&ua=Mozilla/5.0", (const char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 541);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
}

static void verification(const br_detector *detector)
{
    char input[80];
    snprintf(input, sizeof(input), "userstack %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 541, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s userstack", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "USERSTACK %s", "0123456789ABCDEF0123456789abcdef");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "userstack %s", key);
    const char *bodies[] = {
        "{\"is_mobile_device\":false}",
        "{\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"}",
        "{\"info\":\"other\"}",
    };
    const bool verified[] = {true, true, false};
    for (size_t i = 0; i < 3; ++i) {
        test_http http = {.response = {.status = i == 2 ? 403 : 500, .body = {(const unsigned char *)bodies[i], strlen(bodies[i])}}, .inspect = inspect, .user = (void *)key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == verified[i] && !results.items[0].verification_error);
        br_results_clear(&results);
    }
    const unsigned char marked[] = "is_mobile_device";
    test_http http = {.response = {.status = 200, .body = {marked, sizeof(marked) - 1}, .body_error = "read reset"}, .inspect = inspect, .user = (void *)key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http = (test_http){.send_rc = 1, .send_error = "context canceled", .inspect = inspect, .user = (void *)key};
    transport = test_transport(&http);
    ctx = (br_scan_ctx){.transport = &transport};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    verification(detector);
    return test_finish("UserStack");
}
