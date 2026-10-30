/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_serpstack_init(const br_detector **out, char **error);

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char url[128];
    snprintf(url, sizeof(url), "https://api.serpstack.com/search?access_key=%s&query=Mcdonalds", (char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 561);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !request->body.len);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_serpstack_init(&detector, &error) == 0 && error == NULL);
    CHECK(detector->type == 561 && !strcmp(detector->name, "SerpStack"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "serpstack"));
    char key[33], input[96];
    test_secret(key, 32, 5);
    snprintf(input, sizeof(input), "serpstack %s", key);
    br_results found = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(found.len == 1);
    test_key_result(&found.items[0], 561, key, "key");
    br_results_clear(&found);
    snprintf(input, sizeof(input), "%s", key);
    br_results bare = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(bare.len == 0);
    br_results_clear(&bare);
    snprintf(input, sizeof(input), "serpstack %s\nserpstack %s", key, key);
    br_results dups = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(dups.len == 2);
    br_results_clear(&dups);

    snprintf(input, sizeof(input), "serpstack %s", key);
    const char *bodies[] = {"{\"search_url\":\"https://example\"}", "no marker",
                            "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\""};
    const bool verified[] = {true, false, true};
    for (size_t i = 0; i < 3; ++i) {
        test_http http = {.response = {.status = 200, .body = {(const unsigned char *)bodies[i], strlen(bodies[i])}},
                          .inspect = inspect_request, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == verified[i] && http.calls == 1);
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http restricted = {.response = {.status = 401, .body = {(const unsigned char *)bodies[0], strlen(bodies[0])}},
                            .inspect = inspect_request, .user = key};
    br_transport transport = test_transport(&restricted);
    br_scan_ctx ctx = {.transport = &transport};
    br_results bad = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(bad.len == 1 && !bad.items[0].verified);
    br_results_clear(&bad);
    test_http unread = {.response = {.status = 200, .body_error = "read failed",
                                     .body = {(const unsigned char *)bodies[0], strlen(bodies[0])}},
                        .inspect = inspect_request, .user = key};
    br_transport unread_transport = test_transport(&unread);
    br_scan_ctx unread_ctx = {.transport = &unread_transport};
    br_results kept = test_scan(detector, &unread_ctx, true, input, strlen(input));
    CHECK(kept.len == 1 && !kept.items[0].verified);
    br_results_clear(&kept);
    br_results skipped = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(skipped.len == 0);
    br_results_clear(&skipped);
    return test_finish("SerpStack");
}
