/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_web3storage_init(const br_detector **out, char **error);

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_web3storage_init(NULL, &error) != 0 && error);
    free(error);
    CHECK(br_web3storage_init(&detector, &error) == 0 && !error && detector->type == 930);
    CHECK(!strcmp(detector->name, "Web3Storage") && !strcmp(detector->keywords[0], "web3"));
    CHECK(!strcmp(detector->description, "Web3.storage is a service offering decentralized storage solutions. Web3.storage API keys can be used to access and manage stored data."));
    CHECK(detector->max_credential_span == -1 && !detector->false_positive);
    return detector;
}

static void token(char *out, size_t middle, size_t signature)
{
    const char *prefix = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ";
    memcpy(out, prefix, strlen(prefix));
    for (size_t i = 0; i < middle; ++i) out[strlen(prefix) + i] = (char)('A' + (i % 26));
    out[strlen(prefix) + middle] = '.';
    for (size_t i = 0; i < signature; ++i) out[strlen(prefix) + middle + 1 + i] = (char)('a' + (i % 26));
    out[strlen(prefix) + middle + 1 + signature] = 0;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)ctx;
    char expect[512];
    snprintf(expect, sizeof(expect), "Bearer %s", (const char *)http->user);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.web3.storage/user/uploads"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 930);
    CHECK(!request->body.len && request->nheaders == 2);
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
    char key[480], input[560];
    token(key, 100, 25);
    snprintf(input, sizeof(input), "web3 token = '%s'", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 930, key, "key");
    br_results_clear(&results);
    token(key, 300, 100);
    snprintf(input, sizeof(input), "WEB3 %s", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    const struct { size_t middle, signature; } rejected[] = {{99, 25}, {301, 25}, {100, 24}, {100, 101}};
    for (size_t i = 0; i < 4; ++i) {
        token(key, rejected[i].middle, rejected[i].signature);
        snprintf(input, sizeof(input), "web3 %s", key);
        results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 0);
        br_results_clear(&results);
    }
    token(key, 100, 25);
    snprintf(input, sizeof(input), "%s web3", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char key[480], input[560];
    token(key, 100, 25);
    snprintf(input, sizeof(input), "web3 %s", key);
    const struct { int status; bool verified; const char *error; } cases[] = {
        {200, true, NULL}, {401, false, NULL}, {403, false, "unexpected HTTP response status 403"},
    };
    for (size_t i = 0; i < 3; ++i) {
        test_http http = {.response = {.status = cases[i].status}, .inspect = inspect, .user = key};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char sensitive[512];
    snprintf(sensitive, sizeof(sensitive), "dial %s failed", key);
    test_http http = {.send_rc = 1, .send_error = sensitive, .inspect = inspect, .user = key};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "dial [REDACTED] failed"));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("Web3Storage");
}
