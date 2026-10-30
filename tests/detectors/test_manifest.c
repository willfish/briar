/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_manifest_init(const br_detector **out, char **error);

static const char key1[] = "0Nubbkxtphh1c3YHbmB8MipsgpbmczRT";
static const char key2[] = "0Nubbkxtphh1c3YHbmB8MipsgpbmczR_";
static const char *seen_url;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    char url[96];
    (void)http;
    CHECK(ctx && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.len && !request->dedup_key.len);
    snprintf(url, sizeof(url), "https://api.manifest.ly/api/v1/checklists/?api_key=%s", key1);
    CHECK(!strcmp(request->url, seen_url ? seen_url : url));
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_manifest_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_manifest_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 644 && detector->version == 0 && !strcmp(detector->name, "Manifest"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "manifest"));
    CHECK(detector->max_credential_span == -1 && detector->scan);
    CHECK(!strcmp(detector->description,
                  "Manifest API keys are used to interact with the Manifest service, which provides checklist management and other features."));
    return detector;
}

static void extraction(const br_detector *detector)
{
    char gap[96], wide[96], raw[80];
    snprintf(gap, sizeof(gap), "MANIFEST%*s%s", 40, "", key1);
    snprintf(wide, sizeof(wide), "manifest%*s%s", 41, "", key1);
    memcpy(raw, "\0manifest ", 10);
    memcpy(raw + 10, key1, 32);
    br_results results = test_scan(detector, NULL, false, gap, strlen(gap));
    test_key_result(&results.items[0], 644, key1, "key");
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, wide, strlen(wide));
    CHECK(results.len == 0);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, raw, 42);
    CHECK(results.len == 1 && results.items[0].raw.len == 32);
    br_results_clear(&results);
    char both[128];
    snprintf(both, sizeof(both), "manifest %s manifest %s manifest %s", key1, key1, key2);
    results = test_scan(detector, NULL, false, both, strlen(both));
    CHECK(results.len == 3);
    CHECK(!memcmp(results.items[0].raw.data, key1, 32));
    CHECK(!memcmp(results.items[1].raw.data, key1, 32));
    CHECK(!memcmp(results.items[2].raw.data, key2, 32));
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, "manifest short", 14);
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "manifest %s", key1);
    const int statuses[] = {200, 299, 199, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http http = {.response = {.status = statuses[i]}, .inspect = inspect};
        br_scan_ctx ctx = {.transport = &(br_transport){0}};
        br_transport transport = test_transport(&http);
        ctx.transport = &transport;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
        CHECK(results.items[0].verified == (statuses[i] >= 200 && statuses[i] < 300));
        CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http failed = {.send_rc = -1, .send_error = "synthetic transport failure", .inspect = inspect};
    br_transport transport = test_transport(&failed);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[64];
    snprintf(input, sizeof(input), "manifest %s", key1);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 1, "prior", "key") == 0);
    br_results results = {.items = &prior, .len = 1, .cap = 1};
    results.cap = 0;
    char *error = NULL;
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Manifest result"));
    CHECK(results.len == 1 && results.items == &prior);
    CHECK(http.calls == 1 && http.releases == 1);
    free(error);
    br_result_clear(&prior);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    rollback(detector);
    CHECK(detector->scan(detector, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    return test_finish("Manifest");
}
