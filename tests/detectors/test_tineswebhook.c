/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_tineswebhook_init(const br_detector **out, char **error);

static const char key1[] =
    "https://Ab_1.tines.com/webhook/0123456789abcdef0123456789abcdef/abcdef0123456789abcdef0123456789";
static const char key2[] =
    "https://other-host.tines.com/webhook/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    CHECK(ctx && !strcmp(request->method, "GET") && request->profile == BR_HTTP_DETECTOR_PUBLIC);
    CHECK(request->timeout_ms == 10000 && request->body.len == 0 && request->body.data);
    CHECK(!strcmp(request->url, key1) && request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_tineswebhook_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 913 && !strcmp(detector->name, "TinesWebhook"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "tines.com"));
    CHECK(detector->max_credential_span == -1);
    CHECK(!strcmp(detector->description,
                  "Tines is an automation platform. Tines Webhook URLs can be used to trigger and interact with Tines workflows."));
    return detector;
}

int main(void)
{
    const br_detector *detector = descriptor();
    char input[320];
    snprintf(input, sizeof(input), "noise %s\n%s", key1, key2);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[0], 913, key1, "key");
    test_key_result(&results.items[1], 913, key2, "key");
    br_results_clear(&results);
    const char bad[] = "https://Ab_1.tines.com/webhook/ABCDEF0123456789abcdef0123456789/abcdef0123456789abcdef0123456789";
    results = test_scan(detector, NULL, false, bad, sizeof(bad) - 1);
    CHECK(results.len == 0);
    br_results_clear(&results);
    test_http http = {.response = {.status = 204}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, key1, strlen(key1));
    CHECK(results.len == 1 && results.items[0].verified && http.releases == 1);
    br_results_clear(&results);
    http.response.status = 404;
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, key1, strlen(key1));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, key1, strlen(key1));
    CHECK(results.len == 0);
    br_results_clear(&results);
    return test_finish("TinesWebhook");
}
