/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

extern int br_smartystreets_init(const br_detector **, char **);

static char key[21];
static const char id[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http;
    (void)ctx;
    char url[192];
    snprintf(url, sizeof(url),
             "https://us-zipcode.api.smartystreets.com/lookup?auth-id=%s&auth-token=%s&state=CA&zipcode=94035",
             id, key);
    CHECK(!strcmp(request->url, url) && request->nheaders == 1 && request->timeout_ms == 5000);
}

int main(void)
{
    CHECK(strlen(id) == 36);
    memset(key, 'K', 20);
    key[20] = 0;
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_smartystreets_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 562 && !strcmp(detector->name, "SmartyStreets") && detector->max_credential_span == 1024);
    char input[128];
    snprintf(input, sizeof(input), "smartystreets %s %s", key, id);
    test_http http = {.inspect = inspect, .response.status = 200};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    test_key_result(&results.items[0], 562, key, "key");
    br_results_clear(&results);
    size_t calls = http.calls;
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len && http.calls == calls);
    printf("smartystreets: %zu assertions, 0 failures; synthetic injected HTTP only\n", test_assertions);
    return 0;
}
