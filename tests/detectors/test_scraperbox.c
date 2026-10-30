/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_scraperbox_init(const br_detector **out, char **error);

static const char key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
static const char other[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 32);
    char copy[33]; memcpy(copy, value, 32); copy[32] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 559, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

typedef struct { const char *key, *send_error; int status; } reply;
typedef struct { reply rows[2]; size_t count; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; reply *step = &steps->rows[at];
    char url[96];
    snprintf(url, sizeof(url), "https://api.scraperbox.com/scrape?token=%s&url=https://google.com", step->key);
    CHECK(ctx == steps->expected_ctx && http->releases == at && strlen(url) == 95);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 10000 && request->detector_type == 559);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!request->body.len && !request->dedup_key.len);
    http->response = (br_http_response){.status = step->status, .body_error = "ignored close"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : 0;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_scraperbox_init(NULL, &error) == -1); free(error);
    CHECK(!br_scraperbox_init(&detector, &error) && !error);
    CHECK(detector->type == 559 && !strcmp(detector->name, "ScraperBox"));
    CHECK(!strcmp(detector->description, "ScraperBox is a web scraping service that allows users to extract data from websites. The provided token can be used to authenticate and perform scraping operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "scraperbox") && detector->max_credential_span == -1);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[160];
    snprintf(input, sizeof(input), "scraperbox %s\nSCRAPERBOX %s\nscraperbox %s", key, other, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 3);
    check_result(&results.items[0], key, false);
    check_result(&results.items[1], other, false);
    check_result(&results.items[2], key, false);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "scraperbox %s", "abcdefghijklmnopqrstuvwxyz012345");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "scraperbox%*s%s", 41, "", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", key, other);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); /* Nil context is a constructor continue, after the URL is formatted. */
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "scraperbox %s", key);
    const int codes[] = {199, 200, 299, 300, 401, 500};
    for (size_t i = 0; i < 6; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = codes[i]};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        check_result(&results.items[0], key, codes[i] >= 200 && codes[i] < 300);
        br_results_clear(&results);
    }
    script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = 200, .send_error = "dial failed"};
    test_http http = {.inspect = inspect, .user = &steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == 1 && http.releases == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("ScraperBox 10s token URL + nil drop + 2xx only");
}
