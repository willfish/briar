/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_zenserp_init(const br_detector **out, char **error);

static const char key[] = "0123456789abcdef-ghijklmnopqrstuvwxy";
static const char other[] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 36 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[37]; memcpy(copy, value, (size_t)len); copy[len] = '\0';
    return json_object_new_string(copy);
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 553, expected, "key");
    CHECK(result->verified == verified);
    if (cause) {
        CHECK(result->verification_error && !strcmp(result->verification_error, cause));
        CHECK(!strstr(result->verification_error, expected));
    } else CHECK(!result->verification_error);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    CHECK(strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_zenserp_init(NULL, &error) == -1); free(error);
    CHECK(!br_zenserp_init(&detector, &error) && !error);
    CHECK(detector->type == 553 && !strcmp(detector->name, "Zenserp") && detector->version == 0);
    CHECK(!strcmp(detector->description, "Zenserp is a service that provides SERP (Search Engine Results Page) API. Zenserp API keys can be used to access search engine data programmatically."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "zenserp") && detector->max_credential_span == -1);
    return detector;
}

typedef struct { const char *key, *send_error, *body, *body_error; int status; } reply;
typedef struct { reply rows[2]; size_t count; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; reply *step = &steps->rows[at];
    char url[96];
    snprintf(url, sizeof(url), "https://app.zenserp.com/api/v2/search?q=\"test\"&apikey=%s", step->key);
    CHECK(ctx == steps->expected_ctx && http->releases == at && strlen(url) == 90);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 553);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!request->body.len && !request->dedup_key.len);
    http->response = (br_http_response){.status = step->status, .body_error = step->body_error};
    if (step->body) http->response.body = (br_slice){(const unsigned char *)step->body, strlen(step->body)};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : 0;
}

static br_results run(const br_detector *detector, const char *input, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count);
    return results;
}

static void extraction(const br_detector *detector)
{
    char input[160], hyphens[37];
    snprintf(input, sizeof(input), "zenserp %s\nzenserp %s", key, key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key, false, NULL);
    check_result(&results.items[1], key, false, NULL);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "ZENSERP%*s%s", 40, "", other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], other, false, NULL); br_results_clear(&results);
    snprintf(input, sizeof(input), "zenserp%*s%s", 41, "", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    memset(hyphens, '-', 36); hyphens[36] = 0;
    snprintf(input, sizeof(input), "zenserp %s", hyphens);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); /* Leading hyphen is not a word boundary after a space. */
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zenserp x%s", hyphens);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); /* Trailing hyphen is not a word boundary before end. */
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "zenserp %s", key);
    br_results results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false, "net/http: nil Context");
    br_results_clear(&results);
    script ok = {.count = 1, .rows = {{.key = key, .status = 200, .body = "pre query post"}}};
    results = run(detector, input, &ok); check_result(&results.items[0], key, true, NULL); br_results_clear(&results);
    script missing = {.count = 1, .rows = {{.key = key, .status = 200, .body = "no marker"}}};
    results = run(detector, input, &missing); check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
    script unread = {.count = 1, .rows = {{.key = key, .status = 200, .body = "query", .body_error = "read failed"}}};
    results = run(detector, input, &unread); check_result(&results.items[0], key, false, "read failed"); br_results_clear(&results);
    const int quiet[] = {401, 403};
    for (size_t i = 0; i < 2; ++i) {
        script steps = {.count = 1, .rows = {{.key = key, .status = quiet[i], .body = "query"}}};
        results = run(detector, input, &steps); check_result(&results.items[0], key, false, NULL); br_results_clear(&results);
    }
    script bad = {.count = 1, .rows = {{.key = key, .status = 429}}};
    results = run(detector, input, &bad);
    check_result(&results.items[0], key, false, "unexpected status code: 429");
    br_results_clear(&results);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("Zenserp quoted query URL + query marker + duplicate occurrences");
}
