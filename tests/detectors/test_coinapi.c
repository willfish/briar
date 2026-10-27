/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "GHIJKLMNOPQRSTUVWXYZ0123456789ABCDEF";
static const char other[] = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
static size_t fail_finding_after;

/* Existing focused finding-allocation check, not a header/auth allocation seam. */
struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 36 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[37]; memcpy(copy, value, (size_t)len); copy[len] = '\0'; return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other) == 36);
    CHECK(br_coinapi_init(NULL, &error) == -1 && error && !strcmp(error, "invalid CoinApi detector output")); free(error); error = NULL;
    CHECK(!br_coinapi_init(&detector, &error) && detector && !error);
    CHECK(!br_coinapi_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 554 && detector->version == 0 && !strcmp(detector->name, "CoinApi") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "CoinApi provides a RESTful API to access cryptocurrency market data. CoinApi keys can be used to fetch real-time and historical cryptocurrency data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "coinapi"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 554, expected, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[38];
    snprintf(input, sizeof(input), "coinapi '%s'", key); expect_one(detector, input, key); /* G-Z, no UUID grouping. */
    snprintf(input, sizeof(input), "COINAPI=%s", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "preCoInApIsuffix\r\n%s", other); expect_one(detector, input, other); /* No entropy filter. */
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "coin api %s", key); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = 'g'; snprintf(input, sizeof(input), "coinapi %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = '_'; snprintf(input, sizeof(input), "coinapi %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[35] = 0; snprintf(input, sizeof(input), "coinapi %s", changed); expect_one(detector, input, NULL);
    snprintf(changed, sizeof(changed), "%sA", key); snprintf(input, sizeof(input), "coinapi %s", changed); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinapi _%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "coinapi %s_", key); expect_one(detector, input, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "coinapi%*s%s", gap, "", key); expect_one(detector, input, gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[2] = changed[17] = '-'; snprintf(input, sizeof(input), "coinapi %s", changed); expect_one(detector, input, changed); /* Arbitrary literal hyphens. */
    snprintf(input, sizeof(input), "coinapi %s-", key); expect_one(detector, input, key); /* Non-consuming boundary, even before another allowed byte. */
    memcpy(changed, key, sizeof(key)); changed[0] = '-'; snprintf(input, sizeof(input), "coinapi x%s", changed); expect_one(detector, input, changed);
    memcpy(changed, key, sizeof(key)); changed[35] = '-'; snprintf(input, sizeof(input), "coinapi %sx", changed); expect_one(detector, input, changed);
    snprintf(input, sizeof(input), "coinapi %s", changed); expect_one(detector, input, NULL);
    memset(changed, '-', 36); changed[36] = 0; snprintf(input, sizeof(input), "coinapi x%sx", changed); expect_one(detector, input, changed);
    snprintf(input, sizeof(input), "coinapi %s", changed); expect_one(detector, input, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc; } reply;
typedef struct { reply rows[3]; size_t count; const char *borrowed_key; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx); reply *step = &steps->rows[at];
    CHECK(request->detector_type == 554 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://rest.coinapi.io/v1/exchanges"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-Coinapi-Key") && strlen(request->headers[0].value) == 36 && !strcmp(request->headers[0].value, step->key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog")); /* No Bearer/Type/Accept/logical CL. */
    steps->borrowed_key = request->headers[0].value;
    static const unsigned char body[] = "\xff\0ignored non-JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/close failure"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_key && strlen(steps->borrowed_key) == 36 && !strcmp(steps->borrowed_key, steps->rows[http->calls - 1].key));
    steps->borrowed_key = NULL; test_http_release(user, response);
}

static br_transport transport_for(test_http *http) { return (br_transport){http, test_http_send, release_response}; }

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); CHECK(http.calls == steps->count && http.releases == steps->count); return results;
}

static void occurrences_and_nil(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "coinapi %s\ncoinapi %s\ncoinapi %s", key, other, key); const char *keys[] = {key, other, key}; script steps = {.count = 3};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = i == 1 ? 503 : 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {0}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i != 1);
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(!results.len); br_results_clear(&results);
    /* Real shared-send setup failure, not Do: whole mixed domain is suppressed. */
    br_scan_ctx missing_transport = {0}; results = test_scan(detector, &missing_transport, true, input, strlen(input)); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
}

static void statuses_and_do_errors(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "coinapi %s", key); const int codes[] = {199, 200, 201, 204, 299, 300, 401, 403, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = codes[i]}; br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, codes[i] >= 200 && codes[i] < 300); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create CoinApi result", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = 200, .send_error = causes[i], .send_rc = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    char hyphens[37]; memset(hyphens, '-', 36); hyphens[36] = 0; snprintf(input, sizeof(input), "coinapi x%sx", hyphens);
    script steps = {.count = 1}; steps.rows[0] = (reply){.key = hyphens, .status = 200}; br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], hyphens, true); br_results_clear(&results);
}

static void resource_boundary(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "coinapi %s\ncoinapi %s", key, other);
    script steps = {.count = 2}; steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 200};
    for (int nil_ctx = 0; nil_ctx < 2; ++nil_ctx) {
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = transport_for(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error, *error = NULL;
        fail_finding_after = 2;
        int rc = detector->scan(detector, nil_ctx ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && !fail_finding_after && error && !strcmp(error, "cannot create CoinApi result"));
        CHECK(http.calls == (nil_ctx ? 0u : 1u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned")); br_json *part = NULL; CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part) && !strcmp(json_object_get_string(part), "prior")); free(error); br_results_clear(&results);
    }
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], other, true); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); occurrences_and_nil(detector); statuses_and_do_errors(detector); resource_boundary(detector);
    return test_finish("CoinApi uppercase/non-UUID occurrences + borrowed canonical header + full send suppression + own rollback");
}
