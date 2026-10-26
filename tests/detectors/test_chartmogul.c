/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <strings.h>

static const char key[] = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
static const char other[] = "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4";
static bool track_basic;
static size_t basic_allocations, fail_basic_after;

/* Same focused allocation seam as Censys. Basic(KEY32, empty password) owns
 * exactly 7+4*ceil(33/3)=51 bytes. Fail/count that allocation, not Client.Do.
 * Zero-filled forwarding memory remains a valid malloc result. */
void *malloc(size_t size)
{
    if (track_basic && size == 51) {
        ++basic_allocations;
        if (fail_basic_after && --fail_basic_after == 0) return NULL;
    }
    return calloc(1, size);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_chartmogul_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Chartmogul detector output")); free(error); error = NULL;
    CHECK(!br_chartmogul_init(&detector, &error) && detector && !error);
    CHECK(!br_chartmogul_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 815 && detector->version == 0 && !strcmp(detector->name, "Chartmogul") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "ChartMogul is a subscription analytics platform that helps businesses measure, understand, and grow their subscription revenue. ChartMogul API keys can be used to access and manage subscription data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "chartmogul"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 815, expected, "key"); CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    basic_allocations = 0; track_basic = true; br_results results = test_scan(detector, NULL, false, input, strlen(input)); track_basic = false;
    CHECK(!basic_allocations && results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[34];
    snprintf(input, sizeof(input), "chartmogul '%s'", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "CHARTMOGUL=-%s-", key); expect_one(detector, input, key);
    snprintf(input, sizeof(input), "prefixChartMogulsuffix\r\n%s", other); expect_one(detector, input, other);
    snprintf(input, sizeof(input), "%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "chart mogul %s", key); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = 'A'; snprintf(input, sizeof(input), "chartmogul %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = '_'; snprintf(input, sizeof(input), "chartmogul %s", changed); expect_one(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[31] = '\0'; snprintf(input, sizeof(input), "chartmogul %s", changed); expect_one(detector, input, NULL);
    snprintf(changed, sizeof(changed), "%sa", key); snprintf(input, sizeof(input), "chartmogul %s", changed); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "chartmogul _%s", key); expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "chartmogul %s_", key); expect_one(detector, input, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "chartmogul%*s%s", gap, "", key); expect_one(detector, input, gap == 40 ? key : NULL);
    }
    memset(changed, 'z', 32); changed[32] = '\0'; snprintf(input, sizeof(input), "chartmogul %s", changed); expect_one(detector, input, changed); /* Lower alnum, not hex; no entropy filter. */
}

typedef struct { const char *key, *send_error; int status, send_rc; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *expected_ctx; } script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i) if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 815 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.chartmogul.com/v1/ping"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!header(request, "Content-Type") && !header(request, "Accept") && !header(request, "Content-Length"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    const char *auth = header(request, "Authorization"); CHECK(auth && strlen(auth) == 50 && !memcmp(auth, "Basic ", 6));
    unsigned char plain[36]; CHECK(EVP_DecodeBlock(plain, (const unsigned char *)auth + 6, 44) == 33);
    CHECK(!memcmp(plain, step->key, 32) && plain[32] == ':'); /* Empty password, no extra bytes or padding. */
    static const unsigned char body[] = "\xff\0ignored non-JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/close error"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps->expected_ctx = &ctx;
    basic_allocations = 0; track_basic = true; br_results results = test_scan(detector, &ctx, verify, input, strlen(input)); track_basic = false;
    CHECK(basic_allocations == (verify ? steps->count : 0) && http.calls == steps->count && http.releases == steps->count); return results;
}

static void verification(const br_detector *detector)
{
    char input[80]; snprintf(input, sizeof(input), "chartmogul %s", key);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = statuses[i]};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "synthetic Do failure", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = 200, .send_error = causes[i], .send_rc = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void duplicates_and_nil_context(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "chartmogul %s\nchartmogul %s\nchartmogul %s", key, other, key);
    script steps = {.count = 3}; const char *keys[] = {key, other, key};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = 200};
    for (int verify = 0; verify < 2; ++verify) {
        script none = {0}; br_results results = run(detector, input, verify, verify ? &steps : &none); CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify);
        br_results_clear(&results);
    }
    basic_allocations = 0; track_basic = true; br_results results = test_scan(detector, NULL, true, input, strlen(input)); track_basic = false;
    CHECK(!results.len && basic_allocations == 3); br_results_clear(&results); /* Basic preparation precedes each constructor skip. */
}

static void basic_resource_boundary(const br_detector *detector)
{
    char *authorization = NULL, *error = NULL; basic_allocations = 0; fail_basic_after = 1; track_basic = true;
    int rc = br_http_basic_auth((br_slice){(const unsigned char *)key, 32}, (br_slice){0}, &authorization, &error); track_basic = false;
    CHECK(rc == 1 && !authorization && error && !strcmp(error, "out of memory constructing Basic authentication") && basic_allocations == 1 && !fail_basic_after); free(error); error = NULL;
    char input[192]; snprintf(input, sizeof(input), "chartmogul %s\nchartmogul %s\nchartmogul %s", key, other, key);
    script steps = {.count = 3}; const char *keys[] = {key, other, key};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = 200};
    for (int nil = 0; nil < 2; ++nil) {
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; CHECK(!br_finding_key(&prior, 777, "prior", "key")); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(!br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data; char *saved_error = results.items[0].verification_error;
        basic_allocations = 0; fail_basic_after = 2; track_basic = true;
        rc = detector->scan(detector, nil ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error); track_basic = false;
        CHECK(rc == -1 && error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_basic_after && basic_allocations == 2);
        CHECK(http.calls == (nil ? 0u : 1u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].raw.len == 5 && !memcmp(saved, "prior", 5));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified && results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
        br_json *part = NULL; CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part) && !strcmp(json_object_get_string(part), "prior")); free(error); error = NULL; br_results_clear(&results);
    }
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); verification(detector); duplicates_and_nil_context(detector); basic_resource_boundary(detector);
    return test_finish("Chartmogul occurrences + Basic key: before nil-context skip + suppressed Do errors");
}
