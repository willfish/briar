/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_nutritionix_init(const br_detector **out, char **error);

static const char key[] = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3";
static const char other[] = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
static const char id[] = "a1b2c3d4";
static const char id2[] = "z9y8x7w6";
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[64];
    CHECK(len >= 0 && (size_t)len < sizeof(copy));
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32 && strlen(id) == 8);
    CHECK(br_nutritionix_init(NULL, &error) == -1 && error &&
          !strcmp(error, "invalid Nutritionix detector output"));
    free(error);
    error = NULL;
    CHECK(!br_nutritionix_init(&detector, &error) && detector && !error);
    CHECK(!br_nutritionix_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 364 && detector->version == 0 && !strcmp(detector->name, "Nutritionix"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "Nutritionix provides a food tracking API. The API keys can be used to access and log nutritional data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "nutritionix"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
          detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 364, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[40];
    snprintf(input, sizeof(input), "nutritionix %s %s", key, id);
    expect_one(detector, input, key);
    snprintf(input, sizeof(input), "NUTRITIONIX\r\n%s %s", other, id2);
    expect_one(detector, input, other);
    snprintf(input, sizeof(input), "preNutritionixsuffix %s %s", key, id);
    expect_one(detector, input, key);
    expect_one(detector, key, NULL);
    snprintf(input, sizeof(input), "nutrition ix %s %s", key, id);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "nutritionix %s", key);
    expect_one(detector, input, NULL); /* Id is required. */
    snprintf(input, sizeof(input), "nutritionix %s", id);
    expect_one(detector, input, NULL);
    memcpy(changed, key, 33);
    changed[0] = 'B';
    snprintf(input, sizeof(input), "nutritionix %s %s", changed, id);
    expect_one(detector, input, NULL);
    memcpy(changed, key, 33);
    changed[4] = '-';
    snprintf(input, sizeof(input), "nutritionix %s %s", changed, id);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "nutritionix %s_ %s", key, id);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "nutritionix _%s %s", key, id);
    expect_one(detector, input, NULL);
    snprintf(changed, sizeof(changed), "%sA", key);
    snprintf(input, sizeof(input), "nutritionix %s %s", changed, id);
    expect_one(detector, input, NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        char gap_input[160];
        /* Id stays inside the first prefix window; the key uses its own. */
        int n = snprintf(gap_input, sizeof(gap_input), "nutritionix %s nutritionix%*s%s", id, gap, "", key);
        CHECK(n > 0 && (size_t)n < sizeof(gap_input));
        br_results results = test_scan(detector, NULL, false, gap_input, (size_t)n);
        CHECK(results.len == (gap == 40 ? 1u : 0u));
        if (gap == 40) check_result(&results.items[0], key, false);
        br_results_clear(&results);
    }
    /* An 8-byte id is not a prefix of the 32-byte key: both need word boundaries. */
    snprintf(input, sizeof(input), "nutritionix %s %s", key, key);
    expect_one(detector, input, NULL);
}

typedef struct {
    const char *key, *id, *send_error;
    int status, send_rc;
} reply;
typedef struct {
    reply rows[4];
    size_t count;
    const br_scan_ctx *expected_ctx;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 364 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://trackapi.nutritionix.com/v2/natural/nutrients"));
    static const char body[] =
        "{\"query\":\"for breakfast i ate 2 eggs, bacon, and french toast\",\"timezone\":\"US/Eastern\"}";
    CHECK(request->body.len == sizeof(body) - 1 && request->body.data &&
          !memcmp(request->body.data, body, sizeof(body) - 1));
    CHECK(!request->dedup_key.len && request->nheaders == 4);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-App-Id") && !strcmp(request->headers[1].value, step->id));
    CHECK(!strcmp(request->headers[2].name, "X-App-Key") && !strcmp(request->headers[2].value, step->key));
    CHECK(!strcmp(request->headers[3].name, "User-Agent") && !strcmp(request->headers[3].value, "TruffleHog"));
    http->response = (br_http_response){.status = step->status, .body_error = "ignored"};
    http->send_error = step->send_error;
    http->send_rc = step->send_error ? -1 : step->send_rc;
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == (verify ? steps->count : 0) && http.releases == http.calls);
    return results;
}

static void product_and_status(const br_detector *detector)
{
    char input[192];
    snprintf(input, sizeof(input), "nutritionix %s %s\nnutritionix %s %s", key, id, other, id2);
    script steps = {.count = 4};
    const char *keys[] = {key, key, other, other};
    const char *ids[] = {id, id2, id, id2};
    for (size_t i = 0; i < 4; ++i) steps.rows[i] = (reply){.key = keys[i], .id = ids[i], .status = i == 1 ? 401 : 200};
    script none = {0};
    br_results results = run(detector, input, false, &none);
    CHECK(results.len == 4);
    for (size_t i = 0; i < 4; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    results = run(detector, input, true, &steps);
    CHECK(results.len == 4);
    for (size_t i = 0; i < 4; ++i) check_result(&results.items[i], keys[i], i != 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 4);
    for (size_t i = 0; i < 4; ++i) check_result(&results.items[i], keys[i], false);
    br_results_clear(&results);
    const int codes[] = {199, 200, 299, 300, 503};
    snprintf(input, sizeof(input), "nutritionix %s %s", key, id);
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script one = {.count = 1};
        one.rows[0] = (reply){.key = key, .id = id, .status = codes[i]};
        results = run(detector, input, true, &one);
        CHECK(results.len == 1);
        check_result(&results.items[0], key, codes[i] >= 200 && codes[i] < 300);
        br_results_clear(&results);
    }
    script failed = {.count = 1};
    failed.rows[0] = (reply){.key = key, .id = id, .status = 200, .send_error = "net/http: nil Context"};
    results = run(detector, input, true, &failed);
    CHECK(results.len == 1);
    check_result(&results.items[0], key, false);
    br_results_clear(&results);
}

static void rollback(const br_detector *detector)
{
    char input[128];
    snprintf(input, sizeof(input), "nutritionix %s %s\nnutritionix %s %s", key, id, other, id2);
    br_results results = {0};
    br_result prior = {0};
    CHECK(!br_finding_key(&prior, 777, "prior", "key"));
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data;
    char *saved_error = results.items[0].verification_error, *error = NULL;
    fail_finding_after = 2;
    int rc = detector->scan(detector, NULL, false,
                            (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(rc == -1 && !fail_finding_after && error && !strcmp(error, "cannot create Nutritionix result"));
    CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].verified);
    CHECK(results.items[0].verification_error == saved_error && !strcmp(saved_error, "caller-owned"));
    free(error);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    product_and_status(detector);
    rollback(detector);
    return test_finish("Nutritionix key/id product, canonical headers, 2xx, nil skip, rollback");
}
