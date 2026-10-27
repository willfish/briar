/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_crowdin_init(const br_detector **out, char **error);

static const char key[] =
    "G7h9J2k5M6n8P3q4R1s0" "T2u5V7w9X2y4Z6a8B3c1"
    "D5e7F9g2H4j6K8m0N3p5" "Q7r9S2t4U6v8W0x3Y5z7";
static const char other[] =
    "Z9y8X7w6V5u4T3s2R1q0" "Z9y8X7w6V5u4T3s2R1q0"
    "Z9y8X7w6V5u4T3s2R1q0" "Z9y8X7w6V5u4T3s2R1q0";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;

/* Real native capture/finding resource boundaries, with no heap auth seam. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) {
        ++allocation_failures;
        return NULL;
    }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 80 && strlen(other) == 80);
    CHECK(br_crowdin_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    fail_alloc_size = sizeof("(?i:crowdin)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_crowdin_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_crowdin_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_crowdin_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 335 && detector->version == 0 && !strcmp(detector->name, "Crowdin"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Crowdin is a cloud-based localization management platform. Crowdin API keys can be used to access and manage localization projects and resources."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "crowdin"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 335, expected, "key");
    CHECK(result->raw.len == 80 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 80 && !memcmp(json_object_get_string(part), expected, 80));
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[82];
    const char *accepted[] = {"crowdin = '%s'", "CrOwDiN\r\n%s", "preCROWDINsuffix:%s", "crowdin\r%s", "crowdin\n%s", "crowdin-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s crowdin", "crow din %s", "crowdin%s", "crowdin _%s", "crowdin %s_", "crowdin X%s", "crowdin %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "crowdin%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[79] = '\0';
    snprintf(input, sizeof(input), "crowdin %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[80] = 'A'; changed[81] = '\0';
    snprintf(input, sizeof(input), "crowdin %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char disallowed[] = "_-.:/+=";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[40] = disallowed[i];
        snprintf(input, sizeof(input), "CROWDIN %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    const char low_entropy[] = {'A', 'a', '9'};
    for (size_t i = 0; i < sizeof(low_entropy); ++i) {
        memset(changed, low_entropy[i], 80); changed[80] = '\0';
        snprintf(input, sizeof(input), "crowdin %s", changed); extraction_case(detector, input, strlen(input), changed);
    } /* No local FP/entropy filter or required mixture of cases/digits. */
    snprintf(input, sizeof(input), "crowdin %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Non-overlapping whole matches. */
    snprintf(input, sizeof(input), "crowdin crowdin %s", key);
    extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "crowdin%c%s", 0, key);
    CHECK(n == 88); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc, body_kind; } reply;
typedef struct {
    reply rows[3];
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_auth, *agent_suffix;
} script;

static void check_authorization(const char *authorization, const char *expected)
{
    CHECK(authorization && strlen(authorization) == 87 && !memcmp(authorization, "Bearer ", 7));
    CHECK(!memcmp(authorization + 7, expected, 80) && authorization[87] == '\0');
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->expected_ctx && http->releases == at);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 335 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.crowdin.com/api/v2/storages"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    check_authorization(request->headers[0].value, step->key);
    steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->agent_suffix ? "TruffleHog crowdin-offline" : "TruffleHog"));
    /* Full effective header set: no invented Type, Accept or logical CL. */
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){
        .status = step->status,
        .body = step->body_kind == 0 ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = step->body_kind == 0 ? NULL : step->body_kind == 1 ? "" : "synthetic ignored body read error",
    };
    http->send_error = step->send_error; http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    /* The common sender has freed its header array. The provider's complete
     * borrowed stack value must still be valid, even after a failed send. */
    check_authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key);
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth);
    return results;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    const char *keys[] = {key, other, key};
    unsigned char input[3 * 90 + 1]; size_t len = 0;
    for (size_t i = 0; i < 3; ++i) {
        memcpy(input + len, i == 1 ? "CROWDIN " : "crowdin ", 8); len += 8;
        memcpy(input + len, keys[i], 80); len += 80;
        input[len++] = '\0'; input[len++] = i == 1 ? '\r' : '\n';
    }
    input[len++] = 0xff; /* Invalid bytes outside matches are not a global UTF-8 rejection. */
    br_slice data = {input, len};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .agent_suffix = "crowdin-offline"};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = 1, .send_error = "synthetic timeout"};
        steps.rows[1] = (reply){.key = other, .status = 204};
        steps.rows[2] = (reply){.key = key, .status = 299, .send_rc = -7, .send_error = "context canceled"};
        br_results results = run(detector, data, verify, &steps);
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i == 1);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, data.data, data.len);
        CHECK(results.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
        br_results_clear(&results);
    }
    script steps = {.count = 3};
    for (size_t i = 0; i < 3; ++i) steps.rows[i] = (reply){.key = keys[i], .status = 200};
    br_results results = run(detector, data, true, &steps);
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], true); /* No cache/uniqueness. */
    br_results_clear(&results);
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "crowdin %s", key);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = status, .body_kind = status % 3};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = rejected[i], .body_kind = 2};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    char sensitive[192]; snprintf(sensitive, sizeof(sensitive), "synthetic Bearer %s", key);
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create Crowdin result", sensitive, "unsupported native client configuration", "context canceled", "context deadline exceeded", "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results results = run(detector, data, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = 2 * sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[96]; snprintf(input, sizeof(input), "crowdin %s", key);
    for (int mode = 0; mode < 5; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {
            .transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : mode == 4 ? fail_send_allocation : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL,
        };
        size_t before = allocation_failures;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_alloc_after && allocation_failures == before + (mode == 4 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned"));
    CHECK(results->items[0].secret_parts == parts);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(parts, "key", &part) && !strcmp(json_object_get_string(part), "prior"));
}

static void resources_and_rollback(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "crowdin %s\ncrowdin %s", key, other);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    br_captures probe = {0}; char *error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(br_captures_find(detector->state, data, &probe, false, &error) == 1 && error && !fail_alloc_after);
    free(error); error = NULL; br_captures_clear(&probe);
    for (int mode = 0; mode < 3; ++mode) {
        script steps = {.count = 2};
        steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 200};
        test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_result prior = {0}; br_results results = {0};
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
        prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
        CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        const char *expected[] = {"out of memory iterating regex", "out of memory copying detector capture", "cannot create Crowdin result", "cannot create Crowdin result"};
        for (int failure = 0; failure < 4; ++failure) {
            if (failure == 0) { fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1; }
            if (failure == 1) { fail_alloc_size = 81; fail_alloc_after = 2; }
            if (failure == 2) { fail_alloc_size = 80; fail_alloc_after = 2; }
            if (failure == 3) fail_part_after = 2;
            size_t before = allocation_failures;
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_alloc_after && !fail_part_after);
            CHECK(!strcmp(error, expected[failure]) && allocation_failures == before + (failure == 3 ? 0u : 1u));
            CHECK(http.calls == (mode == 1 && failure >= 2 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = 0;
        }
        /* The actual append guard returns +1; normalize it to fatal -1. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append Crowdin result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error);
        check_prior(&results, raw, prior_error, parts); br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, false, data.data, data.len);
    CHECK(results.len == 2); check_result(&results.items[0], key, false); check_result(&results.items[1], other, false);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_and_send_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("Crowdin");
}
