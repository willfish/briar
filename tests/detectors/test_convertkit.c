/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "G7h9J2k5_M6n8P3q4_R1s0";
static const char other[] = "Z9_y8X7w6V5u4T3s2R1q0_";
static size_t fail_alloc_size, fail_alloc_after, allocation_failures, fail_part_after;

/* Target real shared-resource boundaries, never an invented URL allocation. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 22 && strlen(other) == 22);
    CHECK(br_convertkit_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    /* Native prefix allocation fails with a positive helper return. */
    fail_alloc_size = sizeof("(?i:convertkit)(?s:.){0,40}?"); fail_alloc_after = 1;
    CHECK(br_convertkit_init(&detector, &error) == -1 && !detector && error && !fail_alloc_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_convertkit_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_convertkit_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 225 && detector->version == 0 && !strcmp(detector->name, "Convertkit"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Convertkit is an email marketing service provider. API keys can be used to access and manage email marketing campaigns and subscriber data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "convertkit"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 225, expected, "key");
    CHECK(result->raw.len == 22 && result->verified == verified && !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 22 && !memcmp(json_object_get_string(part), expected, 22));
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
    char input[160], changed[24];
    const char *accepted[] = {"convertkit = '%s'", "CoNvErTkIt\r\n%s", "preCONVERTKITsuffix:%s", "convertkit\r%s", "convertkit\n%s", "convertkit-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key);
        extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s convertkit", "convert kit %s", "convertkit%s", "convertkit _%s", "convertkit %s_", "convertkit X%s", "convertkit %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key);
        extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "convertkit%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[21] = '\0';
    snprintf(input, sizeof(input), "convertkit %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[22] = 'a'; changed[23] = '\0';
    snprintf(input, sizeof(input), "convertkit %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char disallowed[] = "-.:/";
    for (size_t i = 0; i < sizeof(disallowed) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[10] = disallowed[i];
        snprintf(input, sizeof(input), "convertkit %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = changed[21] = '_';
    snprintf(input, sizeof(input), "convertkit %s", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, '_', 22); changed[22] = '\0';
    snprintf(input, sizeof(input), "convertkit %s", changed); extraction_case(detector, input, strlen(input), changed); /* No entropy filter. */
    snprintf(input, sizeof(input), "convertkit %s %s", key, other);
    extraction_case(detector, input, strlen(input), key); /* Non-overlapping whole matches, not all nearby words. */
    int n = snprintf(input, sizeof(input), "convertkit%c%s", 0, key);
    CHECK(n == 33); extraction_case(detector, input, (size_t)n, key); /* Complete input bytes beyond NUL. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    reply rows[3];
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
    char expected_url[80];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->expected_ctx && http->releases == at);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 225 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "https://api.convertkit.com/v3/forms?api_key=%s", step->key) == 66);
    CHECK(strlen(request->url) == 66 && !strcmp(request->url, steps->expected_url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    /* Common UA only: no invented Authorization, Type, Accept or logical CL. */
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog convertkit-offline" : "TruffleHog"));
    steps->borrowed_url = request->url;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){
        .status = step->status,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = "synthetic ignored body read error",
    };
    http->send_error = step->send_error; http->send_rc = step->send_rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && strlen(steps->borrowed_url) == 66);
    CHECK(!strcmp(steps->borrowed_url, steps->expected_url));
    steps->borrowed_url = NULL;
    test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url);
    return results;
}

static void occurrences_and_nil_context(const br_detector *detector)
{
    char input[160]; snprintf(input, sizeof(input), "convertkit %s\nCONVERTKIT %s\nconvertkit %s", key, other, key);
    const char *keys[] = {key, other, key};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.count = verify ? 3u : 0u, .agent_suffix = "convertkit-offline"};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = 1, .send_error = "synthetic timeout"};
        steps.rows[1] = (reply){.key = other, .status = 204};
        steps.rows[2] = (reply){.key = key, .status = 299, .send_rc = -7, .send_error = "context canceled"};
        br_results results = run(detector, input, verify, &steps);
        CHECK(results.len == 3);
        for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], keys[i], verify && i == 1);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input));
        CHECK(results.len == (verify ? 0u : 3u));
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i], false);
        br_results_clear(&results);
    }
}

static void statuses_and_send_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "convertkit %s", key);
    /* Every 2xx verifies despite absent/binary/unreadable bodies. */
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = status, .nil_body = status % 2 == 0};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {0, 199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.key = key, .status = rejected[i]};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
    const char *causes[] = {"net/http: nil Context", "out of memory constructing HTTP headers", "cannot create Convertkit result", "synthetic api_key=G7h9J2k5_M6n8P3q4_R1s0", "unsupported native client configuration", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key, .status = 200, .send_rc = i % 2 ? -1 : 1, .send_error = causes[i]};
        br_results results = run(detector, input, true, &steps);
        CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_send_allocation(void *user)
{
    (void)user;
    fail_alloc_size = sizeof(br_header); fail_alloc_after = 1;
    return false;
}

static void combined_send_domain(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "convertkit %s", key);
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
    char input[96]; snprintf(input, sizeof(input), "convertkit %s\nconvertkit %s", key, other);
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
        for (int failure = 0; failure < 4; ++failure) {
            size_t calls = http.calls;
            if (failure == 0) fail_part_after = 2; /* First finding was already appended (or nil-ctx skipped). */
            else {
                fail_alloc_size = failure == 1 ? 22 : failure == 2 ? 23 : 2 * sizeof(br_span);
                fail_alloc_after = failure == 3 ? 1 : 2;
            }
            int rc = detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error);
            CHECK(rc == -1 && error && !fail_part_after && !fail_alloc_after);
            const char *expected = failure < 2 ? "cannot create Convertkit result" : failure == 2 ? "out of memory copying detector capture" : "out of memory iterating regex";
            CHECK(!strcmp(error, expected));
            CHECK(http.calls == calls + (mode == 1 && failure < 2 ? 1u : 0u) && http.releases == http.calls);
            check_prior(&results, raw, prior_error, parts);
            free(error); error = NULL;
            http.calls = http.releases = 0;
        }
        /* A genuine positive +1 append-guard failure is fatal, not a skip. */
        size_t capacity = results.cap; results.cap = 0;
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error);
        CHECK(!strcmp(error, "cannot append Convertkit result"));
        results.cap = capacity; check_prior(&results, raw, prior_error, parts);
        free(error); error = NULL;
        CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error);
        check_prior(&results, raw, prior_error, parts); br_results_clear(&results);
    }
    script steps = {.count = 2};
    steps.rows[0] = (reply){.key = key, .status = 200}; steps.rows[1] = (reply){.key = other, .status = 299};
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 2); check_result(&results.items[0], key, true); check_result(&results.items[1], other, true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); occurrences_and_nil_context(detector); statuses_and_send_errors(detector);
    combined_send_domain(detector); resources_and_rollback(detector);
    return test_finish("Convertkit");
}
