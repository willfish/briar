/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "Aa0f-b1c2-d3e4f5-a6b7c8-d9e0f1a2";
static const char other[] = "1a2f-c3d4-e5f6a7-b8c9d0-e1f2a3b4";
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_everhour_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:everhour)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_everhour_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_everhour_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_everhour_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 284 && detector->version == 0 && !strcmp(detector->name, "Everhour"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Everhour is a time tracking software for teams. Everhour API keys can be used to access and manage project and time tracking data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "everhour"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 284, expected, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void token_case(const br_detector *detector, const char *token, bool accepted)
{
    char input[160]; snprintf(input, sizeof(input), "EvErHoUr %s", token);
    extraction_case(detector, input, strlen(input), accepted ? token : NULL);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[34];
    const char *accepted[] = {"everhour = '%s'", "EvErHoUr\r\n%s", "preEVERHOURsuffix:%s", "everhour\r%s", "everhour\n%s", "everhour-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s everhour", "ever hour %s", "everhour%s", "everhour _%s", "everhour %s_", "everhour X%s", "everhour %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "everhour%*s%s", (int)gap, "", key); extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    token_case(detector, "AAAA-0000-000000-000000-00000000", true); /* Upper A allowed throughout FIRST group only; no local validation/entropy restriction. */
    token_case(detector, "abcdef12-3456-7890-abcd-ef1234567890", false); /* Ordinary UUID 8-4-4-4-12 is NOT this 4-4-6-6-8 shape. */
    token_case(detector, "aaaabbbbccccddddeeeeffff00001111", false);
    for (char upper = 'B'; upper <= 'F'; ++upper) {
        memcpy(changed, key, sizeof(key)); changed[0] = upper; token_case(detector, changed, false);
    }
    const size_t later_groups[] = {5, 10, 17, 24};
    for (size_t i = 0; i < sizeof(later_groups) / sizeof(later_groups[0]); ++i) {
        for (char upper = 'A'; upper <= 'F'; ++upper) {
            memcpy(changed, key, sizeof(key)); changed[later_groups[i]] = upper; token_case(detector, changed, false);
        }
    }
    const size_t hyphens[] = {4, 9, 16, 23};
    for (size_t i = 0; i < sizeof(hyphens) / sizeof(hyphens[0]); ++i) {
        CHECK(key[hyphens[i]] == '-'); memcpy(changed, key, sizeof(key)); changed[hyphens[i]] = '_'; token_case(detector, changed, false);
    }
    memcpy(changed, key, sizeof(key)); changed[31] = '\0'; token_case(detector, changed, false);
    memcpy(changed, key, sizeof(key)); changed[32] = 'a'; changed[33] = '\0'; token_case(detector, changed, false);
    memcpy(changed, key, sizeof(key)); changed[0] = 'g'; token_case(detector, changed, false);
    snprintf(input, sizeof(input), "everhour %s %s", key, other); extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "everhour%c%s", 0, key);
    CHECK(n == 41); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%ceverhour %s%c", 0xff, key, 0xff);
    CHECK(n == 43); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *expected_ctx; const char *borrowed_key; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 284 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.everhour.com/clients"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && strlen(request->headers[1].value) == 32 && !memcmp(request->headers[1].value, row->key, 33));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog everhour-offline"));
    /* Exact count excludes Auth, Accept and invented logical CL. */
    steps->borrowed_key = request->headers[1].value;
    static const unsigned char body[] = "\0\xff invalid JSON \"status\":401";
    http->response = (br_http_response){.status = row->status,
        .body = row->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1},
        .body_error = row->nil_body ? "" : "ignored partial-read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_key && !memcmp(steps->borrowed_key, steps->rows[http->calls - 1].key, 33));
    steps->borrowed_key = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "everhour-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_key); return results;
}

static void occurrences_and_verification(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "everhour %s\nEVERHOUR %s\neverhour %s", key, other, key);
    reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 204, .nil_body = true},
                    {.key = key, .status = 200, .send_rc = -7, .send_error = "cannot create Everhour result"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u}; br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        check_result(&results.items[0], key, verify); check_result(&results.items[1], other, verify); check_result(&results.items[2], key, false);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? other : key, false);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "everhour %s", key);
    for (int status = 200; status < 300; ++status) {
        reply row = {.key = key, .status = status, .nil_body = status % 2 != 0}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int statuses[] = {199, 300, 301, 400, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .nil_body = i % 2 != 0}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "everhour %s", key);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned") && results->items[0].secret_parts == parts);
}

static void own_resources(const br_detector *detector)
{
    char input[128]; snprintf(input, sizeof(input), "everhour %s\neverhour %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "everhour-offline"}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* First original occurrence already appended or nil-context skipped. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Everhour result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_key);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual +1 capture/regexp resource failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Everhour result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); occurrences_and_verification(detector);
    shared_setup_errors(detector); own_resources(detector); return test_finish("Everhour");
}
