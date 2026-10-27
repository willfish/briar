/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[51], other[51];
static const char url_prefix[] = "https://plugin.api.dronahq.com/users/?tokenkey=";
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Only actual shared resources are failed; there is no URL formatter/copy seam. */
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 50 && strlen(other) == 50);
    CHECK(br_dronahq_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:dronahq)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_dronahq_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_dronahq_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_dronahq_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 651 && detector->version == 0 && !strcmp(detector->name, "DronaHQ"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DronaHQ is a platform for building internal tools and applications. DronaHQ keys can be used to access and manage these tools and applications."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "dronahq"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 651, expected, "key");
    CHECK(result->raw.len == 50 && result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[52];
    const char *accepted[] = {"dronahq = '%s'", "DrOnAhQ\r\n%s", "preDRONAHQsuffix:%s", "dronahq\r%s", "dronahq\n%s", "dronahq-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s dronahq", "drona hq %s", "dronahq%s", "dronahq _%s", "dronahq %s_", "dronahq X%s", "dronahq %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "dronahq%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[49] = '\0';
    snprintf(input, sizeof(input), "dronahq %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[50] = 'a'; changed[51] = '\0';
    snprintf(input, sizeof(input), "dronahq %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = "AZ_-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[25] = invalid[i];
        snprintf(input, sizeof(input), "dronahq %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'z', 50); changed[50] = '\0';
    snprintf(input, sizeof(input), "dronahq %s", changed); extraction_case(detector, input, strlen(input), changed); /* No hex/entropy/local FP restriction. */
    snprintf(input, sizeof(input), "dronahq %s %s", key, other); extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "dronahq%c%s", 0, key);
    CHECK(n == 58); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%cdronahq %s%c", 0xff, key, 0xff);
    CHECK(n == 60); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url, *agent_suffix;
    char expected_url[sizeof(url_prefix) + 50];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 651 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len);
    memcpy(steps->expected_url, url_prefix, sizeof(url_prefix) - 1);
    memcpy(steps->expected_url + sizeof(url_prefix) - 1, row->key, 51);
    CHECK(strlen(request->url) == sizeof(steps->expected_url) - 1 && !memcmp(request->url, steps->expected_url, sizeof(steps->expected_url)));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, steps->agent_suffix ? "TruffleHog dronahq-offline" : "TruffleHog"));
    /* Exact count excludes Auth, Type, Accept and invented logical CL. */
    steps->borrowed_url = request->url;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = row->nil_body ? "" : "synthetic ignored read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && !memcmp(steps->borrowed_url, steps->expected_url, sizeof(steps->expected_url)));
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}

static void verification_and_occurrences(const br_detector *detector)
{
    char input[224]; snprintf(input, sizeof(input), "dronahq %s\nDRONAHQ %s\ndronahq %s", key, other, key);
    reply rows[] = {{.key = key, .status = 200, .send_rc = 1, .send_error = "cannot create DronaHQ result"},
                    {.key = other, .status = 204, .nil_body = true},
                    {.key = key, .status = 299, .send_rc = -7, .send_error = "cannot format DronaHQ URL"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u, .agent_suffix = "dronahq-offline"};
        br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        check_result(&results.items[0], key, false); check_result(&results.items[1], other, verify); check_result(&results.items[2], key, false);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap); /* Constructor skip never appends and clears. */
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? other : key, false);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "dronahq %s", key);
    /* Every source 2xx branch succeeds, including absent/binary/unreadable bodies. */
    for (int status = 200; status < 300; ++status) {
        reply row = {.key = key, .status = status, .nil_body = status % 2 == 0}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const int rejected[] = {199, 300, 401, 403, 429, 503};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        reply row = {.key = key, .status = rejected[i]}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[72]; snprintf(input, sizeof(input), "dronahq %s", key);
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

static void resource_failures(const br_detector *detector)
{
    char input[144]; snprintf(input, sizeof(input), "dronahq %s\ndronahq %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* Finding resources fail before URL preparation/nil-context skip. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot create DronaHQ result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual positive +1 regex/capture failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append DronaHQ result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 50, 0); test_secret(other, 50, 11);
    const br_detector *detector = descriptor(); extraction(detector); verification_and_occurrences(detector);
    shared_setup_errors(detector); resource_failures(detector);
    return test_finish("DronaHQ");
}
