/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[53], other[53];
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 52 && strlen(other) == 52);
    CHECK(br_dyspatch_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:dyspatch)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_dyspatch_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_dyspatch_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_dyspatch_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 258 && detector->version == 0 && !strcmp(detector->name, "Dyspatch"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Dyspatch is a platform for managing and sending transactional emails. Dyspatch API keys can be used to access and manage email templates and sending operations."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "dyspatch"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 258, expected, "key");
    CHECK(result->raw.len == 52 && result->verified == verified && !result->verification_error);
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
    char input[192], changed[54];
    const char *accepted[] = {"dyspatch = '%s'", "DySpAtCh\r\n%s", "preDYSPATCHsuffix:%s", "dyspatch\r%s", "dyspatch\n%s", "dyspatch-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s dyspatch", "dys patch %s", "dyspatch%s", "dyspatch _%s", "dyspatch %s_", "dyspatch X%s", "dyspatch %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "dyspatch%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[51] = '\0';
    snprintf(input, sizeof(input), "dyspatch %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[52] = 'A'; changed[53] = '\0';
    snprintf(input, sizeof(input), "dyspatch %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = "az_-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[26] = invalid[i];
        snprintf(input, sizeof(input), "dyspatch %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'Z', 52); changed[52] = '\0';
    snprintf(input, sizeof(input), "dyspatch %s", changed); extraction_case(detector, input, strlen(input), changed); /* Not hex-only; no local FP/entropy filter. */
    snprintf(input, sizeof(input), "dyspatch %s %s", key, other); extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "dyspatch%c%s", 0, key);
    CHECK(n == 61); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%cdyspatch %s%c", 0xff, key, 0xff);
    CHECK(n == 63); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error, *body_error; br_slice body; int status, send_rc; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_auth;
    char expected_auth[60];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 258 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.dyspatch.io/templates"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/vnd.dyspatch.2020.11+json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 59);
    memcpy(steps->expected_auth, "Bearer ", 7); memcpy(steps->expected_auth + 7, row->key, 53);
    CHECK(!memcmp(request->headers[1].value, steps->expected_auth, 60));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog dyspatch-offline"));
    /* Exact header count excludes Type and invented logical Content-Length. */
    steps->borrowed_auth = request->headers[1].value;
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = row->body_error};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, steps->expected_auth, 60));
    steps->borrowed_auth = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "dyspatch-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth); return results;
}

static void occurrences_and_drop_priority(const br_detector *detector)
{
    char input[240]; snprintf(input, sizeof(input), "dyspatch %s\nDYSPATCH %s\ndyspatch %s", key, other, key);
    reply rows[] = {{.key = key, .status = 500, .body = {(const unsigned char *)"metadata", 8}},
                    {.key = other, .status = 200, .body = {(const unsigned char *)"data", 4}, .body_error = ""},
                    {.key = key, .status = 401, .body = {(const unsigned char *)"limited_usage", 13}, .body_error = "read failure", .send_rc = -7, .send_error = "cannot create Dyspatch result"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u}; br_results results = run(detector, input, verify, &steps);
        CHECK(results.len == (verify ? 2u : 3u));
        check_result(&results.items[0], key, verify);
        if (verify) check_result(&results.items[1], key, false);
        else { check_result(&results.items[1], other, false); check_result(&results.items[2], key, false); }
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? other : key, false);
        br_results_clear(&results);
    }
}

static void binary_markers_and_read_errors(const br_detector *detector)
{
    char input[72]; snprintf(input, sizeof(input), "dyspatch %s", key);
    static const unsigned char binary[] = {'x', 0, 0xff, 'm', 'e', 't', 'a', 'd', 'a', 't', 'a'};
    const int statuses[] = {0, 199, 200, 204, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .body = {binary, sizeof(binary)}}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, true); br_results_clear(&results);
    }
    const struct { br_slice body; bool verified; } bodies[] = {
        {{(const unsigned char *)"limited_usage", 13}, true},
        {{(const unsigned char *)"metadata", 8}, true},
        {{(const unsigned char *)"DATA LIMITED_USAGE", 18}, false},
        {{(const unsigned char *)"{}", 2}, false},
        {{0}, false},
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        reply row = {.key = key, .status = 500, .body = bodies[i].body}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, bodies[i].verified); br_results_clear(&results);
    }
    const int read_statuses[] = {200, 401, 500};
    for (size_t i = 0; i < 3; ++i) for (int empty = 0; empty < 2; ++empty) {
        reply row = {.key = key, .status = read_statuses[i], .body = {binary, sizeof(binary)}, .body_error = empty ? "" : "synthetic read failure"};
        script steps = {.rows = &row, .count = 1}; br_results results = run(detector, input, true, &steps);
        CHECK(!results.len); br_results_clear(&results); /* Read failure wins over even matching partial bytes. */
    }
    reply send = {.key = key, .status = 200, .body = {binary, sizeof(binary)}, .body_error = "", .send_rc = 1, .send_error = "net/http: nil Context"};
    script failed = {.rows = &send, .count = 1}; br_results results = run(detector, input, true, &failed);
    CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[72]; snprintf(input, sizeof(input), "dyspatch %s", key);
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
    char input[152]; snprintf(input, sizeof(input), "dyspatch %s\ndyspatch %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 4; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .status = 500, .body = {(const unsigned char *)"data", 4}}, {.key = other, .status = 200}};
        if (mode == 3) rows[0].body_error = ""; /* First read-error DROP cannot hide a later finding resource failure. */
        script steps = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &steps};
        br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "dyspatch-offline"}; steps.expected_ctx = &ctx;
        fail_part_after = 2;
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Dyspatch result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 || mode == 3 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual positive +1 capture/regexp failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Dyspatch result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 52, 0); test_secret(other, 52, 11);
    for (size_t i = 0; i < 52; ++i) {
        if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
        if (other[i] >= 'a' && other[i] <= 'z') other[i] -= 'a' - 'A';
    }
    const br_detector *detector = descriptor(); extraction(detector); occurrences_and_drop_priority(detector);
    binary_markers_and_read_errors(detector); shared_setup_errors(detector); own_resources(detector);
    return test_finish("Dyspatch");
}
