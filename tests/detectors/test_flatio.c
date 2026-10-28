/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[129], other[129];
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 128 && strlen(other) == 128);
    CHECK(br_flatio_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:flat)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_flatio_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_flatio_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_flatio_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 501 && detector->version == 0 && !strcmp(detector->name, "FlatIO"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "FlatIO is a music notation software. FlatIO keys can be used to access and modify musical scores and related data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "flat")); /* NOT required flatio. */
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 501, expected, "key");
    CHECK(result->raw.len == 128 && result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *d, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(d, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *d)
{
    char input[384], changed[130];
    const char *accepted[] = {"flat = '%s'", "FlAt\r\n%s", "FLATio: %s", "preFLATsuffix:%s", "flat-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(d, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s flat", "fl at %s", "flat%s", "flat _%s", "flat %s_", "flat X%s", "flat %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(d, input, strlen(input), NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "flat%*s%s", gap, "", key); extraction_case(d, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[127] = '\0';
    snprintf(input, sizeof(input), "flat %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[128] = 'z'; changed[129] = '\0';
    snprintf(input, sizeof(input), "flat %s", changed); extraction_case(d, input, strlen(input), NULL);
    const char invalid[] = "AGZ_-+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[64] = invalid[i];
        snprintf(input, sizeof(input), "FLAT %s", changed); extraction_case(d, input, strlen(input), NULL);
    }
    memset(changed, 'z', 128); changed[128] = '\0';
    snprintf(input, sizeof(input), "flat %s", changed); extraction_case(d, input, strlen(input), changed); /* Not hex; no entropy/local validation. */
    snprintf(input, sizeof(input), "flat %s %s", key, other); extraction_case(d, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "flat%c%s", 0, key); CHECK(n == 133); extraction_case(d, input, (size_t)n, key);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool empty_body; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *expected_ctx; const char *borrowed_auth; char expected_auth[136]; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 501 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.flat.io/v2/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(snprintf(steps->expected_auth, sizeof(steps->expected_auth), "Bearer %s", row->key) == 135);
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 135 && !memcmp(request->headers[1].value, steps->expected_auth, 136));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog flatio-offline"));
    /* Exact header count excludes Content-Type and invented logical CL. */
    steps->borrowed_auth = request->headers[1].value;
    static const unsigned char body[] = "\0\xff invalid JSON \"status\":401";
    http->response = (br_http_response){.status = row->status,
        .body = row->empty_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1},
        .body_error = row->empty_body ? "" : "ignored partial-read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, steps->expected_auth, 136));
    steps->borrowed_auth = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *d, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "flatio-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(d, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth); return results;
}

static void occurrences_and_verification(const br_detector *d)
{
    char input[512]; snprintf(input, sizeof(input), "flat %s; FLAT %s; flat %s", key, other, key);
    reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 204, .empty_body = true},
                    {.key = key, .status = 200, .send_rc = -7, .send_error = "cannot create FlatIO result"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u}; br_results results = run(d, input, verify, &steps); CHECK(results.len == 3);
        check_result(&results.items[0], key, verify); check_result(&results.items[1], other, verify); check_result(&results.items[2], key, false); br_results_clear(&results);
        results = test_scan(d, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? other : key, false);
        br_results_clear(&results);
    }
    const int statuses[] = {200, 204, 299, 199, 300, 401, 403, 500};
    snprintf(input, sizeof(input), "flat %s", key);
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .empty_body = i % 2 != 0}; script steps = {.rows = &row, .count = 1};
        br_results results = run(d, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }

static void shared_failures(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "flat %s", key);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static void check_prior(const br_results *results, unsigned char *raw, char *cause, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == cause && !strcmp(cause, "caller-owned") && results->items[0].secret_parts == parts);
}

static void own_resources(const br_detector *d)
{
    char input[320]; snprintf(input, sizeof(input), "flat %s; flat %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "flatio-offline"}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* First occurrence appended (verified in mode1) or nil-context skipped. */
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FlatIO result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual positive +1 capture/regexp allocation failure. */
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append guard. */
        CHECK(d->scan(d, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FlatIO result"));
        results.cap = cap; check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 128, 0); test_secret(other, 128, 11);
    const br_detector *d = descriptor(); extraction(d); occurrences_and_verification(d); shared_failures(d); own_resources(d);
    return test_finish("FlatIO");
}
