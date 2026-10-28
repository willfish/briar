/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[33], other[33];
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
    CHECK(br_financialmodelingprep_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:financialmodelingprep)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_financialmodelingprep_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_financialmodelingprep_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_financialmodelingprep_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 406 && detector->version == 0 && !strcmp(detector->name, "FinancialModelingPrep"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "FinancialModelingPrep provides financial data APIs. The API keys can be used to access financial data and related services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "financialmodelingprep"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 406, expected, "key");
    CHECK(result->raw.len == 32 && result->verified == verified && !result->verification_error);
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
    char input[192], changed[34];
    const char *accepted[] = {"financialmodelingprep = '%s'", "FiNaNcIaLmOdElInGpReP\r\n%s", "preFINANCIALMODELINGPREPsuffix:%s", "financialmodelingprep-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(d, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s financialmodelingprep", "financial modelingprep %s", "financialmodelingprep%s", "financialmodelingprep _%s", "financialmodelingprep %s_", "financialmodelingprep X%s", "financialmodelingprep %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(d, input, strlen(input), NULL);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "financialmodelingprep%*s%s", gap, "", key); extraction_case(d, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[31] = '\0';
    snprintf(input, sizeof(input), "financialmodelingprep %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[32] = 'z'; changed[33] = '\0';
    snprintf(input, sizeof(input), "financialmodelingprep %s", changed); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[16] = '-';
    snprintf(input, sizeof(input), "financialmodelingprep %s", changed); extraction_case(d, input, strlen(input), NULL);
    memset(changed, 'Z', 32); changed[32] = '\0';
    snprintf(input, sizeof(input), "financialmodelingprep %s", changed); extraction_case(d, input, strlen(input), changed); /* Not hex, no local entropy/validation. */
    snprintf(input, sizeof(input), "financialmodelingprep %s %s", key, other); extraction_case(d, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "financialmodelingprep%c%s", 0, key); CHECK(n > 0); extraction_case(d, input, (size_t)n, key);
}

typedef struct { const char *key, *read_error, *send_error; br_slice body; int status, send_rc; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *expected_ctx; const char *borrowed_url; char expected_url[114]; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 406 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && strlen(row->key) == 32);
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "https://financialmodelingprep.com/api/v3/financial-statement-symbol-lists?apikey=%s", row->key) == 113);
    CHECK(strlen(request->url) == 113 && !memcmp(request->url, steps->expected_url, 114));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog financialmodelingprep-offline"));
    /* Complete raw URL, no Auth/Type/Accept/logical CL. Only injected HTTP here. */
    steps->borrowed_url = request->url;
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = row->read_error};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && !memcmp(steps->borrowed_url, steps->expected_url, 114));
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *d, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "financialmodelingprep-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(d, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}

#define BODY(text) {(const unsigned char *)(text), sizeof(text) - 1}
static void occurrences_and_verification(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "financialmodelingprep %s; FINANCIALMODELINGPREP %s; financialmodelingprep %s", key, other, key);
    reply rows[] = {{.key = key, .status = 200, .body = BODY("[ \"")},
                    {.key = other, .status = 204, .body = BODY("[ \""), .read_error = ""},
                    {.key = key, .status = 200, .body = BODY("[ \""), .send_rc = -7, .send_error = "cannot create FinancialModelingPrep result"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u}; br_results results = run(d, input, verify, &steps); CHECK(results.len == 3);
        check_result(&results.items[0], key, verify); check_result(&results.items[1], other, false); check_result(&results.items[2], key, false); br_results_clear(&results);
        results = test_scan(d, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? other : key, false);
        br_results_clear(&results);
    }
    static const unsigned char binary[] = "\0\xff unrelated [ \" malformed";
    const struct { int status; br_slice body; const char *read_error; bool verified; } cases[] = {
        {200, BODY("[ \"USD\"]"), NULL, true}, {204, BODY("unrelated [ \" invalid"), NULL, true},
        {299, {binary, sizeof(binary) - 1}, NULL, true},
        {200, BODY("[\"USD\"]"), NULL, false}, {200, BODY("[  \"USD\"]"), NULL, false},
        {200, BODY("[\n\"USD\"]"), NULL, false}, {200, {0}, NULL, false},
        {200, {binary, sizeof(binary) - 1}, "partial read error", false},
        {204, BODY("[ \""), "", false},
        {199, BODY("[ \""), NULL, false}, {300, BODY("[ \""), NULL, false},
        {401, BODY("[ \""), NULL, false}, {403, BODY("[ \""), NULL, false},
        {500, {binary, sizeof(binary) - 1}, NULL, false}, {500, BODY("[ \""), "", false},
    };
    snprintf(input, sizeof(input), "financialmodelingprep %s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        reply row = {.key = key, .status = cases[i].status, .body = cases[i].body, .read_error = cases[i].read_error};
        script steps = {.rows = &row, .count = 1}; br_results results = run(d, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, cases[i].verified); br_results_clear(&results);
    }
}
#undef BODY

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }

static void shared_failures(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "financialmodelingprep %s", key);
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
    char input[160]; snprintf(input, sizeof(input), "financialmodelingprep %s; financialmodelingprep %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *cause = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .status = 200, .body = {(const unsigned char *)"[ \"", 3}}, {.key = other, .status = 200}};
        script steps = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "financialmodelingprep-offline"}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* First occurrence appended (verified in mode1) or nil-context skipped. */
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FinancialModelingPrep result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual positive +1 regex allocation failure. */
        CHECK(d->scan(d, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, cause, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append guard. */
        CHECK(d->scan(d, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FinancialModelingPrep result"));
        results.cap = cap; check_prior(&results, raw, cause, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 32, 0); test_secret(other, 32, 11); key[0] = 'G'; key[12] = 'Z'; key[31] = 'W'; other[9] = 'Y';
    const br_detector *d = descriptor(); extraction(d); occurrences_and_verification(d); shared_failures(d); own_resources(d);
    return test_finish("FinancialModelingPrep");
}
