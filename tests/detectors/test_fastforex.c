/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[29], other[29];
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 28 && strlen(other) == 28);
    CHECK(br_fastforex_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:fastforex)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_fastforex_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_fastforex_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_fastforex_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 636 && detector->version == 0 && !strcmp(detector->name, "FastForex"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "FastForex provides foreign exchange rate data. FastForex API keys can be used to access and retrieve this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "fastforex"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 636, expected, "key");
    CHECK(result->raw.len == 28 && result->verified == verified && !result->verification_error);
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
    char input[192], changed[30];
    const char *accepted[] = {"fastforex = '%s'", "FaStFoReX\r\n%s", "preFASTFOREXsuffix:%s", "fastforex\r%s", "fastforex\n%s", "fastforex-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s fastforex", "fast forex %s", "fastforex%s", "fastforex _%s", "fastforex %s_", "fastforex X%s", "fastforex %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "fastforex%*s%s", (int)gap, "", key); extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[27] = '\0';
    snprintf(input, sizeof(input), "fastforex %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[28] = 'z'; changed[29] = '\0';
    snprintf(input, sizeof(input), "fastforex %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = "ABCDEFZ_+/=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[14] = invalid[i];
        snprintf(input, sizeof(input), "FASTFOREX %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memset(changed, 'z', 28); changed[28] = '\0';
    snprintf(input, sizeof(input), "fastforex %s", changed); extraction_case(detector, input, strlen(input), changed); /* Not hex/UUID; no validation/entropy/local FP restriction. */
    snprintf(input, sizeof(input), "fastforex %s %s", key, other); extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "fastforex%c%s", 0, key);
    CHECK(n == 38); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%cfastforex %s%c", 0xff, key, 0xff);
    CHECK(n == 40); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url;
    char expected_url[72];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 636 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && strlen(row->key) == 28);
    CHECK(snprintf(steps->expected_url, sizeof(steps->expected_url), "https://api.fastforex.io/fetch-all?api_key=%s", row->key) == 71);
    CHECK(strlen(request->url) == 71 && !memcmp(request->url, steps->expected_url, 72));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, "TruffleHog fastforex-offline"));
    /* No Auth, Type, Accept or invented logical CL. No finance/provider calls:
     * the complete unencoded URL goes ONLY to this injected transport. */
    steps->borrowed_url = request->url;
    static const unsigned char body[] = "\0\xff ignored \"status\":401";
    http->response = (br_http_response){.status = row->status,
        .body = row->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1},
        .body_error = row->nil_body ? "" : "ignored partial-read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_url && !memcmp(steps->borrowed_url, steps->expected_url, 72));
    steps->borrowed_url = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "fastforex-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}

static void hyphen_boundaries_and_fragments(const br_detector *detector)
{
    char input[128], token[30], expected[29];
    token[0] = 'a'; token[1] = '-'; memcpy(token + 2, key + 1, 28);
    snprintf(input, sizeof(input), "fastforex %s", token);
    reply row = {.key = token + 1, .status = 200}; script steps = {.rows = &row, .count = 1};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], row.key, true); br_results_clear(&results);
    /* 29-byte token backtracks to its INNER '-' and captures only its last28. */
    memcpy(expected, key, sizeof(key)); expected[27] = '-';
    snprintf(input, sizeof(input), "fastforex %sq", expected); row.key = expected;
    results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], expected, true); br_results_clear(&results);
    /* End '-' -> adjacent q is a word boundary; do NOT require a full delimiter. */
    snprintf(input, sizeof(input), "fastforex %s", expected); extraction_case(detector, input, strlen(input), NULL);
    memset(expected, '-', 28); expected[28] = '\0';
    snprintf(input, sizeof(input), "FASTFOREX%sq", expected);
    results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], expected, true); br_results_clear(&results);
    /* Keyword word -> leading '-' and trailing '-' -> q bound an all-hyphen key. */
    snprintf(input, sizeof(input), "fastforex %s ", expected); extraction_case(detector, input, strlen(input), NULL);
}

static void occurrences_and_verification(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "fastforex %s\nFASTFOREX %s\nfastforex %s", key, other, key);
    reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 204, .nil_body = true},
                    {.key = key, .status = 200, .send_rc = -7, .send_error = "cannot create FastForex result"}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u}; br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        check_result(&results.items[0], key, verify); check_result(&results.items[1], other, verify); check_result(&results.items[2], key, false);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 3u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], i == 1 ? other : key, false);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "fastforex %s", key);
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
    (void)user; fail_size = sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[64]; snprintf(input, sizeof(input), "fastforex %s", key);
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
    char input[128]; snprintf(input, sizeof(input), "fastforex %s\nfastforex %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "fastforex-offline"}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* First original occurrence already appended or nil-context skipped. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create FastForex result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual +1 capture/regexp resource failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append FastForex result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 28, 0); test_secret(other, 28, 11);
    const br_detector *detector = descriptor(); extraction(detector); hyphen_boundaries_and_fragments(detector);
    occurrences_and_verification(detector); shared_setup_errors(detector); own_resources(detector);
    return test_finish("FastForex");
}
