/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[43], other_key[53], id[37], other_id[37];
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
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 42 && strlen(other_key) == 52 && strlen(id) == 36 && strlen(other_id) == 36);
    CHECK(br_exportsdk_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:exportsdk)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_exportsdk_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_exportsdk_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_exportsdk_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 771 && detector->version == 0 && !strcmp(detector->name, "ExportSDK"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "ExportSDK is a service used for exporting data and generating PDFs. ExportSDK keys can be used to authenticate API requests and generate documents."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "exportsdk"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    /* Required template IDs remain HIDDEN even after verification. */
    test_key_result(result, 771, expected, "key");
    CHECK(result->raw.len == strlen(expected) && result->verified == verified && !result->verification_error);
}

static void pair_input(char *out, size_t size, const char *value_key, const char *value_id)
{
    CHECK(snprintf(out, size, "exportsdk %s%50sexportsdk %s", value_key, "", value_id) > 0);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[320], changed[54];
    pair_input(input, sizeof(input), key, id); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "ExPoRtSdK\r\n%s%50sEXPORTSDK '%s'", key, "", id); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "preexportsdksuffix:%s%50sexportsdk %s", key, "", id); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "exportsdk %s", key); extraction_case(detector, input, NULL); /* Ordinary word-only suffix cannot start an ID after a word underscore. */
    snprintf(input, sizeof(input), "exportsdk %s", id); extraction_case(detector, input, NULL);
    const size_t prefix_lengths[] = {4, 5, 10, 15, 16};
    for (size_t i = 0; i < sizeof(prefix_lengths) / sizeof(prefix_lengths[0]); ++i) {
        size_t n = prefix_lengths[i]; memset(changed, 'z', n); changed[n] = '_'; memcpy(changed + n + 1, key + 6, 37);
        pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, n >= 5 && n <= 15 ? changed : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = 'A'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[17] = 'A'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[5] = '-'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[41] = '\0'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[42] = 'z'; changed[43] = '\0'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL);
    memcpy(changed, id, sizeof(id)); changed[18] = 'A'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL);
    memcpy(changed, id, sizeof(id)); changed[35] = '\0'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL);
    memcpy(changed, id, sizeof(id)); changed[36] = 'z'; changed[37] = '\0'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "exportsdk _%s%50sexportsdk %s", key, "", id); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "exportsdk %s%50sexportsdk %s_", key, "", id); extraction_case(detector, input, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "exportsdk%*s%s%50sexportsdk %s", (int)gap, "", key, "", id);
        extraction_case(detector, input, gap == 40 ? key : NULL);
        snprintf(input, sizeof(input), "exportsdk %s%50sexportsdk%*s%s", key, "", (int)gap, "", id);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    char far[1400]; int n = snprintf(far, sizeof(far), "exportsdk %s", key); CHECK(n > 0);
    memset(far + n, '.', 1100); snprintf(far + n + 1100, sizeof(far) - (size_t)n - 1100, "exportsdk %s", id);
    extraction_case(detector, far, key); /* Span1024 is NOT a detector-local cap. */
}

typedef struct { const char *key, *id, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_key;
    const unsigned char *borrowed_body;
    char expected_body[57];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 771 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.exportsdk.com/v1/pdf"));
    CHECK(strlen(row->id) == 36 && snprintf(steps->expected_body, sizeof(steps->expected_body), "{  \"templateId\": \"%s\"}", row->id) == 56);
    CHECK(request->body.data && request->body.len == 56 && !memcmp(request->body.data, steps->expected_body, 57));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "X-Api-Key") && !strcmp(request->headers[1].value, row->key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog exportsdk-offline"));
    /* Exact count excludes Auth, Accept and invented logical CL. Never make a
     * real PDF request: both headers and full payload go ONLY to this fake. */
    steps->borrowed_key = request->headers[1].value; steps->borrowed_body = request->body.data;
    static const unsigned char body[] = "\0\xff ignored \"status\":401";
    http->response = (br_http_response){.status = row->status,
        .body = row->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body) - 1},
        .body_error = row->nil_body ? "" : "ignored partial-read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_key && !strcmp(steps->borrowed_key, steps->rows[http->calls - 1].key));
    CHECK(steps->borrowed_body && !memcmp(steps->borrowed_body, steps->expected_body, 57));
    steps->borrowed_key = NULL; steps->borrowed_body = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "exportsdk-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_key && !steps->borrowed_body); return results;
}

static void hyphen_boundaries_and_fragments(const br_detector *detector)
{
    char input[224], special[43], fragment[37];
    memcpy(special, key, sizeof(key)); special[6] = '-';
    snprintf(input, sizeof(input), "exportsdk %s", special);
    reply row = {.key = special, .id = special + 6, .status = 200}; script steps = {.rows = &row, .count = 1};
    br_results results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], special, true); br_results_clear(&results);
    /* Word underscore -> nonword '-' permits an ID from the key itself. */
    memcpy(special, key, sizeof(key)); special[6] = 'a'; special[7] = '-'; memset(special + 8, 'z', 33); special[41] = '-';
    snprintf(input, sizeof(input), "exportsdk %sq", special);
    memcpy(fragment, special + 7, 35); fragment[35] = 'q'; fragment[36] = '\0';
    row.id = fragment; results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], special, true); br_results_clear(&results);
    /* Key ends '-' before word q; ID begins at its INNER '-' and extends into q.
     * Do not validate UUIDs or substitute the key suffix for this actual capture. */
    snprintf(input, sizeof(input), "exportsdk %s", special); extraction_case(detector, input, NULL); /* '-' at EOF lacks final word boundary. */
    memset(fragment, '-', 36); fragment[36] = '\0';
    snprintf(input, sizeof(input), "exportsdk %s%50sEXPORTSDK%sq", key, "", fragment);
    row.key = key; row.id = fragment;
    results = run(detector, input, true, &steps); CHECK(results.len == 1); check_result(&results.items[0], key, true); br_results_clear(&results);
}

static void products_and_verification(const br_detector *detector)
{
    const char *keys[] = {key, other_key, key}, *ids[] = {id, other_id, id};
    char input[900]; snprintf(input, sizeof(input), "exportsdk %s%50sEXPORTSDK %s%50sexportsdk %s%50sexportsdk %s%50sExPoRtSdK %s%50sexportsdk %s",
        key, "", other_key, "", key, "", id, "", other_id, "", id);
    const int statuses[] = {200, 204, 299, 199, 300, 401, 403, 503, 201}; reply rows[9];
    for (size_t i = 0; i < 9; ++i) rows[i] = (reply){.key = keys[i / 3], .id = ids[i % 3], .status = statuses[i], .nil_body = i % 2 != 0};
    rows[0].send_rc = 1; rows[0].send_error = "cannot create ExportSDK result";
    rows[8].send_rc = -7; rows[8].send_error = "cannot append ExportSDK result";
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 9u : 0u}; br_results results = run(detector, input, verify, &steps); CHECK(results.len == 9);
        for (size_t i = 0; i < 9; ++i) check_result(&results.items[i], keys[i / 3], verify && !rows[i].send_rc && statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 9u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], false);
        br_results_clear(&results);
    }
    pair_input(input, sizeof(input), key, id);
    for (int status = 200; status < 300; ++status) {
        reply row = {.key = key, .id = id, .status = status, .nil_body = status % 2 != 0}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, true); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[224]; pair_input(input, sizeof(input), key, id);
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
    char input[320]; snprintf(input, sizeof(input), "exportsdk %s%50sexportsdk %s%50sexportsdk %s", key, "", id, "", other_id);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .id = id, .status = 200}, {.key = key, .id = other_id, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "exportsdk-offline"}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* First hidden-ID product already appended or nil-context skipped. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create ExportSDK result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_key && !steps.borrowed_body);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 2; /* Genuine positive +1 ID-list regex resource failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append ExportSDK result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    memcpy(key, "abcgz_", 6); test_secret(key + 6, 36, 0);
    memcpy(other_key, "zzzzzzzzzzzzzzz_", 16); test_secret(other_key + 16, 36, 11);
    test_secret(id, 36, 7); test_secret(other_id, 36, 19);
    const br_detector *detector = descriptor(); extraction(detector); hyphen_boundaries_and_fragments(detector);
    products_and_verification(detector); shared_setup_errors(detector); own_resources(detector);
    return test_finish("ExportSDK");
}
