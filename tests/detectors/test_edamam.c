/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[33], other_key[33], id[9], other_id[9];
static size_t fail_size, fail_after, allocation_failures, fail_id_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "id") && fail_id_after && --fail_id_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other_key) == 32 && strlen(id) == 8 && strlen(other_id) == 8);
    CHECK(br_edamam_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:edamam)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_edamam_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_edamam_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_edamam_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 424 && detector->version == 0 && !strcmp(detector->name, "Edamam"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Edamam provides nutrition analysis and diet recommendations. Edamam API keys can be used to access and modify nutrition data and perform diet analysis."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "edamam"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected_key, const char *expected_id, bool verified)
{
    CHECK(result->detector_type == 424 && result->raw.len == 32 && !memcmp(result->raw.data, expected_key, 32));
    CHECK(result->raw_v2.len == 40 && !memcmp(result->raw_v2.data, expected_key, 32) && !memcmp(result->raw_v2.data + 32, expected_id, 8));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->detector_name && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && json_object_get_string_len(part) == 32 && !memcmp(json_object_get_string(part), expected_key, 32));
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && json_object_get_string_len(part) == 8 && !memcmp(json_object_get_string(part), expected_id, 8));
}

static void pair_input(char *out, size_t size, const char *value_key, const char *value_id)
{
    CHECK(snprintf(out, size, "edamam %s%50sedamam %s", value_key, "", value_id) > 0);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected_key, const char *expected_id)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected_key && expected_id ? 1u : 0u) && !http.calls && !http.releases);
    if (results.len) check_result(&results.items[0], expected_key, expected_id, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[288], changed[34];
    pair_input(input, sizeof(input), key, id); extraction_case(detector, input, key, id);
    snprintf(input, sizeof(input), "EdAmAm\r\n%s%50sEDAMAM-%s-", key, "", id); extraction_case(detector, input, key, id);
    snprintf(input, sizeof(input), "preedamamsuffix:%s%50sedamam %s", key, "", id); extraction_case(detector, input, key, id);
    snprintf(input, sizeof(input), "edamam %s", key); extraction_case(detector, input, NULL, NULL); /* The ID regex cannot truncate the key word. */
    snprintf(input, sizeof(input), "edamam %s", id); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, key, sizeof(key)); changed[16] = 'A'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, key, sizeof(key)); changed[31] = '\0'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, key, sizeof(key)); changed[32] = 'a'; changed[33] = '\0'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, id, sizeof(id)); changed[4] = 'Z'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, id, sizeof(id)); changed[7] = '\0'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, id, sizeof(id)); changed[8] = 'a'; changed[9] = '\0'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "edamam _%s%50sedamam %s", key, "", id); extraction_case(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "edamam %s%50sedamam %s_", key, "", id); extraction_case(detector, input, NULL, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "edamam%*s%s%50sedamam %s", (int)gap, "", key, "", id);
        extraction_case(detector, input, gap == 40 ? key : NULL, gap == 40 ? id : NULL);
        snprintf(input, sizeof(input), "edamam %s%50sedamam%*s%s", key, "", (int)gap, "", id);
        extraction_case(detector, input, gap == 40 ? key : NULL, gap == 40 ? id : NULL);
    }
    char nonhex[33]; memset(nonhex, 'z', 32); nonhex[32] = '\0';
    pair_input(input, sizeof(input), nonhex, "zzzzzzzz"); extraction_case(detector, input, nonhex, "zzzzzzzz"); /* No hex, entropy or local FP check. */
    char far[1400]; int n = snprintf(far, sizeof(far), "edamam %s", key); CHECK(n > 0);
    memset(far + n, '.', 1100); snprintf(far + n + 1100, sizeof(far) - (size_t)n - 1100, "edamam %s", id);
    extraction_case(detector, far, key, id); /* Span1024 is not a local product limit. */
}

typedef struct { const char *key, *id, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_url;
    char expected_url[sizeof("https://api.edamam.com/auto-complete?app_id=&app_key=&q=") + 32 + 8];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 424 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !request->body.data && !request->body.len);
    int n = snprintf(steps->expected_url, sizeof(steps->expected_url), "https://api.edamam.com/auto-complete?app_id=%s&app_key=%s&q=", row->id, row->key);
    CHECK(n == (int)sizeof(steps->expected_url) - 1);
    CHECK(strlen(request->url) == (size_t)n && !memcmp(request->url, steps->expected_url, sizeof(steps->expected_url)));
    CHECK(!strcmp(request->url + n - 3, "&q=")); /* Empty q and trailing '=' must survive. */
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog edamam-offline"));
    /* Exact count excludes Auth, Accept and invented logical CL. */
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
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "edamam-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_url); return results;
}

static void products_and_verification(const br_detector *detector)
{
    const char *keys[] = {key, other_key, key}, *ids[] = {id, other_id, id};
    char input[640]; snprintf(input, sizeof(input), "edamam %s%50sEDAMAM %s%50sedamam %s%50sedamam %s%50sEdAmAm %s%50sedamam %s",
        key, "", other_key, "", key, "", id, "", other_id, "", id);
    const int statuses[] = {200, 204, 299, 199, 300, 401, 429, 503, 201}; reply rows[9];
    for (size_t i = 0; i < 9; ++i) rows[i] = (reply){.key = keys[i / 3], .id = ids[i % 3], .status = statuses[i], .nil_body = i % 2 != 0};
    rows[0].send_rc = 1; rows[0].send_error = "cannot create Edamam result";
    rows[8].send_rc = -7; rows[8].send_error = "net/http: nil Context";
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 9u : 0u}; br_results results = run(detector, input, verify, &steps); CHECK(results.len == 9);
        for (size_t i = 0; i < 9; ++i) check_result(&results.items[i], keys[i / 3], ids[i % 3], verify && !rows[i].send_rc && statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 9u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], keys[i / 3], ids[i % 3], false);
        br_results_clear(&results);
    }
    pair_input(input, sizeof(input), key, id);
    for (int status = 200; status < 300; ++status) {
        reply row = {.key = key, .id = id, .status = status, .nil_body = status % 2 == 0}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, id, true); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}

static void shared_setup_errors(const br_detector *detector)
{
    char input[136]; pair_input(input, sizeof(input), key, id);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], key, id, false); br_results_clear(&results);
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
    char input[192]; snprintf(input, sizeof(input), "edamam %s%50sedamam %s%50sedamam %s", key, "", id, "", other_id);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_result prior = {0}; br_results results = {0}; char *error = NULL;
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
        prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0);
        unsigned char *raw = results.items[0].raw.data; char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts;
        reply rows[] = {{.key = key, .id = id, .status = 200}, {.key = key, .id = other_id, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "edamam-offline"}; steps.expected_ctx = &ctx;
        fail_id_after = 2; /* First complete pair appended or nil-context skipped. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Edamam result") && !fail_id_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_url);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 2; /* Actual +1 ID-list scratch/capture failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Edamam result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 32, 0); test_secret(other_key, 32, 11); test_secret(id, 8, 7); test_secret(other_id, 8, 19);
    const br_detector *detector = descriptor(); extraction(detector); products_and_verification(detector);
    shared_setup_errors(detector); own_resources(detector);
    return test_finish("Edamam");
}
