/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other_key[] = "fedcba98-7654-3210-fedc-ba9876543210";
static const char id[] = "AB12CD3-EF45GH6-IJ78KL9-MN01OP2";
static const char other_id[] = "ZY98XW7-VU65TS4-RQ32PO1-NM09LK8";
static size_t fail_size, fail_after, allocation_failures, fail_part_after;
static bool arm_auth;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && arm_auth && !strcmp(name, "key")) { arm_auth = false; fail_size = 99; fail_after = 1; }
    return rc;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 36 && strlen(other_key) == 36 && strlen(id) == 31 && strlen(other_id) == 31);
    CHECK(br_duply_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:duply)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_duply_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_duply_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_duply_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 821 && detector->version == 0 && !strcmp(detector->name, "Duply"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "An API for generating images. API keys can fetch and create images."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "duply"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    /* ID is necessary for each native product but never projected into output. */
    test_key_result(result, 821, expected, "key");
    CHECK(result->raw.len == 36 && result->verified == verified && !result->verification_error);
}

static void pair_input(char *out, size_t size, const char *value_key, const char *value_id)
{
    CHECK(snprintf(out, size, "duply %s%50sduply %s", value_key, "", value_id) > 0);
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
    char input[320], changed[38];
    pair_input(input, sizeof(input), key, id); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "DuPlY\r\n%s%50sDUPLY-%s-", key, "", id); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "preduplysuffix:%s%50sduply %s", key, "", id); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "duply %s", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "duply %s", id); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[9] = 'A'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = 'g'; pair_input(input, sizeof(input), changed, id); extraction_case(detector, input, NULL);
    memcpy(changed, id, sizeof(id)); changed[0] = 'a'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL);
    memcpy(changed, id, sizeof(id)); changed[7] = '_'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL);
    memcpy(changed, id, sizeof(id)); changed[31] = 'X'; changed[32] = '\0'; pair_input(input, sizeof(input), key, changed); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "duply _%s%50sduply %s", key, "", id); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "duply %s%50sduply %s_", key, "", id); extraction_case(detector, input, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "duply%*s%s%50sduply %s", (int)gap, "", key, "", id);
        extraction_case(detector, input, gap == 40 ? key : NULL);
        snprintf(input, sizeof(input), "duply %s%50sduply%*s%s", key, "", (int)gap, "", id);
        extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    char far[1400]; int n = snprintf(far, sizeof(far), "duply %s", key); CHECK(n > 0);
    memset(far + n, '.', 1100); snprintf(far + n + 1100, sizeof(far) - (size_t)n - 1100, "duply %s", id);
    extraction_case(detector, far, key); /* Span1024 is a hint, not a local product constraint. */
}

typedef struct { const char *key, *id, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_auth;
    char expected_auth[99];
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 821 && request->profile == BR_HTTP_SANE && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://gen.duply.co/v1/usage"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 98);
    char *basic = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)row->id, 31}, (br_slice){(const unsigned char *)row->key, 36}, &basic, &error) == 0 && !error);
    CHECK(strlen(basic + 6) == 92); memcpy(steps->expected_auth, basic, 99); free(basic);
    CHECK(!memcmp(request->headers[1].value, steps->expected_auth, 99)); /* ID:KEY, never reversed. */
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog duply-offline"));
    /* Exact count excludes Accept and invented logical CL. */
    steps->borrowed_auth = request->headers[1].value;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status,
        .body = row->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = row->nil_body ? "" : "synthetic ignored read error"};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, steps->expected_auth, 99));
    steps->borrowed_auth = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "duply-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth); return results;
}

static void products_and_verification(const br_detector *detector)
{
    const char *keys[] = {key, other_key, key}, *ids[] = {id, other_id, id};
    char input[800]; snprintf(input, sizeof(input), "duply %s%50sDUPLY %s%50sduply %s%50sduply %s%50sDuPlY %s%50sduply %s",
        key, "", other_key, "", key, "", id, "", other_id, "", id);
    const int statuses[] = {200, 204, 299, 199, 300, 401, 429, 503, 201}; reply rows[9];
    for (size_t i = 0; i < 9; ++i) rows[i] = (reply){.key = keys[i / 3], .id = ids[i % 3], .status = statuses[i], .nil_body = i % 2 != 0};
    rows[0].send_rc = 1; rows[0].send_error = "cannot create Duply result";
    rows[8].send_rc = -7; rows[8].send_error = "out of memory constructing Basic authentication";
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
        reply row = {.key = key, .id = id, .status = status, .nil_body = status % 2 == 0}; script steps = {.rows = &row, .count = 1};
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
    char input[160]; pair_input(input, sizeof(input), key, id);
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], key, false); br_results_clear(&results);
    }
}

static br_results prior_result(void)
{
    br_result prior = {0}; br_results results = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error); CHECK(br_results_push(&results, &prior) == 0); return results;
}

static void check_prior(const br_results *results, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 777 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(results->items[0].verification_error == error && !strcmp(error, "caller-owned") && results->items[0].secret_parts == parts);
}

static void own_resources(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "duply %s%50sduply %s%50sduply %s", key, "", id, "", other_id);
    br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
        reply rows[] = {{.key = key, .id = id, .status = 200}, {.key = key, .id = other_id, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "duply-offline"}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* One hidden-ID product already appended or nil-context skipped. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "cannot create Duply result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 2; /* ID-list scratch failure is genuine +1, not a skipped product. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append Duply result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
    pair_input(input, sizeof(input), key, id); data = (br_slice){(const unsigned char *)input, strlen(input)};
    br_scan_ctx ctx = {0}; br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
    char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
    arm_auth = true;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == 0 && !error && !arm_auth && fail_after == 1);
    fail_after = 0; check_prior(&results, raw, prior_error, parts); /* Encoder is AFTER the constructor skip. */
    arm_auth = true;
    CHECK(detector->scan(detector, &ctx, true, data, &results, &error) == -1 && error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); products_and_verification(detector);
    shared_setup_errors(detector); own_resources(detector);
    return test_finish("Duply");
}
