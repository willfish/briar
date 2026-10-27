/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[65], other[65], case_key[65];
static size_t fail_size, fail_after, allocation_failures, fail_part_after;

/* Fail real shared resources, not an invented auth/header allocation. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) {
        ++allocation_failures; return NULL;
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
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 64 && strlen(other) == 64 && strlen(case_key) == 64);
    CHECK(br_digitaloceantoken_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:ocean|do)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_digitaloceantoken_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_digitaloceantoken_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_digitaloceantoken_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 64 && detector->version == 0 && !strcmp(detector->name, "DigitalOceanToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DigitalOcean is a cloud infrastructure provider offering cloud services to help deploy, manage, and scale applications. DigitalOcean tokens can be used to access and manage these services."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "digitalocean"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *error)
{
    test_key_result(result, 64, expected, "key");
    CHECK(result->raw.len == 64 && result->verified == verified);
    CHECK(error ? result->verification_error && !strcmp(result->verification_error, error) : !result->verification_error);
}

static const br_result *find_result(const br_results *results, const char *token)
{
    const br_result *found = NULL;
    for (size_t i = 0; i < results->len; ++i) {
        if (results->items[i].raw.len == 64 && !memcmp(results->items[i].raw.data, token, 64)) {
            CHECK(!found); found = &results->items[i];
        }
    }
    CHECK(found); return found;
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, len);
    CHECK(results.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[66];
    const char *accepted[] = {"ocean = '%s'", "OCEAN\r\n%s", "do %s", "DO\r%s", "digitalocean:%s", "condor:%s", "ocean-%s-"};
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        snprintf(input, sizeof(input), accepted[i], key); extraction_case(detector, input, strlen(input), key);
    }
    const char *rejected[] = {"%s", "%s ocean", "oc ean %s", "ocean%s", "ocean _%s", "ocean %s_", "ocean X%s", "ocean %s9"};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        snprintf(input, sizeof(input), rejected[i], key); extraction_case(detector, input, strlen(input), NULL);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "do%*s%s", (int)gap, "", key);
        extraction_case(detector, input, strlen(input), gap == 40 ? key : NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[63] = '\0';
    snprintf(input, sizeof(input), "ocean %s", changed); extraction_case(detector, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[64] = 'a'; changed[65] = '\0';
    snprintf(input, sizeof(input), "ocean %s", changed); extraction_case(detector, input, strlen(input), NULL);
    const char invalid[] = ".:/+=";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[32] = invalid[i];
        snprintf(input, sizeof(input), "do %s", changed); extraction_case(detector, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[0] = changed[63] = '_';
    snprintf(input, sizeof(input), "do %s", changed); extraction_case(detector, input, strlen(input), changed);
    changed[0] = '-'; changed[63] = key[63];
    snprintf(input, sizeof(input), "do %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "do%s", changed); extraction_case(detector, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[63] = '-';
    snprintf(input, sizeof(input), "ocean %s", changed); extraction_case(detector, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "ocean %sX", changed); extraction_case(detector, input, strlen(input), changed);
    memset(changed, '_', 64); changed[64] = '\0';
    snprintf(input, sizeof(input), "do %s", changed); extraction_case(detector, input, strlen(input), changed); /* No local entropy/FP filter. */
    snprintf(input, sizeof(input), "ocean %s %s", key, other); extraction_case(detector, input, strlen(input), key);
    int n = snprintf(input, sizeof(input), "do%c%s", 0, key);
    CHECK(n == 67); extraction_case(detector, input, (size_t)n, key);
    n = snprintf(input, sizeof(input), "%cdo %s%c", 0xff, key, 0xff);
    CHECK(n == 69); extraction_case(detector, input, (size_t)n, key);
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *key, *send_error; int status, send_rc; bool nil_body; } reply;
typedef struct {
    const reply *rows;
    size_t count, seen;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_auth, *agent_suffix;
    char expected_auth[72];
    size_t fault_call, fault_size, failures_before;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(http->calls <= steps->count && ctx == steps->expected_ctx && http->releases == http->calls - 1);
    CHECK(request->detector_type == 64 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.digitalocean.com/v2/account"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    const char *auth = request->headers[0].value;
    CHECK(strlen(auth) == 71 && !memcmp(auth, "Bearer ", 7));
    size_t row = 0;
    while (row < steps->count && strcmp(auth + 7, steps->rows[row].key)) ++row;
    CHECK(row < steps->count && row < sizeof(size_t) * 8 && !(steps->seen & ((size_t)1 << row)));
    steps->seen |= (size_t)1 << row;
    const reply *step = &steps->rows[row];
    memcpy(steps->expected_auth, "Bearer ", 7); memcpy(steps->expected_auth + 7, step->key, 65);
    CHECK(!memcmp(auth, steps->expected_auth, 72));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, steps->agent_suffix ? "TruffleHog digitaloceantoken-offline" : "TruffleHog"));
    /* Exact header count excludes Type, Accept and invented logical CL. */
    steps->borrowed_auth = auth;
    static const unsigned char body[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = step->status,
        .body = step->nil_body ? (br_slice){0} : (br_slice){body, sizeof(body)},
        .body_error = step->nil_body ? "" : "synthetic ignored read error"};
    http->send_rc = step->send_rc; http->send_error = step->send_error;
    if (http->calls == steps->fault_call) {
        fail_size = steps->fault_size; fail_after = 2; steps->failures_before = allocation_failures;
        /* First duplicate is the fake's owned error, second is the real setter. */
    }
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, steps->expected_auth, 72));
    if (http->calls == steps->fault_call)
        CHECK(!fail_after && allocation_failures == steps->failures_before + 1); /* Setter before release. */
    steps->borrowed_auth = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->agent_suffix}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth);
    CHECK(steps->seen == ((size_t)1 << steps->count) - 1); return results;
}

static void unique_tokens_and_statuses(const br_detector *detector)
{
    char input[384]; snprintf(input, sizeof(input), "ocean %s\ndo %s\nDO %s\nDIGITALOCEAN %s", key, other, key, case_key);
    reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 401, .nil_body = true}, {.key = case_key, .status = 403}};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 3u : 0u, .agent_suffix = "digitaloceantoken-offline"};
        br_results results = run(detector, input, verify, &steps); CHECK(results.len == 3);
        check_result(find_result(&results, key), key, verify, NULL);
        check_result(find_result(&results, other), other, false, NULL);
        check_result(find_result(&results, case_key), case_key, false, verify ? "unexpected status code: 403" : NULL);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == 3);
        const char *tokens[] = {key, other, case_key};
        for (size_t i = 0; i < 3; ++i) check_result(find_result(&results, tokens[i]), tokens[i], false, verify ? "net/http: nil Context" : NULL);
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "do %s", key);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 403, 429, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = key, .status = statuses[i], .nil_body = i % 2 == 0}; script steps = {.rows = &row, .count = 1}; char expected[64];
        snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false;
}

static void leaf_causes_and_setup_errors(const br_detector *detector)
{
    char input[96], echo[256]; snprintf(input, sizeof(input), "do %s", key);
    snprintf(echo, sizeof(echo), "synthetic %s echo %s; other %s", key, key, other);
    const char *causes[] = {"context deadline exceeded", "failed to make request: literal leaf", "failed to create request: literal leaf", "cannot create DigitalOceanToken result", echo, "", NULL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        reply row = {.key = key, .status = 200, .send_rc = i % 2 ? -7 : 1, .send_error = causes[i]}; script steps = {.rows = &row, .count = 1};
        br_results results = run(detector, input, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], key, false, causes[i] ? causes[i] : "HTTP transport failed");
        if (causes[i] == echo) CHECK(strstr(results.items[0].verification_error, key) && !strstr(results.items[0].verification_error, "[REDACTED]"));
        br_results_clear(&results);
    }
    const char *setup[] = {"HTTP transport not installed", "context canceled", "out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 3; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        size_t before = allocation_failures; br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(results.len == 1 && !http.calls && http.releases == (mode == 0 ? 0u : 1u));
        CHECK(!fail_after && allocation_failures == before + (mode == 2 ? 1u : 0u));
        check_result(&results.items[0], key, false, setup[mode]); br_results_clear(&results);
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

static void resource_failures(const br_detector *detector)
{
    char input[192]; snprintf(input, sizeof(input), "do %s\nocean %s", key, other); br_slice data = {(const unsigned char *)input, strlen(input)};
    for (int mode = 0; mode < 3; ++mode) {
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
        reply rows[] = {{.key = key, .status = 200}, {.key = other, .status = 200}}; script steps = {.rows = rows, .count = 2};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        fail_part_after = 2; /* One finding already appended, including with nil context. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot create DigitalOceanToken result") && !fail_part_after);
        CHECK(http.calls == (mode == 1 ? 1u : 0u) && http.releases == http.calls && !steps.borrowed_auth);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        fail_size = 2 * sizeof(br_span); fail_after = 1; /* Actual positive +1 regex resource failure. */
        CHECK(detector->scan(detector, mode == 2 ? NULL : &ctx, mode != 0, data, &results, &error) == -1);
        CHECK(error && !strcmp(error, "out of memory iterating regex") && !fail_after);
        check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
        size_t cap = results.cap; results.cap = 0; /* Actual positive +1 append-guard failure. */
        CHECK(detector->scan(detector, &ctx, false, data, &results, &error) == -1 && error && !strcmp(error, "cannot append DigitalOceanToken result"));
        results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

static void setter_failures(const br_detector *detector)
{
    static const char probe_cause[] = "synthetic leaf copy boundary";
    br_result probe = {0}; fail_size = sizeof(probe_cause); fail_after = 1;
    CHECK(br_result_set_verification_error(&probe, probe_cause, NULL, 0) == 1 && !fail_after && !probe.verification_error); br_result_clear(&probe);
    char input[192], cause[256]; snprintf(input, sizeof(input), "do %s\nocean %s", key, other);
    snprintf(cause, sizeof(cause), "synthetic %s echo %s", key, other);
    for (int nil_context = 0; nil_context < 2; ++nil_context) {
        reply rows[] = {{.key = key, .status = 200, .send_rc = 1, .send_error = cause}, {.key = other, .status = 200, .send_rc = -1, .send_error = cause}};
        script steps = {.rows = rows, .count = 2, .fault_call = 2, .fault_size = strlen(cause) + 1};
        test_http http = {.inspect = inspect_request, .user = &steps}; br_transport transport = {&http, test_http_send, release_response};
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
        char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
        if (nil_context) { fail_size = sizeof("net/http: nil Context"); fail_after = 2; }
        CHECK(detector->scan(detector, nil_context ? NULL : &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1);
        CHECK(error && !strcmp(error, "cannot store DigitalOceanToken verification error") && !fail_after);
        CHECK(http.calls == (nil_context ? 0u : 2u) && http.releases == http.calls && !steps.borrowed_auth);
        check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    }
}

int main(void)
{
    test_secret(key, 64, 0); test_secret(other, 64, 11);
    key[0] = 'G'; key[17] = '_'; key[31] = '-'; key[53] = 'Z'; other[7] = '_'; other[29] = '-'; other[61] = 'W';
    memcpy(case_key, key, sizeof(key)); case_key[0] = 'g';
    const br_detector *detector = descriptor(); extraction(detector); unique_tokens_and_statuses(detector);
    leaf_causes_and_setup_errors(detector); resource_failures(detector); setter_failures(detector);
    return test_finish("DigitalOceanToken");
}
