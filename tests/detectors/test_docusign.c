/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char id[] = "01234567-89ab-cdef-0123-456789abcdef";
static const char other[] = "fedcba98-7654-3210-fedc-ba9876543210";
static const char secret[] = "11111111-2222-3333-4444-555555555555";
static const char endpoint[] = "https://account-d.docusign.com/oauth/token?grant_type=client_credentials";
static size_t fail_size, fail_after, fail_secret_after;
static bool arm_redacted, arm_auth;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "secret") && fail_secret_after && --fail_secret_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (rc == 0 && !strcmp(name, "secret") && (arm_redacted || arm_auth)) {
        fail_size = arm_redacted ? 37 : 107; fail_after = 1;
        arm_redacted = arm_auth = false;
    }
    return rc;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(id) == 36 && strlen(secret) == 36);
    CHECK(br_docusign_init(NULL, &error) == -1 && error); free(error); error = NULL;
    fail_size = sizeof("(?i:integration|id)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_docusign_init(&detector, &error) == -1 && !detector && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_docusign_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_docusign_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 919 && detector->version == 0 && !strcmp(detector->name, "Docusign"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Docusign is an electronic signature and digital transaction management service. Docusign credentials can be used to access and manage digital transactions and documents."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "docusign"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint); return detector;
}

static void check_result(const br_result *result, const char *expected_id, const char *expected_secret, bool verified)
{
    CHECK(result->detector_type == 919 && result->raw.len == 36 && !memcmp(result->raw.data, expected_id, 36));
    CHECK(result->raw_v2.len == 72 && !memcmp(result->raw_v2.data, expected_id, 36) && !memcmp(result->raw_v2.data + 36, expected_secret, 36));
    CHECK(result->redacted && strlen(result->redacted) == 36 && !strcmp(result->redacted, expected_id));
    CHECK(result->verified == verified && !result->verification_error && !result->verification_from_cache);
    CHECK(!result->detector_name && !result->extra_data && !result->structured_data);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &part) && !strcmp(json_object_get_string(part), expected_id));
    CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), expected_secret));
}

static void pair_input(char *out, size_t size, const char *value_id, const char *value_secret)
{
    CHECK(snprintf(out, size, "integration %s%50ssecret %s", value_id, "", value_secret) > 0);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected_id, const char *expected_secret)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == (expected_id && expected_secret ? 1u : 0u) && !http.calls && !http.releases);
    if (results.len) check_result(&results.items[0], expected_id, expected_secret, false);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[320], changed[38];
    pair_input(input, sizeof(input), id, secret); extraction_case(detector, input, id, secret);
    snprintf(input, sizeof(input), "ID\r\n%s%50sSeCrEt:%s", id, "", secret); extraction_case(detector, input, id, secret);
    snprintf(input, sizeof(input), "secret invalid %s", id); extraction_case(detector, input, id, id); /* Prefix fragment and self-pair. */
    snprintf(input, sizeof(input), "integration %s", id); extraction_case(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "secret %s", secret); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, id, sizeof(id)); changed[9] = 'A'; pair_input(input, sizeof(input), changed, secret); extraction_case(detector, input, NULL, NULL);
    memcpy(changed, secret, sizeof(secret)); changed[0] = 'g'; pair_input(input, sizeof(input), id, changed); extraction_case(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "id _%s%50ssecret %s", id, "", secret); extraction_case(detector, input, NULL, NULL);
    snprintf(input, sizeof(input), "id %s_%50ssecret %s", id, "", secret); extraction_case(detector, input, NULL, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "id%*s%s%50ssecret %s", (int)gap, "", id, "", secret);
        extraction_case(detector, input, gap == 40 ? id : NULL, gap == 40 ? secret : NULL);
        snprintf(input, sizeof(input), "id %s%50ssecret%*s%s", id, "", (int)gap, "", secret);
        extraction_case(detector, input, gap == 40 ? id : NULL, gap == 40 ? secret : NULL);
    }
    char far[1400]; int n = snprintf(far, sizeof(far), "id %s", id); CHECK(n > 0);
    memset(far + n, '.', 1100); snprintf(far + n + 1100, sizeof(far) - (size_t)n - 1100, "secret %s", secret);
    extraction_case(detector, far, id, secret); /* No local span filter. */
}

typedef struct {
    const char *id, *secret, *send_error, *body_error;
    br_slice body;
    int status, send_rc;
    bool poison_send, poison_read;
} reply;
typedef struct {
    const reply *rows;
    size_t count;
    const br_scan_ctx *expected_ctx;
    const char *borrowed_auth;
    char expected_auth[107];
    char *send_cause;
} script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->expected_ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    CHECK(request->detector_type == 919 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, endpoint));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept"));
    CHECK(!strcmp(request->headers[0].value, "application/vnd.docusign+json; version=3"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && strlen(request->headers[1].value) == 106);
    char *basic = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)row->id, 36}, (br_slice){(const unsigned char *)row->secret, 36}, &basic, &error) == 0 && !error);
    CHECK(strlen(basic + 6) == 100); memcpy(steps->expected_auth, basic, 107); free(basic);
    CHECK(!memcmp(request->headers[1].value, steps->expected_auth, 107));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog docusign-offline"));
    steps->borrowed_auth = request->headers[1].value;
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = row->body_error};
    http->send_rc = row->send_rc; http->send_error = row->send_error;
}

static int injected_send(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    test_http *http = user; script *steps = http->user;
    int rc = test_http_send(user, ctx, request, response, error); steps->send_cause = *error; return rc;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; const reply *row = &steps->rows[http->calls - 1];
    CHECK(steps->borrowed_auth && !memcmp(steps->borrowed_auth, steps->expected_auth, 107));
    if (row->poison_send && steps->send_cause) memset(steps->send_cause, '!', strlen(steps->send_cause));
    if (row->poison_read) memset((char *)row->body_error, '!', strlen(row->body_error));
    steps->borrowed_auth = NULL; steps->send_cause = NULL; test_http_release(user, response);
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps}; br_transport transport = {&http, injected_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "docusign-offline"}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count && !steps->borrowed_auth); return results;
}

static void products(const br_detector *detector)
{
    const char *ids[] = {id, other, id}, *secrets[] = {secret, id, secret};
    char input[800]; snprintf(input, sizeof(input), "integration %s%50sid %s%50sintegration %s%50ssecret %s%50sSECRET %s%50ssecret %s",
        id, "", other, "", id, "", secret, "", id, "", secret);
    const int statuses[] = {200, 201, 204, 401, 500, 299, 403, 200, 300}; reply rows[9];
    for (size_t i = 0; i < 9; ++i) rows[i] = (reply){.id = ids[i / 3], .secret = secrets[i % 3], .status = statuses[i],
        .body = {(const unsigned char *)"not-json ey\r\n", 13}, .body_error = "ignored after matching line"};
    for (int verify = 0; verify < 2; ++verify) {
        script steps = {.rows = rows, .count = verify ? 9u : 0u}; br_results results = run(detector, input, verify, &steps); CHECK(results.len == 9);
        for (size_t i = 0; i < 9; ++i) check_result(&results.items[i], ids[i / 3], secrets[i % 3], verify && statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&results);
        results = test_scan(detector, NULL, verify, input, strlen(input)); CHECK(results.len == (verify ? 0u : 9u));
        if (verify) CHECK(!results.items && !results.cap);
        for (size_t i = 0; i < results.len; ++i) check_result(&results.items[i], ids[i / 3], secrets[i % 3], false);
        br_results_clear(&results);
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

static void body_case(const br_detector *detector, br_slice body, const char *read_error,
                      int status, bool verified, const char *fatal, bool poison)
{
    char input[160]; pair_input(input, sizeof(input), id, secret);
    reply row = {.id = id, .secret = secret, .status = status, .body = body, .body_error = read_error, .poison_read = poison};
    script steps = {.rows = &row, .count = 1}; test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, injected_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "docusign-offline"}; steps.expected_ctx = &ctx;
    br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
    char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(http.calls == 1 && http.releases == 1 && !steps.borrowed_auth);
    if (fatal) { CHECK(rc == -1 && error && !strcmp(error, fatal)); check_prior(&results, raw, prior_error, parts); }
    else { CHECK(rc == 0 && !error && results.len == 2); check_result(&results.items[1], id, secret, verified); }
    free(error); br_results_clear(&results);
}

static void reader_contract(const br_detector *detector)
{
    body_case(detector, (br_slice){(const unsigned char *)"no marker", 9}, NULL, 500, false, NULL, false);
    body_case(detector, (br_slice){(const unsigned char *)"key\r\n", 5}, "late error", 200, true, NULL, false);
    body_case(detector, (br_slice){(const unsigned char *)"ey", 2}, "late error", 401, false, NULL, false);
    body_case(detector, (br_slice){(const unsigned char *)"ey", 2}, "late error", 200, true, NULL, false);
    body_case(detector, (br_slice){(const unsigned char *)"e\ry", 3}, NULL, 200, false, NULL, false);
    body_case(detector, (br_slice){(const unsigned char *)"ey\r\r", 4}, NULL, 200, true, NULL, false);
    static const unsigned char binary[] = {0, 'e', 'y', '\n'};
    body_case(detector, (br_slice){binary, sizeof(binary)}, NULL, 200, true, NULL, false);
    body_case(detector, (br_slice){0}, "", 200, false, "", false);
    char leaf[160], expected[160]; snprintf(leaf, sizeof(leaf), "reader %s:%s", id, secret); strcpy(expected, leaf);
    body_case(detector, (br_slice){(const unsigned char *)"none\n", 5}, leaf, 401, false, expected, true);
    unsigned char *large = malloc(65540); CHECK(large); memset(large, 'x', 65540); large[0] = 'e'; large[1] = 'y';
    body_case(detector, (br_slice){large, 65535}, "late", 200, true, NULL, false);
    static const char shape[] = "unsupported: Docusign Scanner read shape for a 65536-byte final line";
    body_case(detector, (br_slice){large, 65536}, NULL, 200, false, shape, false);
    large[0] = large[1] = 'x'; body_case(detector, (br_slice){large, 65536}, "late", 401, false, shape, false);
    large[0] = 'e'; large[1] = 'y'; large[65535] = '\n';
    body_case(detector, (br_slice){large, 65536}, "late", 200, true, NULL, false);
    large[65534] = '\r'; body_case(detector, (br_slice){large, 65536}, NULL, 200, true, NULL, false);
    memset(large, 'x', 65540); large[65536] = '\n'; large[65537] = 'e'; large[65538] = 'y'; large[65539] = '\n';
    body_case(detector, (br_slice){large, 65540}, NULL, 500, false, "bufio.Scanner: token too long", false);
    memset(large, 'x', 65540); large[0] = 'e'; large[1] = 'y';
    body_case(detector, (br_slice){large, 65537}, NULL, 401, false, "bufio.Scanner: token too long", false);
    large[2] = '\n'; body_case(detector, (br_slice){large, 65540}, "late error", 200, true, NULL, false);
    free(large);
}

static bool cancelled(void *user) { (void)user; return true; }
static bool fail_headers(void *user)
{
    (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false;
}

static void fatal_send_and_rollback(const br_detector *detector)
{
    char input[256], leaf[200], expected[256];
    snprintf(input, sizeof(input), "id %s%50ssecret %s%50ssecret %s", id, "", secret, "", other);
    snprintf(leaf, sizeof(leaf), "Error making request: literal %s:%s", id, other);
    snprintf(expected, sizeof(expected), "Error making request: %s", leaf);
    reply rows[] = {{.id = id, .secret = secret, .status = 200, .body = {(const unsigned char *)"ey\n", 3}},
                    {.id = id, .secret = other, .status = 200, .send_rc = -7, .send_error = leaf, .poison_send = true, .body_error = "must not replace send cause"}};
    script steps = {.rows = rows, .count = 2}; test_http http = {.inspect = inspect_request, .user = &steps};
    br_transport transport = {&http, injected_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "docusign-offline"}; steps.expected_ctx = &ctx;
    br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
    char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error && !strcmp(error, expected));
    CHECK(http.calls == 2 && http.releases == 2); check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
    pair_input(input, sizeof(input), id, secret);
    const char *causes[] = {"Error making request: HTTP transport not installed", "Error making request: context canceled", "Error making request: out of memory constructing HTTP headers"};
    for (int mode = 0; mode < 3; ++mode) {
        test_http setup = {0}; br_transport fake = test_transport(&setup);
        br_scan_ctx context = {.transport = mode ? &fake : NULL, .cancelled = mode == 1 ? cancelled : mode == 2 ? fail_headers : NULL};
        results = prior_result(); raw = results.items[0].raw.data; prior_error = results.items[0].verification_error; parts = results.items[0].secret_parts; error = NULL;
        CHECK(detector->scan(detector, &context, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error && !strcmp(error, causes[mode]));
        CHECK(!setup.calls && setup.releases == (mode ? 1u : 0u) && !fail_after); check_prior(&results, raw, prior_error, parts);
        free(error); br_results_clear(&results);
    }
}

static void own_resources(const br_detector *detector)
{
    char input[256]; snprintf(input, sizeof(input), "id %s%50ssecret %s%50ssecret %s", id, "", secret, "", other);
    br_scan_ctx ctx = {0}; br_results results = prior_result(); unsigned char *raw = results.items[0].raw.data;
    char *prior_error = results.items[0].verification_error; br_json *parts = results.items[0].secret_parts; char *error = NULL;
    fail_secret_after = 2;
    CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error && !strcmp(error, "cannot create Docusign result") && !fail_secret_after);
    check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
    pair_input(input, sizeof(input), id, secret);
    arm_redacted = true;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error && !strcmp(error, "cannot create Docusign Redacted") && !arm_redacted && !fail_after);
    check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
    arm_auth = true;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == 0 && !error && !arm_auth && fail_after == 1);
    fail_after = 0; check_prior(&results, raw, prior_error, parts); /* Basic helper is AFTER constructor skip. */
    arm_auth = true;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
    fail_size = 2 * sizeof(br_span); fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error && !strcmp(error, "out of memory iterating regex") && !fail_after);
    check_prior(&results, raw, prior_error, parts); free(error); error = NULL;
    size_t cap = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) == -1 && error && !strcmp(error, "cannot append Docusign result"));
    results.cap = cap; check_prior(&results, raw, prior_error, parts); free(error); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor(); extraction(detector); products(detector); reader_contract(detector);
    fatal_send_and_rollback(detector); own_resources(detector);
    return test_finish("Docusign");
}
