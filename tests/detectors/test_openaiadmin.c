/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_openaiadmin_init(const br_detector **out, char **error);

static char key_a[134], key_b[134];
static size_t fail_finding_after;

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 133 || len == 5);
    if (fail_finding_after && --fail_finding_after == 0) return NULL;
    char copy[134];
    memcpy(copy, value, (size_t)len);
    copy[len] = '\0';
    return json_object_new_string(copy);
}

static void make_key(char out[134], char left, char right)
{
    memcpy(out, "sk-admin-", 9);
    memset(out + 9, left, 58);
    memcpy(out + 67, "T3BlbkFJ", 8);
    memset(out + 75, right, 58);
    out[133] = '\0';
}

static void check_result(const br_result *result, const char *expected, bool verified, const char *cause)
{
    char redacted[19];
    memcpy(redacted, expected, 11);
    memcpy(redacted + 11, "...", 3);
    memcpy(redacted + 14, expected + 129, 4);
    redacted[18] = '\0';
    CHECK(result->detector_type == 1040);
    CHECK(result->raw.len == 133 && !memcmp(result->raw.data, expected, 133));
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), expected));
    CHECK(result->verified == verified && !result->verification_from_cache);
    if (cause) {
        CHECK(result->verification_error && !strcmp(result->verification_error, cause));
        CHECK(!strstr(result->verification_error, expected));
    } else CHECK(!result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_line && !result->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    make_key(key_a, 'A', 'B');
    make_key(key_b, 'C', 'D');
    CHECK(strlen(key_a) == 133 && strlen(key_b) == 133);
    CHECK(br_openaiadmin_init(NULL, &error) == -1 && error && !strcmp(error, "invalid OpenAIAdmin detector output"));
    free(error);
    error = NULL;
    CHECK(!br_openaiadmin_init(&detector, &error) && detector && !error);
    CHECK(!br_openaiadmin_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1040 && detector->version == 0 && !strcmp(detector->name, "OpenAIAdmin"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "OpenAI Admin API keys provide administrative access to OpenAI organization resources. These keys can be used to manage API keys, audit logs, and other organization-level settings."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "sk-admin-"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void expect_one(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (expected ? 1u : 0u));
    if (expected) check_result(&results.items[0], expected, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[512], changed[134];
    snprintf(input, sizeof(input), "admin %s", key_a);
    expect_one(detector, input, key_a); /* Pattern is unprefixed; keyword is engine metadata. */
    expect_one(detector, key_a, key_a);
    snprintf(input, sizeof(input), "%s\n%s\n%s", key_a, key_b, key_a);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key_a, false, NULL);
    check_result(&results.items[1], key_b, false, NULL);
    br_results_clear(&results);
    memcpy(changed, key_a, 134);
    changed[67] = 't';
    snprintf(input, sizeof(input), "x %s", changed);
    expect_one(detector, input, NULL); /* T3BlbkFJ is case-sensitive. */
    memcpy(changed, key_a, 134);
    changed[9] = '-';
    snprintf(input, sizeof(input), " %s ", changed);
    expect_one(detector, input, changed); /* Hyphen is inside the class and is a boundary. */
    memcpy(changed, key_a, 134);
    changed[132] = '_';
    snprintf(input, sizeof(input), " %s ", changed);
    expect_one(detector, input, changed);
    snprintf(input, sizeof(input), "x%s", key_a);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "%sZ", key_a);
    expect_one(detector, input, NULL);
    snprintf(input, sizeof(input), "sk-proj-%s", key_a + 9);
    expect_one(detector, input, NULL);
    memcpy(changed, key_a, 134);
    changed[20] = '+';
    snprintf(input, sizeof(input), " %s ", changed);
    expect_one(detector, input, NULL);
}

typedef struct { const char *key, *send_error, *body; int status, send_rc; } reply;
typedef struct { reply rows[3]; size_t count; const br_scan_ctx *expected_ctx; } script;

static const char *header_value(const br_http_request *request, const char *name)
{
    const char *found = NULL;
    size_t n = 0;
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcmp(request->headers[i].name, name)) { found = request->headers[i].value; ++n; }
    CHECK(n == 1 && found);
    return found;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->rows[at];
    CHECK(request->detector_type == 1040 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.openai.com/v1/organization/admin_api_keys"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strcmp(header_value(request, "Authorization") + 7, step->key));
    CHECK(!strncmp(header_value(request, "Authorization"), "Bearer ", 7));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, "TruffleHog"));
    static const unsigned char ignored[] = "not-json";
    http->response = (br_http_response){.status = step->status, .body = {ignored, sizeof(ignored) - 1}, .body_error = step->body};
    http->send_error = step->send_error;
    http->send_rc = step->send_error ? -1 : step->send_rc;
}

static br_results run(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->count);
    return results;
}

static void verification(const br_detector *detector)
{
    char input[420];
    snprintf(input, sizeof(input), "%s %s %s", key_a, key_b, key_a);
    script none = {0};
    br_results results = run(detector, input, false, &none);
    CHECK(results.len == 2 && none.count == 0);
    check_result(&results.items[0], key_a, false, NULL);
    check_result(&results.items[1], key_b, false, NULL);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 2);
    check_result(&results.items[0], key_a, false, "net/http: nil Context");
    check_result(&results.items[1], key_b, false, "net/http: nil Context");
    br_results_clear(&results);
    const int codes[] = {199, 200, 201, 401, 403, 500};
    snprintf(input, sizeof(input), "token=%s", key_a);
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (reply){.key = key_a, .status = codes[i], .body = "ignored read"};
        results = run(detector, input, true, &steps);
        CHECK(results.len == 1);
        char cause[80];
        const char *expected = NULL;
        if (codes[i] != 200 && codes[i] != 401) {
            snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", codes[i]);
            expected = cause;
        }
        check_result(&results.items[0], key_a, codes[i] == 200, expected);
        br_results_clear(&results);
    }
    char noisy[180];
    snprintf(noisy, sizeof(noisy), "dial %s: connection refused", key_a);
    script steps = {.count = 1};
    steps.rows[0] = (reply){.key = key_a, .status = 200, .send_error = noisy};
    results = run(detector, input, true, &steps);
    CHECK(results.len == 1);
    check_result(&results.items[0], key_a, false, "dial [REDACTED]: connection refused");
    br_results_clear(&results);
    br_scan_ctx missing = {0};
    results = test_scan(detector, &missing, true, input, strlen(input));
    CHECK(results.len == 1);
    check_result(&results.items[0], key_a, false, "HTTP transport not installed");
    br_results_clear(&results);
    {
        test_http null_diag = {.send_rc = 1};
        br_transport null_transport = test_transport(&null_diag);
        br_scan_ctx null_ctx = {.transport = &null_transport};
        br_results null_out = test_scan(detector, &null_ctx, true, input, strlen(input));
        CHECK(null_out.len >= 1 && !null_out.items[0].verified);
        /* br_http_send supplies this when the mock diagnostic is NULL. */
        CHECK(null_out.items[0].verification_error && !strcmp(null_out.items[0].verification_error, "HTTP transport failed"));
        CHECK(null_diag.calls >= 1);
        br_results_clear(&null_out);
    }
}

static void resource_boundary(const br_detector *detector)
{
    char input[300];
    snprintf(input, sizeof(input), "%s\n%s", key_a, key_b);
    script steps = {.count = 2};
    steps.rows[0] = (reply){.key = key_a, .status = 200};
    steps.rows[1] = (reply){.key = key_b, .status = 200};
    for (int nil_ctx = 0; nil_ctx < 2; ++nil_ctx) {
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        steps.expected_ctx = &ctx;
        br_results results = {0};
        br_result prior = {0};
        CHECK(!br_finding_key(&prior, 777, "prior", "key"));
        prior.verified = true;
        prior.verification_error = strdup("caller-owned");
        CHECK(prior.verification_error && !br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data;
        char *saved_error = results.items[0].verification_error, *error = NULL;
        fail_finding_after = 2;
        int rc = detector->scan(detector, nil_ctx ? NULL : &ctx, true,
                                (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
        CHECK(rc == -1 && !fail_finding_after && error && !strcmp(error, "cannot create OpenAIAdmin result"));
        CHECK(http.calls == (nil_ctx ? 0u : 1u) && http.releases == http.calls);
        CHECK(results.len == 1 && results.items[0].raw.data == saved && !strcmp(saved_error, "caller-owned"));
        CHECK(results.items[0].detector_type == 777 && results.items[0].verified);
        free(error);
        br_results_clear(&results);
    }
    br_results results = run(detector, input, true, &steps);
    CHECK(results.len == 2);
    check_result(&results.items[0], key_a, true, NULL);
    check_result(&results.items[1], key_b, true, NULL);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    resource_boundary(detector);
    return test_finish("OpenAIAdmin unique admin grammar + redacted bearer + status setter");
}
