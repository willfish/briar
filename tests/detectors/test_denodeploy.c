/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char token[] = "ddp_G7h9J2k5M6n8P3q4R1s0T2u5V7w9X2y4Z6a8";
static const char other[] = "ddw_z9Y8x7W6v5U4t3S2r1Q0p9N8m7K6j5H4g3F2";
static size_t fail_size, fail_after, allocation_failures, fail_add_after;

/* Real native allocation/metadata boundaries, not production failure APIs. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}

char *strdup(const char *text)
{
    size_t size = strlen(text) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(token) == 40 && strlen(other) == 40);
    CHECK(br_denodeploy_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_denodeploy_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_denodeploy_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 954 && detector->version == 0 && !strcmp(detector->name, "DenoDeploy"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "DenoDeploy is a cloud service for deploying JavaScript and TypeScript applications. DenoDeploy tokens can be used to access and manage these deployments."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "ddp_") && !strcmp(detector->keywords[1], "ddw_"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void result(const br_result *value, const char *expected, bool verified, const char *error, br_slice login)
{
    CHECK(value->detector_type == 954 && !value->detector_name);
    CHECK(value->raw.len == 40 && !memcmp(value->raw.data, expected, 40));
    CHECK(!value->raw_v2.data && !value->raw_v2.len && !value->redacted && !value->structured_data);
    CHECK(value->secret_parts && json_object_object_length(value->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(value->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 40 && !memcmp(json_object_get_string(part), expected, 40));
    CHECK(value->verified == verified && !value->verification_from_cache);
    CHECK((value->verification_error != NULL) == (error != NULL));
    if (error) CHECK(!strcmp(value->verification_error, error));
    CHECK(!value->primary_secret.data && !value->primary_secret.len && !value->primary_line);
    CHECK(!value->chunk_offset && !value->chunk_offset_set);
    if (!login.data) CHECK(!value->extra_data);
    else {
        CHECK(value->extra_data && json_object_object_length(value->extra_data) == 1);
        CHECK(json_object_object_get_ex(value->extra_data, "login", &part) && json_object_is_type(part, json_type_string));
        CHECK((size_t)json_object_get_string_len(part) == login.len);
        CHECK(!login.len || !memcmp(json_object_get_string(part), login.data, login.len));
    }
}

static void extraction_case(const br_detector *detector, const void *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) result(&out.items[0], expected, false, NULL, (br_slice){0});
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    char input[192], changed[42];
    extraction_case(detector, token, 40, token); extraction_case(detector, other, 40, other);
    const char *accepted[] = {"'%s'", "(%s)\r\n", "-%s-", "without-provider-%s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), accepted[i], token); extraction_case(detector, input, strlen(input), token); }
    const char *rejected[] = {"_%s", "%s_", "x%s", "%s9", "%.39s", "%sA"};
    for (size_t i = 0; i < 6; ++i) { snprintf(input, sizeof(input), rejected[i], token); extraction_case(detector, input, strlen(input), NULL); }
    const char *bad_prefixes[] = {"DDP_", "ddP_", "ddq_", "ddW_"};
    for (size_t i = 0; i < 4; ++i) { memcpy(changed, token, sizeof(token)); memcpy(changed, bad_prefixes[i], 4); extraction_case(detector, changed, 40, NULL); }
    const char invalid[] = "_-./+";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) { memcpy(changed, token, sizeof(token)); changed[20] = invalid[i]; extraction_case(detector, changed, 40, NULL); }
    memcpy(changed, "ddp_", 4); memset(changed + 4, 'A', 36); changed[40] = '\0';
    extraction_case(detector, changed, 40, changed); /* No entropy/JWT/filter requirement. */
    memset(input, '.', 100); memcpy(input + 100, token, 40);
    extraction_case(detector, input, 140, token); /* Direct regex, no PrefixRegex gap. */
    input[0] = '\0'; memcpy(input + 1, token, 40); input[41] = (char)0xff;
    extraction_case(detector, input, 42, token); /* No global input UTF-8 guard. */
    extraction_case(detector, NULL, 0, NULL);
}

typedef struct { const char *token, *send_error, *read_error; int status, rc; br_slice body; } reply;
typedef struct {
    reply rows[3]; size_t count;
    const br_scan_ctx *ctx;
    const char *borrowed_auth;
    char *read_storage[3];
    bool suffix;
    size_t arm_size, arm_after, arm_call;
} script;

static void authorization(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 47 && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, expected, 41));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    reply *row = &steps->rows[at];
    CHECK(request->detector_type == 954 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.deno.com/user"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, row->token); steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog deno-offline" : "TruffleHog"));
    if (row->read_error) { steps->read_storage[at] = strdup(row->read_error); CHECK(steps->read_storage[at]); }
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = steps->read_storage[at]};
    http->send_rc = row->rc; http->send_error = row->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error);
    test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; size_t at = http->calls - 1;
    authorization(steps->borrowed_auth, steps->rows[at].token); steps->borrowed_auth = NULL;
    /* Safely invalidate borrowed error bytes while keeping storage allocated
     * until invoke returns. The result must already own its sanitized copy. */
    if (steps->read_storage[at]) memset(steps->read_storage[at], '!', strlen(steps->read_storage[at]));
    test_http_release(user, response);
}

static int invoke(const br_detector *detector, br_slice input, bool verify, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "deno-offline" : NULL}; steps->ctx = &ctx;
    int rc = detector->scan(detector, &ctx, verify, input, out, error);
    CHECK(http.calls == steps->count && http.releases == http.calls && !steps->borrowed_auth);
    for (size_t i = 0; i < 3; ++i) { free(steps->read_storage[i]); steps->read_storage[i] = NULL; }
    return rc;
}

static br_results run(const br_detector *detector, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL;
    int rc = invoke(detector, input, true, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error);
    return out;
}

static void statuses_reads_and_occurrences(const br_detector *detector)
{
    br_slice data = text(token);
    const int statuses[] = {0, 199, 201, 204, 299, 300, 401, 403, 429, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = token, .status = statuses[i], .body = TEXT("\xff"), .read_error = "ignored error"};
        char error[96]; snprintf(error, sizeof(error), "unexpected HTTP response status %d", statuses[i]);
        br_results out = run(detector, data, &steps); CHECK(out.len == 1);
        result(&out.items[0], token, false, statuses[i] == 401 ? NULL : error, (br_slice){0}); br_results_clear(&out);
    }
    char read_error[160]; snprintf(read_error, sizeof(read_error), "read %s twice %s", token, token);
    const char *read_errors[] = {read_error, "", "out of memory reading body"};
    const char *expected[] = {"read [REDACTED] twice [REDACTED]", "", "out of memory reading body"};
    for (size_t i = 0; i < 3; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = token, .status = 200, .body = TEXT("\xff"), .read_error = read_errors[i]};
        br_results out = run(detector, data, &steps); CHECK(out.len == 1);
        result(&out.items[0], token, true, expected[i], (br_slice){0}); br_results_clear(&out);
    }
    const char *send_errors[] = {read_error, "net/http: nil Context", "unsupported upstream panic: DenoDeploy nil request before Header.Set", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < sizeof(send_errors) / sizeof(send_errors[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = token, .status = 200, .body = TEXT("{\"login\":\"unused\"}"), .rc = i % 2 ? -1 : 1, .send_error = send_errors[i]};
        br_results out = run(detector, data, &steps); CHECK(out.len == 1);
        result(&out.items[0], token, false, i == 0 ? expected[0] : send_errors[i] ? send_errors[i] : "HTTP transport failed", (br_slice){0}); br_results_clear(&out);
    }
    unsigned char input[3 * 42 + 1]; size_t len = 0; const char *tokens[] = {token, other, token};
    for (size_t i = 0; i < 3; ++i) { memcpy(input + len, tokens[i], 40); len += 40; input[len++] = '\0'; input[len++] = '\n'; }
    input[len++] = 0xff; data = (br_slice){input, len};
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (reply){.token = token, .status = 401};
    steps.rows[1] = (reply){.token = other, .status = 200, .body = TEXT("{\"login\":\"one\"}")};
    steps.rows[2] = (reply){.token = token, .status = 200, .body = TEXT("null")};
    br_results out = run(detector, data, &steps); CHECK(out.len == 3);
    result(&out.items[0], token, false, NULL, (br_slice){0}); result(&out.items[1], other, true, NULL, TEXT("one")); result(&out.items[2], token, true, NULL, TEXT("")); br_results_clear(&out);
    out = test_scan(detector, NULL, false, data.data, data.len); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], tokens[i], false, NULL, (br_slice){0});
    br_results_clear(&out);
}

static void typed_whole_json(const br_detector *detector)
{
    const struct { const char *json, *error; br_slice login; } cases[] = {
        {"null", NULL, TEXT("")}, {"{}", NULL, TEXT("")}, {"{\"login\":null}", NULL, TEXT("")},
        {"{\"login\":\"dev\"}", NULL, TEXT("dev")},
        {"{\"LOGIN\":\"first\",\"login\":null,\"login\":\"last\",\"LOGIN\":null}", NULL, TEXT("last")},
        {"{\"login\":\"\\u03bb\\u0000\\u2603\"}", NULL, TEXT("\xce\xbb\0\xe2\x98\x83")},
        {"{\"login\":\"\xce\xbb\\u0000\xe2\x98\x83\"}", NULL, TEXT("\xce\xbb\0\xe2\x98\x83")},
        {"{\"\xce\xbb\":\"unused\",\"login\":\"raw\"}", NULL, TEXT("raw")},
        {"{\"unused\":1e10000,\"nested\":{\"login\":false},\"login\":\"good\"}", NULL, TEXT("good")},
        {"{\"unused\":99999999999999999999999999999999999999999999999999999999999999}", NULL, TEXT("")},
        {"{\"login\":\"ok\"}\r\n\t ", NULL, TEXT("ok")},
        {"{\"login\":true}", "json: cannot unmarshal bool into Go struct field userResponse.login of type string", {0}},
        {"{\"login\":17,\"login\":\"later\"}", "json: cannot unmarshal number into Go struct field userResponse.login of type string", {0}},
        {"{\"login\":17,\"login\":false}", "json: cannot unmarshal number into Go struct field userResponse.login of type string", {0}},
        {"{\"login\":{}}", "json: cannot unmarshal object into Go struct field userResponse.login of type string", {0}},
        {"[]", "json: cannot unmarshal array into Go value of type denodeploy.userResponse", {0}},
        {"false", "json: cannot unmarshal bool into Go value of type denodeploy.userResponse", {0}},
        {"", "unexpected end of JSON input", {0}}, {"{", "unexpected end of JSON input", {0}},
        {"{} {}", "invalid character '{' after top-level value", {0}},
        {"{\"login\":\"ignored\"}junk", "invalid character 'j' after top-level value", {0}},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (reply){.token = token, .status = 200, .body = text(cases[i].json)};
        br_results out = run(detector, text(token), &steps); CHECK(out.len == 1);
        result(&out.items[0], token, true, cases[i].error, cases[i].login); br_results_clear(&out);
    }
    char echo[80]; snprintf(echo, sizeof(echo), "{\"login\":\"%s\"}", token);
    script steps = {.count = 1}; steps.rows[0] = (reply){.token = token, .status = 200, .body = text(echo)};
    br_results out = run(detector, text(token), &steps);
    result(&out.items[0], token, true, NULL, text(token)); br_results_clear(&out); /* No broad body/token rewrite. */
}

static void check_prior(const br_results *out, unsigned char *raw, char *error, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == error && !strcmp(error, "caller-owned") && out->items[0].secret_parts == parts);
}

static bool cancelled(void *user) { (void)user; return true; }

static void contexts_and_owned_failures(const br_detector *detector)
{
    br_result prior = {0}; br_results out = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0); prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0); unsigned char *raw = out.items[0].raw.data; char *saved = out.items[0].verification_error; br_json *parts = out.items[0].secret_parts;
    CHECK(detector->scan(detector, NULL, true, text(token), &out, &error) == -1 && error && strstr(error, "unsupported upstream panic"));
    check_prior(&out, raw, saved, parts); free(error); error = NULL;
    fail_size = 40; fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, text(token), &out, &error) == -1 && error && !strcmp(error, "cannot create DenoDeploy result") && !fail_after);
    check_prior(&out, raw, saved, parts); free(error); error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){0}, &out, &error) == 0 && !error); check_prior(&out, raw, saved, parts);
    size_t cap = out.cap; out.cap = 0; script steps = {0};
    CHECK(invoke(detector, text(token), false, &steps, &out, &error) == -1 && error && !strcmp(error, "cannot append DenoDeploy result"));
    out.cap = cap; check_prior(&out, raw, saved, parts); free(error); error = NULL;

    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx contexts[] = {{0}, {.transport = &transport, .cancelled = cancelled}, {.transport = &transport, .deadline_monotonic_ms = 1}};
    const char *causes[] = {"HTTP transport not installed", "context canceled", "context deadline exceeded"};
    for (size_t i = 0; i < 3; ++i) {
        http.calls = http.releases = 0;
        br_results found = test_scan(detector, &contexts[i], true, token, 40);
        CHECK(found.len == 1 && !http.calls && http.releases == (i ? 1u : 0u)); result(&found.items[0], token, false, causes[i], (br_slice){0}); br_results_clear(&found);
    }
    const char huge[] = "{\"unused\":9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999}";
    for (int f = 0; f < 5; ++f) {
        steps = (script){.count = f == 0 ? 0u : 1u};
        steps.rows[0] = (reply){.token = token, .status = 200, .body = TEXT("{\"login\":17}")};
        const char *expected;
        if (f == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; expected = "out of memory iterating regex"; }
        else if (f == 1) { steps.rows[0].body = TEXT("{\"login\":\"good\"}"); fail_add_after = 2; expected = "cannot store DenoDeploy login metadata"; }
        else {
            steps.arm_call = 1; steps.arm_after = 1;
            if (f == 2) { steps.rows[0].rc = 1; steps.rows[0].send_error = "synthetic Do failure"; steps.arm_size = sizeof("synthetic Do failure"); expected = "cannot sanitize DenoDeploy verification error"; }
            else if (f == 3) { steps.arm_size = sizeof("json: cannot unmarshal number into Go struct field userResponse.login of type string"); expected = "cannot project DenoDeploy response"; }
            else { steps.rows[0].body = TEXT(huge); steps.arm_size = sizeof(huge); expected = "cannot decode DenoDeploy response"; }
        }
        CHECK(invoke(detector, text(token), true, &steps, &out, &error) == -1 && error && !strcmp(error, expected));
        CHECK(!fail_after && !fail_add_after); check_prior(&out, raw, saved, parts); free(error); error = NULL;
    }
    char input[96]; int len = snprintf(input, sizeof(input), "%s\n%s", token, other);
    steps = (script){.count = 1}; steps.rows[0] = (reply){.token = token, .status = 200, .body = TEXT("null")}; fail_size = 40; fail_after = 2;
    CHECK(invoke(detector, (br_slice){(const unsigned char *)input, (size_t)len}, true, &steps, &out, &error) == -1 && error && !fail_after);
    check_prior(&out, raw, saved, parts); free(error); error = NULL;
    steps = (script){.count = 1}; steps.rows[0] = (reply){.token = token, .status = 200, .body = TEXT("{\"login\":\"\xff\"}")};
    CHECK(invoke(detector, text(token), true, &steps, &out, &error) == -1 && error && strstr(error, "invalid UTF-8 JSON response"));
    check_prior(&out, raw, saved, parts); free(error); br_results_clear(&out);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); statuses_reads_and_occurrences(detector); typed_whole_json(detector); contexts_and_owned_failures(detector);
    return test_finish("DenoDeploy");
}
