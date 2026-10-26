/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

#define SLICE(text) ((br_slice){(const unsigned char *)(text), sizeof(text) - 1})
#define FIELD_TYPE(field, type) "json: cannot unmarshal " type " into Go struct field user." field " of type string"
#define ROOT_TYPE(type) "json: cannot unmarshal " type " into Go value of type box.user"
static char key[33], other[33];
static const char status_503[] = "unexpected HTTP response status 503";
static bool fail_status_copy;

/* Target only the core setter's positive-1 resource return. */
char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_box_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Box detector output")); free(error); error = NULL;
    CHECK(!br_box_init(&detector, &error) && detector && !error);
    CHECK(!br_box_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1002 && detector->version == 0 && !strcmp(detector->name, "Box"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Box is a service offering various service for secure collaboration, content management, and workflow. Box token can be used to access and interact with this data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "box"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_text(br_json *object, const char *name, br_slice text)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value)); CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == text.len);
    CHECK(!text.len || !memcmp(json_object_get_string(value), text.data, text.len));
}

static void check_key(const br_result *result, const char *expected)
{
    CHECK(result->detector_type == 1002 && !result->detector_name);
    CHECK(result->raw.len == strlen(expected) && !memcmp(result->raw.data, expected, strlen(expected)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    check_text(result->secret_parts, "key", (br_slice){(const unsigned char *)expected, strlen(expected)});
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void check_extra(const br_result *result, br_slice id, br_slice login, br_slice status)
{
    CHECK(result->verified && !result->verification_error);
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 3);
    check_text(result->extra_data, "user_id", id); check_text(result->extra_data, "username", login); check_text(result->extra_data, "user_status", status);
}

static void check_error(const br_result *result, const char *error)
{
    CHECK(!result->verified && !result->extra_data);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static void extraction_case(const br_detector *detector, const char *input, const char *expected)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) { check_key(&results.items[0], expected); check_error(&results.items[0], NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[256], changed[34];
    snprintf(input, sizeof(input), "box %s", key); extraction_case(detector, input, key);
    snprintf(input, sizeof(input), "unBOXed\r\n'%s'", key); extraction_case(detector, input, key);
    extraction_case(detector, key, NULL); extraction_case(detector, "", NULL);
    for (int gap = 40; gap <= 41; ++gap) {
        snprintf(input, sizeof(input), "box%*s%s", gap, "", key); extraction_case(detector, input, gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "box _%s", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "box %s_", key); extraction_case(detector, input, NULL);
    snprintf(input, sizeof(input), "box %sX", key); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[31] = '\0'; snprintf(input, sizeof(input), "box %s", changed); extraction_case(detector, input, NULL);
    memcpy(changed, key, sizeof(key)); changed[10] = '-'; snprintf(input, sizeof(input), "box %s", changed); extraction_case(detector, input, NULL);
    memset(changed, 'a', 32); changed[32] = '\0'; snprintf(input, sizeof(input), "box %s", changed); extraction_case(detector, input, changed); /* No entropy gate. */
    snprintf(input, sizeof(input), "box %s\nbox %s\nbox %s", key, key, other);
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2);
    check_key(&results.items[0], key); check_key(&results.items[1], other);
    check_error(&results.items[0], NULL); check_error(&results.items[1], NULL); br_results_clear(&results);
}

typedef struct { const char *key; int status, send_rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct {
    reply replies[2]; size_t count, releases, cancel_calls; bool cancel, expired;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 2 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1002 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.box.com/2.0/users/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && header(request, "Content-Type") && !strcmp(header(request, "Content-Type"), "application/json"));
    CHECK(header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Accept") && !header(request, "Content-Length"));
    char auth[64]; snprintf(auth, sizeof(auth), "Bearer %s", step->key);
    CHECK(header(request, "Authorization") && !strcmp(header(request, "Authorization"), auth));
    http->response = (br_http_response){.status = step->status, .body = step->body, .body_error = step->read_error};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps,
                       .deadline_monotonic_ms = steps->expired ? 1 : 0}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == steps->releases); return results;
}

static br_results single(const br_detector *detector, reply step)
{
    char input[64]; snprintf(input, sizeof(input), "box %s", step.key); script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 1); check_key(&results.items[0], step.key); return results;
}

static void valid_document(const br_detector *detector, br_slice body, const char *read_error,
                            br_slice id, br_slice login, br_slice status)
{
    br_results results = single(detector, (reply){.key = key, .status = 200, .body = body, .read_error = read_error});
    check_extra(&results.items[0], id, login, status); br_results_clear(&results);
}

static void typed_success(const br_detector *detector)
{
    valid_document(detector, SLICE("{}"), NULL, SLICE(""), SLICE(""), SLICE(""));
    valid_document(detector, SLICE("null"), NULL, SLICE(""), SLICE(""), SLICE(""));
    valid_document(detector, SLICE("{\"id\":null,\"login\":null,\"status\":null}"), NULL, SLICE(""), SLICE(""), SLICE(""));
    valid_document(detector, SLICE("{\"id\":\"17\",\"login\":\"synthetic@example.invalid\",\"status\":\"active\"}"), NULL,
                    SLICE("17"), SLICE("synthetic@example.invalid"), SLICE("active"));
    valid_document(detector, SLICE("{\"id\":\"first\",\"id\":\"last\",\"login\":\"old\",\"login\":null,\"status\":\"saved\",\"status\":null}"), NULL,
                    SLICE("last"), SLICE("old"), SLICE("saved"));
    valid_document(detector, SLICE("{\"id\":\"lower\",\"ID\":\"upper\",\"LoGiN\":\"u\",\"STATUS\":\"inactive\"}"), NULL,
                    SLICE("upper"), SLICE("u"), SLICE("inactive"));
    valid_document(detector, SLICE("{\"\\u017ftatu\\u017f\":\"active\"}"), NULL, SLICE(""), SLICE(""), SLICE("active"));
    valid_document(detector, SLICE("{\"unknown\":1e10000,\"name\":{\"nested\":[1e9999,9999999999999999999999999999999999999999]},\"id\":\"x\"}"), NULL,
                    SLICE("x"), SLICE(""), SLICE("")); /* No interface/float64 conversion for unused fields. */
    valid_document(detector, SLICE("{\"id\":\"a\\u0000b\",\"login\":\"c\\u0000d\",\"status\":\"e\\u0000f\"}"), NULL,
                    SLICE("a\0b"), SLICE("c\0d"), SLICE("e\0f"));
    valid_document(detector, SLICE("{\"id\":\"first\"}{\"id\":false} ignored"), "later read error", SLICE("first"), SLICE(""), SLICE(""));
    valid_document(detector, SLICE("{}"), "later read error", SLICE(""), SLICE(""), SLICE(""));
    valid_document(detector, SLICE("null {}"), "later read error", SLICE(""), SLICE(""), SLICE(""));
    char body[160]; snprintf(body, sizeof(body), "{\"login\":\"%s\"}", key);
    valid_document(detector, (br_slice){(const unsigned char *)body, strlen(body)}, NULL, SLICE(""), (br_slice){(const unsigned char *)key, 32}, SLICE("")); /* Metadata is not error-redacted. */
}

static void typed_errors(const br_detector *detector)
{
    const struct { const char *body, *error; } cases[] = {
        {"{\"id\":123}", FIELD_TYPE("id", "number")},
        {"{\"login\":true}", FIELD_TYPE("login", "bool")},
        {"{\"status\":{}}", FIELD_TYPE("status", "object")},
        {"{\"id\":1e10000}", FIELD_TYPE("id", "number")},
        {"{\"id\":123,\"id\":\"valid\",\"login\":true}", FIELD_TYPE("id", "number")},
        {"{\"id\":\"valid\",\"id\":false,\"id\":\"later\",\"status\":{}}", FIELD_TYPE("id", "bool")},
        {"{\"ID\":null,\"id\":[],\"ID\":null}", FIELD_TYPE("id", "array")},
        {"{\"status\":false,\"login\":0}", FIELD_TYPE("status", "bool")},
        {"[]", ROOT_TYPE("array")}, {"true", ROOT_TYPE("bool")}, {"1", ROOT_TYPE("number")}, {"\"text\"", ROOT_TYPE("string")},
        {"", "EOF"}, {"{\"id\":", "unexpected EOF"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .status = 200,
            .body = {(const unsigned char *)cases[i].body, strlen(cases[i].body)}});
        check_error(&results.items[0], cases[i].error); br_results_clear(&results);
    }
    char read_error[192], expected[192]; snprintf(read_error, sizeof(read_error), "read %s and %s; keep %s", key, key, other);
    snprintf(expected, sizeof(expected), "read [REDACTED] and [REDACTED]; keep %s", other);
    br_results results = single(detector, (reply){.key = key, .status = 200, .body = SLICE("{\"id\":"), .read_error = read_error});
    check_error(&results.items[0], expected); br_results_clear(&results);
}

static void status_transport_context(const br_detector *detector)
{
    const int codes[] = {401, 201, 400, 403, 503};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        br_results results = single(detector, (reply){.key = key, .status = codes[i], .body = SLICE("not JSON"), .read_error = "ignored"});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected HTTP response status %d", codes[i]);
        check_error(&results.items[0], codes[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char cause[192], expected[192]; snprintf(cause, sizeof(cause), "synthetic %s repeated %s; keep %s", key, key, other);
    snprintf(expected, sizeof(expected), "synthetic [REDACTED] repeated [REDACTED]; keep %s", other);
    br_results results = single(detector, (reply){.key = key, .status = 200, .body = SLICE("{}"), .send_error = cause});
    check_error(&results.items[0], expected); br_results_clear(&results);
    results = single(detector, (reply){.key = key, .send_rc = -1}); check_error(&results.items[0], "HTTP transport failed"); br_results_clear(&results);
    char input[64]; snprintf(input, sizeof(input), "box %s", key);
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1); check_error(&results.items[0], "net/http: nil Context"); br_results_clear(&results);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline};
        results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls); check_error(&results.items[0], NULL); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_error(&results.items[0], deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
}

static void release_owned_body(void *user, br_http_response *response)
{
    test_http_release(user, response);
    free((void *)response->body.data); response->body = (br_slice){0};
}

static void ownership_and_resource_failure(const br_detector *detector)
{
    const char json[] = "{\"id\":\"first\",\"id\":\"last\\u0000id\",\"login\":\"login\",\"status\":\"active\"}";
    char *body = strdup(json); CHECK(body); script steps = {.count = 1, .releases = 1};
    steps.replies[0] = (reply){.key = key, .status = 200, .body = {(const unsigned char *)body, strlen(body)}};
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = {&http, test_http_send, release_owned_body};
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    char input[160]; snprintf(input, sizeof(input), "box %s", key);
    br_results results = test_scan(detector, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    check_extra(&results.items[0], SLICE("last\0id"), SLICE("login"), SLICE("active")); br_results_clear(&results); /* Body, root and visitor values are already released. */
    snprintf(input, sizeof(input), "box %s\nbox %s\nbox %s", key, other, key);
    steps = (script){.count = 2, .releases = 2}; steps.replies[0] = (reply){.key = key, .status = 200, .body = SLICE("{\"id\":false}")};
    steps.replies[1] = (reply){.key = other, .status = 200, .body = SLICE("{}")};
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); check_error(&results.items[0], FIELD_TYPE("id", "bool"));
    check_extra(&results.items[1], SLICE(""), SLICE(""), SLICE("")); br_results_clear(&results); /* Decode error +1 is not scan/resource failure. */
    steps.replies[0] = (reply){.key = key, .status = 200, .body = SLICE("{\"id\":\"owned\"}")};
    steps.replies[1] = (reply){.key = other, .status = 503}; http = (test_http){.inspect = inspect, .user = &steps};
    transport = test_transport(&http); ctx = (br_scan_ctx){.transport = &transport}; steps.expected_ctx = &ctx;
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
    fail_status_copy = true; int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && *error && http.calls == 2 && http.releases == 2);
    CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); check_extra(&results.items[0], SLICE("owned"), SLICE(""), SLICE(""));
    check_error(&results.items[1], status_503); br_results_clear(&results);
}

int main(void)
{
    test_secret(key, 32, 1); test_secret(other, 32, 13); key[0] = 'A'; other[0] = 'Z';
    const br_detector *detector = init();
    extraction(detector); typed_success(detector); typed_errors(detector); status_transport_context(detector); ownership_and_resource_failure(detector);
    return test_finish("Box unique tokens + typed first-document user projection + NUL ownership");
}
