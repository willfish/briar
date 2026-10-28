/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

#define HALF "AaBbCcDd01234567"
static const char key[] = HALF HALF, lower[] = "aabbccdd01234567aabbccdd01234567";
static char mixed[33];
static size_t fail_size, fail_after, allocation_failures, fail_push_size;
static const char *fail_field;
static size_t fail_field_after;
static bool arm_shared_headers;

/* Real native ownership/shared-HTTP resources, not new provider/API seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
void *realloc(void *old, size_t size)
{
    if (fail_push_size && size == fail_push_size) { fail_push_size = 0; ++allocation_failures; return NULL; }
    if (!size) { free(old); return NULL; }
    size_t previous = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, previous < size ? previous : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_field_after && !strcmp(name, fail_field) && --fail_field_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && arm_shared_headers && !strcmp(name, "key")) {
        arm_shared_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1;
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
typedef struct { br_slice id, user, expires, scope; } details;
#define DETAILS(i,u,e,s) ((details){TEXT(i), TEXT(u), TEXT(e), TEXT(s)})

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(lower) == 32 && strlen(mixed) == 32);
    CHECK(br_fastlypersonaltoken_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_fastlypersonaltoken_init(&d, &error) == 0 && d && !error);
    CHECK(br_fastlypersonaltoken_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 68 && d->version == 0 && !strcmp(d->name, "FastlyPersonalToken") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Fastly is a content delivery network (CDN) and cloud service provider. Fastly personal tokens can be used to authenticate API requests to Fastly services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "fastly"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void field(br_json *object, const char *name, br_slice expected)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len && (!expected.len || !memcmp(json_object_get_string(value), expected.data, expected.len)));
}
static void finding(const br_result *r, const char *expected, bool verified, const char *cause, const details *extra)
{
    CHECK(r->detector_type == 68 && !r->detector_name && r->raw.len == 32 && !memcmp(r->raw.data, expected, 32));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->verification_from_cache && !r->chunk_offset && !r->chunk_offset_set && r->verified == verified);
    CHECK((r->verification_error != NULL) == (cause != NULL)); if (cause) CHECK(!strcmp(r->verification_error, cause));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1); field(r->secret_parts, "key", text(expected));
    if (!extra) CHECK(!r->extra_data);
    else {
        CHECK(r->extra_data && json_object_object_length(r->extra_data) == 4);
        field(r->extra_data, "token_id", extra->id); field(r->extra_data, "user_id", extra->user);
        field(r->extra_data, "token_expires_at", extra->expires); field(r->extra_data, "token_scope", extra->scope);
    }
}
static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == (expected ? 1u : 0u));
    if (expected) finding(&out.items[0], expected, false, NULL, NULL);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[280], changed[34]; extraction_case(d, key, NULL);
    const char *good[] = {"fastly %s", "FASTLY='%s'", "FaStLy\r\n%s", "xfastly:(%s)"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, key); }
    snprintf(input, sizeof(input), "fastly %s", mixed); extraction_case(d, input, mixed);
    memset(changed, '_', 32); changed[32] = '\0'; snprintf(input, sizeof(input), "fastly %s", changed); extraction_case(d, input, changed);
    const char *bad[] = {"fast %s", "fastly _%s", "fastly %s_", "fastly %sA", "fastly %.31s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, input, NULL); }
    memcpy(changed, key, sizeof(key)); changed[15] = '+'; snprintf(input, sizeof(input), "fastly %s", changed); extraction_case(d, input, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "fastly", 6); memset(input + 6, ' ', gap); memcpy(input + 6 + gap, key, sizeof(key)); extraction_case(d, input, gap == 40 ? key : NULL);
    }
    /* Hyphens are legal but NON-word: preserve the source's word boundaries
     * and backtracking, rather than adding a full-token-alphabet delimiter. */
    memset(changed, 'A', 32); changed[0] = '-'; changed[32] = '\0';
    snprintf(input, sizeof(input), "fastly %s", changed); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "fastly X%s", changed); extraction_case(d, input, changed);
    memset(changed, 'A', 32); changed[31] = '-'; changed[32] = '\0';
    snprintf(input, sizeof(input), "fastly %sZ", changed); extraction_case(d, input, changed);
    snprintf(input, sizeof(input), "fastly %s\nFASTLY %s\nfastly %s\nfastly %s", key, lower, key, mixed);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false, NULL, NULL); finding(&out.items[1], lower, false, NULL, NULL); finding(&out.items[2], mixed, false, NULL, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].secret_parts != out.items[1].secret_parts); br_results_clear(&out);
    extraction_case(d, "", NULL);
}

typedef struct { const char *key, *read_error, *send_error; int status, rc; br_slice body; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_key; char *read_storage, *transport_storage; unsigned char *body_storage;
    size_t arm_call, arm_size, arm_after, arm_push; const char *arm_field;
} script;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    CHECK(request->detector_type == 68 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.fastly.com/tokens/self"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Fastly-Key") && !strcmp(request->headers[0].value, steps->rows[at].key));
    CHECK(!memcmp(request->headers[0].value, steps->rows[at].key, 33)); steps->borrowed_key = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog fastly-offline" : "TruffleHog"));
    row *reply = &steps->rows[at];
    if (reply->read_error) { steps->read_storage = strdup(reply->read_error); CHECK(steps->read_storage); }
    if (reply->body.len) { steps->body_storage = malloc(reply->body.len); CHECK(steps->body_storage); memcpy(steps->body_storage, reply->body.data, reply->body.len); }
    http->response = (br_http_response){.status = reply->status, .body = {steps->body_storage, reply->body.len}, .body_error = steps->read_storage};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    steps->transport_storage = *error; /* Already-owned output can be moved without a redundant clone. */
    if (steps->arm_call == http->calls) {
        fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push;
        if (steps->arm_field) { fail_field = steps->arm_field; fail_field_after = 1; }
    }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_key && !memcmp(steps->borrowed_key, steps->rows[http->calls - 1].key, 33)); steps->borrowed_key = NULL;
    if (steps->transport_storage) CHECK(!strcmp(steps->transport_storage, steps->rows[http->calls - 1].send_error));
    /* Pending values/Reader causes MUST be independently owned before release. */
    if (steps->read_storage) memset(steps->read_storage, '!', strlen(steps->read_storage));
    if (steps->body_storage) memset(steps->body_storage, '!', response->body.len);
    free(steps->read_storage); free(steps->body_storage);
    steps->read_storage = steps->transport_storage = NULL; steps->body_storage = NULL; test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "fastly-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_key && !steps->read_storage && !steps->body_storage); return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static br_results one(const br_detector *d, int status, br_slice body, const char *read_error, const char *send_error, int send_rc)
{
    char input[48]; snprintf(input, sizeof(input), "fastly %s", key);
    script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = status, .body = body, .read_error = read_error, .send_error = send_error, .rc = send_rc};
    br_results out = run(d, input, &steps); CHECK(out.len == 1); return out;
}

static void four_typed_fields_and_reader(const br_detector *d)
{
    const struct { br_slice body; const char *read, *cause; details expected; } cases[] = {
        {TEXT("null"), NULL, NULL, DETAILS("", "", "never", "")},
        {TEXT("{}"), NULL, NULL, DETAILS("", "", "never", "")},
        {TEXT("{\"id\":\"i\",\"user_id\":\"u\",\"expires_at\":\"not-a-date\",\"scope\":\"global:read\"}"), NULL, NULL, DETAILS("i", "u", "not-a-date", "global:read")},
        {TEXT("{\"id\":\"first\",\"ID\":null,\"user_id\":\"u\",\"USER_ID\":null,\"expires_at\":\"kept\",\"EXPIRES_AT\":null,\"scope\":\"s\",\"SCOPE\":null}"), NULL, NULL, DETAILS("first", "u", "kept", "s")},
        {TEXT("{\"id\":\"old\",\"id\":\"new\",\"expires_at\":\"old\",\"expires_at\":\"\"}"), NULL, NULL, DETAILS("new", "", "never", "")},
        {TEXT("{\"id\":null,\"user_id\":null,\"expires_at\":null,\"scope\":null}"), NULL, NULL, DETAILS("", "", "never", "")},
        {TEXT("{\"id\":\"i\\u0000λ\",\"u\\u017fer_id\":\"\\u0000u\",\"expire\\u017f_at\":\"\\u0000\",\"\\u017fcope\":\"global\\u0000🌲\"}"), NULL, NULL, DETAILS("i\0λ", "\0u", "\0", "global\0🌲")},
        {TEXT("{\"id\\u0000x\":false,\"user_id\\u0000x\":false,\"expires_at\\u0000\":false,\"scope\\u0000\":false}"), NULL, NULL, DETAILS("", "", "never", "")},
        {TEXT("{\"unknown\":{\"n\":1e10000,\"n\":0},\"expires_at\":\"Never\"}"), NULL, NULL, DETAILS("", "", "Never", "")},
        {TEXT("{\"id\":\"first\"}{\"unknown\":1e10000}\xff"), "ignored tail read", NULL, DETAILS("first", "", "never", "")},
        {TEXT("{\"id\":\"complete\"}"), "terminal read", NULL, DETAILS("complete", "", "never", "")},
        {TEXT("{}\0\xff"), NULL, NULL, DETAILS("", "", "never", "")},
        {TEXT("null "), "after separator", NULL, DETAILS("", "", "never", "")},
        {TEXT("null"), "terminal scalar read", "terminal scalar read", DETAILS("", "", "", "")},
        {TEXT("[1e10000]"), NULL, "json: cannot unmarshal array into Go value of type fastlypersonaltoken.token", DETAILS("", "", "", "")},
        {TEXT("\"text\" "), NULL, "json: cannot unmarshal string into Go value of type fastlypersonaltoken.token", DETAILS("", "", "", "")},
        {TEXT("{\"id\":true,\"id\":\"later\",\"scope\":7}"), NULL, "json: cannot unmarshal bool into Go struct field token.id of type string", DETAILS("", "", "", "")},
        {TEXT("{\"user_id\":7}"), NULL, "json: cannot unmarshal number into Go struct field token.user_id of type string", DETAILS("", "", "", "")},
        {TEXT("{\"id\":\"discarded\",\"expires_at\":[]}"), NULL, "json: cannot unmarshal array into Go struct field token.expires_at of type string", DETAILS("", "", "", "")},
        {TEXT("{\"scope\":{},\"id\":false}"), NULL, "json: cannot unmarshal object into Go struct field token.scope of type string", DETAILS("", "", "", "")},
        {TEXT("{\"id\":1e10000,\"id\":\"later\"}"), NULL, "json: cannot unmarshal number into Go struct field token.id of type string", DETAILS("", "", "", "")},
        {TEXT(""), NULL, "EOF", DETAILS("", "", "", "")}, {TEXT("{"), NULL, "unexpected EOF", DETAILS("", "", "", "")},
        {TEXT("{"), "incomplete read", "incomplete read", DETAILS("", "", "", "")}, {TEXT("{"), "", "", DETAILS("", "", "", "")},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_results out = one(d, 200, cases[i].body, cases[i].read, NULL, 0);
        finding(&out.items[0], key, cases[i].cause == NULL, cases[i].cause, cases[i].cause ? NULL : &cases[i].expected); br_results_clear(&out);
    }
}

static void statuses_causes_and_unique_requests(const br_detector *d)
{
    const int statuses[] = {0, 199, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected status code: %d", statuses[i]);
        br_results out = one(d, statuses[i], TEXT("\xff"), "ignored", NULL, 0);
        finding(&out.items[0], key, false, statuses[i] == 401 || statuses[i] == 403 ? NULL : cause, NULL); br_results_clear(&out);
    }
    char echo[240]; snprintf(echo, sizeof(echo), "reader %s echoed %s", key, key);
    br_results out = one(d, 200, TEXT("{"), echo, NULL, 0);
    finding(&out.items[0], key, false, "reader [REDACTED] echoed [REDACTED]", NULL); br_results_clear(&out);
    snprintf(echo, sizeof(echo), "do not strip failed to make request: %s", key);
    out = one(d, 200, TEXT("{}"), NULL, echo, 1);
    finding(&out.items[0], key, false, "do not strip failed to make request: [REDACTED]", NULL); br_results_clear(&out);
    out = one(d, 200, TEXT("{}"), NULL, "", -1); finding(&out.items[0], key, false, "", NULL); br_results_clear(&out);
    char input[180]; snprintf(input, sizeof(input), "fastly %s", key);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 1); finding(&out.items[0], key, false, "net/http: nil Context", NULL); br_results_clear(&out);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_shared_headers = true;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(!arm_shared_headers && !fail_after && allocation_failures == before + 1 && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "out of memory constructing HTTP headers", NULL); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, "HTTP transport not installed", NULL); br_results_clear(&out);
    snprintf(input, sizeof(input), "fastly %s\nFASTLY %s\nfastly %s", key, mixed, key);
    script steps = {.count = 2, .suffix = true}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("null")}; steps.rows[1] = (row){.key = mixed, .status = 401};
    out = run(d, input, &steps); CHECK(out.len == 2); details empty = DETAILS("", "", "never", "");
    finding(&out.items[0], key, true, NULL, &empty); finding(&out.items[1], mixed, false, NULL, NULL); br_results_clear(&out);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key"); free(error); br_results_clear(out);
}
static void owned_resources_and_consumed_boundary(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "fastly %s", key);
    const size_t sizes[] = {33, 32};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures; fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    const char *leaf = "distinct incomplete reader cause";
    for (size_t allocation = 1; allocation <= 2; ++allocation) {
        script steps = {.count = 1, .arm_call = 1, .arm_size = strlen(leaf) + 1, .arm_after = allocation};
        steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{"), .read_error = leaf};
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        int rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error); /* Decode cause then +1 caller setter failure, never ordinary false. */
    }
    const char *type_cause = "json: cannot unmarshal bool into Go struct field token.id of type string";
    script steps = {.count = 1, .arm_call = 1, .arm_size = strlen(type_cause) + 1, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"id\":true}")};
    br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
    int rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    /* Last output field fails after three pending metadata fields were added. */
    steps = (script){.count = 1, .arm_call = 1, .arm_field = "token_scope"}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("null")};
    out = caller_owned(); error = NULL; rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_field_after); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = sizeof("unexpected status code: 500"), .arm_after = 1}; steps.rows[0] = (row){.key = key, .status = 500};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{}")};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"id\":\"\xff\"}")};
    out = caller_owned(); error = NULL; rc = invoke(d, input, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported: FastlyPersonalToken invalid UTF-8 in consumed")); rolled_back(&out, rc, error);
    char products[128]; snprintf(products, sizeof(products), "fastly %s\nfastly %s", key, mixed);
    steps = (script){.count = 2, .arm_call = 2, .arm_size = strlen(leaf) + 1, .arm_after = 2};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("null")}; steps.rows[1] = (row){.key = mixed, .status = 200, .body = TEXT("{"), .read_error = leaf};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, products, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
}

int main(void)
{
    memcpy(mixed, key, sizeof(key)); mixed[5] = '_'; mixed[15] = '-'; mixed[23] = '_';
    const br_detector *d = descriptor();
    extraction(d);
    four_typed_fields_and_reader(d);
    statuses_causes_and_unique_requests(d);
    owned_resources_and_consumed_boundary(d);
    CHECK(!fail_after && !fail_field_after && !fail_push_size && !arm_shared_headers);
    return test_finish("FastlyPersonalToken");
}
