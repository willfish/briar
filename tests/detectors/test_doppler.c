/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

#define PAYLOAD "AbCdEfGhIjKlMnOpQrStUvWxY0123456789aBcDe"
static const char token[] = "dp.pt." PAYLOAD;
static const char other[] = "dp.audit." PAYLOAD;
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;

/* Actual native owned resources, with no production allocation/failure seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++allocation_failures; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *text)
{
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
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
    if (fail_add_after && --fail_add_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && sizeof(PAYLOAD) - 1 == 40);
    CHECK(br_doppler_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_doppler_init(&d, &error) == 0 && d && !error);
    CHECK(br_doppler_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 196 && d->version == 0 && !strcmp(d->name, "Doppler") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Doppler is a secrets management platform that allows teams to manage and secure environment variables and secrets. Doppler tokens can be used to access and manage these secrets."));
    const char *keywords[] = {"dp.ct.", "dp.pt.", "dp.st", "dp.sa.", "dp.scim.", "dp.audit."};
    CHECK(d->nkeywords == 6);
    for (size_t i = 0; i < 6; ++i) CHECK(!strcmp(d->keywords[i], keywords[i]));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void metadata(br_json *extra, const char *key, br_slice expected)
{
    br_json *value = NULL;
    if (!expected.len) { CHECK(!json_object_object_get_ex(extra, key, &value)); return; }
    CHECK(json_object_object_get_ex(extra, key, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len && !memcmp(json_object_get_string(value), expected.data, expected.len));
}

static void finding(const br_result *r, const char *key, bool verified, br_slice type, br_slice workplace)
{
    CHECK(r->detector_type == 196 && !r->detector_name && r->raw.len == strlen(key) && !memcmp(r->raw.data, key, r->raw.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data && !r->verification_error);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->verification_from_cache);
    CHECK(!r->chunk_offset && !r->chunk_offset_set && r->verified == verified);
    br_json *part = NULL; CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == strlen(key) && !memcmp(json_object_get_string(part), key, strlen(key)));
    CHECK(r->extra_data && json_object_is_type(r->extra_data, json_type_object));
    CHECK(json_object_object_length(r->extra_data) == (int)((type.len != 0) + (workplace.len != 0)));
    metadata(r->extra_data, "key type", type); metadata(r->extra_data, "workplace", workplace);
    CHECK(!json_object_object_get_ex(r->extra_data, "name", &part));
}

static void extraction_case(const br_detector *d, br_slice input, const char *key)
{
    br_results out = test_scan(d, NULL, false, input.data, input.len);
    CHECK(out.len == (key ? 1u : 0u));
    if (key) finding(&out.items[0], key, false, (br_slice){0}, (br_slice){0});
    br_results_clear(&out);
}

static void extraction(const br_detector *d, char maximum[87])
{
    const char *kinds[] = {"ct", "pt", "st", "sa", "scim", "audit"};
    char input[256], key[100], changed[100];
    for (size_t i = 0; i < 6; ++i) for (size_t len = 40; len <= 44; len += 4) {
        int prefix = snprintf(key, sizeof(key), "dp.%s.", kinds[i]); CHECK(prefix > 0);
        memset(key + prefix, 'A', len); key[prefix + len] = '\0';
        extraction_case(d, text(key), key); /* No entropy, JWT or Base64 validation. */
    }
    const char *namespaces[] = {"_-", "a9_-", "abcdefghijklmnopqrstuvwxyz012345678"};
    for (size_t i = 0; i < 3; ++i) {
        snprintf(key, sizeof(key), "dp.st.%s.%s", namespaces[i], PAYLOAD); extraction_case(d, text(key), key);
    }
    memcpy(maximum, "dp.st.", 6); memset(maximum + 6, '-', 35); maximum[41] = '.';
    memset(maximum + 42, 'Z', 44); maximum[86] = '\0'; extraction_case(d, text(maximum), maximum);
    const char *bad_namespaces[] = {"a", "AA", "aA", "abcdefghijklmnopqrstuvwxyz0123456789", "a+"};
    for (size_t i = 0; i < 5; ++i) { snprintf(key, sizeof(key), "dp.st.%s.%s", bad_namespaces[i], PAYLOAD); extraction_case(d, text(key), NULL); }
    const char *good[] = {"'%s'", "(%s)\r\n", "-%s-", "arbitrary-prefix/%s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), good[i], token); extraction_case(d, text(input), token); }
    const char *bad[] = {"_%s", "x%s", "%s_", "dp.PT.%s", "DP.pt.%s"};
    for (size_t i = 0; i < 3; ++i) { snprintf(input, sizeof(input), bad[i], token); extraction_case(d, text(input), NULL); }
    for (size_t i = 3; i < 5; ++i) { snprintf(input, sizeof(input), bad[i], PAYLOAD); extraction_case(d, text(input), NULL); }
    memcpy(changed, token, sizeof(token)); changed[20] = '_'; extraction_case(d, text(changed), NULL);
    memcpy(changed, token, sizeof(token)); changed[20] = '-'; extraction_case(d, text(changed), NULL);
    memcpy(changed, "dp.pt.", 6); memset(changed + 6, 'a', 39); changed[45] = '\0'; extraction_case(d, text(changed), NULL);
    memset(changed + 6, 'a', 45); changed[51] = '\0'; extraction_case(d, text(changed), NULL);
    input[0] = '\0'; memcpy(input + 1, token, sizeof(token) - 1); input[sizeof(token)] = (char)0xff;
    extraction_case(d, (br_slice){(unsigned char *)input, sizeof(token) + 1}, token);
    extraction_case(d, (br_slice){0}, NULL);
    snprintf(input, sizeof(input), "%s\n%s\n%s", token, other, token);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], token, false, (br_slice){0}, (br_slice){0});
    finding(&out.items[1], other, false, (br_slice){0}, (br_slice){0});
    finding(&out.items[2], token, false, (br_slice){0}, (br_slice){0});
    CHECK(out.items[0].extra_data != out.items[2].extra_data); br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out); /* Nil ctor SKIPS every occurrence. */
}

typedef struct { const char *key, *read_error, *send_error; int status, rc; br_slice body; } row;
typedef struct {
    row rows[4]; size_t count; const br_scan_ctx *ctx;
    const char *borrowed_auth; char *read_storage, *transport_storage; unsigned char *body_storage;
    size_t arm_call, arm_size, arm_after, arm_add, arm_push;
    bool suffix;
} script;

static void authorization(const char *value, const char *key)
{
    size_t len = strlen(key); CHECK(value && len <= 86 && strlen(value) == 7 + len && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, key, len + 1));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 4 && ctx == steps->ctx && http->releases == at);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 196 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.doppler.com/v3/me"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Accept") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization")); authorization(request->headers[1].value, reply->key);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog doppler-offline" : "TruffleHog"));
    steps->borrowed_auth = request->headers[1].value;
    if (reply->read_error) { steps->read_storage = strdup(reply->read_error); CHECK(steps->read_storage); }
    if (reply->body.len) { steps->body_storage = malloc(reply->body.len); CHECK(steps->body_storage); memcpy(steps->body_storage, reply->body.data, reply->body.len); }
    http->response = (br_http_response){.status = reply->status, .body = {steps->body_storage, reply->body.len}, .body_error = steps->read_storage};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    steps->transport_storage = *error;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_add_after = steps->arm_add; fail_push_size = steps->arm_push; }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key); steps->borrowed_auth = NULL;
    if (steps->read_storage) memset(steps->read_storage, '!', strlen(steps->read_storage));
    if (steps->transport_storage) memset(steps->transport_storage, '!', strlen(steps->transport_storage));
    if (steps->body_storage) memset(steps->body_storage, '!', response->body.len);
    free(steps->read_storage); free(steps->body_storage);
    steps->read_storage = steps->transport_storage = NULL; steps->body_storage = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, bool verify, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "doppler-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, verify, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_auth && !steps->read_storage && !steps->body_storage);
    return rc;
}

static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL;
    int rc = invoke(d, input, true, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static br_results one(const br_detector *d, int status, br_slice body, const char *read_error)
{
    script steps = {.count = 1}; steps.rows[0] = (row){.key = token, .status = status, .body = body, .read_error = read_error};
    return run(d, text(token), &steps);
}

static void statuses_suppression_and_occurrences(const br_detector *d, const char *maximum)
{
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        br_results out = one(d, statuses[i], TEXT("{}\xff"), "ignored trailing read error"); CHECK(out.len == 1);
        finding(&out.items[0], token, statuses[i] >= 200 && statuses[i] < 300, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary do failure", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = token, .status = 200, .body = TEXT("{}"), .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        br_results out = run(d, text(token), &steps); CHECK(out.len == 1); finding(&out.items[0], token, false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    }
    /* Actual shared setup failures, not text classification or provider skips. */
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport, .user_agent = "\r"};
    br_results out = test_scan(d, &ctx, true, token, strlen(token)); CHECK(out.len == 1 && !http.calls && http.releases == 1);
    finding(&out.items[0], token, false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, token, strlen(token)); CHECK(out.len == 1);
    finding(&out.items[0], token, false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    script steps = {.count = 1, .suffix = true}; steps.rows[0] = (row){.key = maximum, .status = 200, .body = TEXT("null")};
    out = run(d, text(maximum), &steps); CHECK(out.len == 1); finding(&out.items[0], maximum, true, (br_slice){0}, (br_slice){0}); br_results_clear(&out);

    char input[240]; snprintf(input, sizeof(input), "%s\n%s\n%s\n%s", token, other, token, token);
    steps = (script){.count = 4};
    steps.rows[0] = (row){.key = token, .status = 200, .body = TEXT("{\"type\":\"first\"}")};
    steps.rows[1] = (row){.key = other, .status = 201, .body = TEXT("{\"name\":false}")}; /* DROP, despite verified. */
    steps.rows[2] = (row){.key = token, .status = 299, .body = TEXT("{\"type\":\"third\"}")};
    steps.rows[3] = (row){.key = token, .status = 401};
    out = run(d, text(input), &steps); CHECK(out.len == 3);
    finding(&out.items[0], token, true, TEXT("first"), (br_slice){0}); finding(&out.items[1], token, true, TEXT("third"), (br_slice){0});
    finding(&out.items[2], token, false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
}

static void first_document_typed_json(const br_detector *d)
{
    const struct { br_slice body; const char *read; bool keep; br_slice type, workplace; } cases[] = {
        {TEXT("null"), NULL, true, {0}, {0}}, {TEXT("{}"), NULL, true, {0}, {0}},
        {TEXT("{\"name\":\"not-published\",\"type\":\"service\",\"workplace\":{\"name\":\"offline\"}}"), NULL, true, TEXT("service"), TEXT("offline")},
        {TEXT("{\"type\":\"first\",\"TYPE\":null,\"workplace\":{\"name\":\"first\"},\"WORKPLACE\":{},\"workplace\":null}"), NULL, true, TEXT("first"), TEXT("first")},
        {TEXT("{\"type\":\"first\",\"TYPE\":\"\",\"workplace\":{\"name\":\"old\",\"NAME\":null},\"workplace\":{\"name\":\"new\"}}"), NULL, true, {0}, TEXT("new")},
        {TEXT("{\"type\":null,\"workplace\":{\"name\":null},\"name\":null}"), NULL, true, {0}, {0}},
        {TEXT("{\"TYPE\":\"λ\\u0000\",\"wor\\u212Aplace\":{\"Name\":\"\\u0000🌲\"}}"), NULL, true, TEXT("λ\0"), TEXT("\0🌲")},
        {TEXT("{\"type\":\"\\u0000\",\"workplace\":{\"name\":\"\\u0000\"}}"), NULL, true, TEXT("\0"), TEXT("\0")},
        {TEXT("{\"type\\u0000x\":\"ignored\",\"workplace\\u0000x\":{\"name\":\"ignored\"},\"name\\u0000\":false}"), NULL, true, {0}, {0}},
        {TEXT("{\"unknown\":1e10000,\"workplace\":{\"unknown\":1e10000,\"name\":\"kept\"}}{}\xff"), "tail read", true, {0}, TEXT("kept")},
        {TEXT("{}\0\xff"), NULL, true, {0}, {0}}, {TEXT("{} not JSON"), NULL, true, {0}, {0}},
        {TEXT("{\"type\":\"complete\"}"), "read after closing brace", true, TEXT("complete"), {0}},
        {TEXT("null "), "read after separator", true, {0}, {0}},
        {TEXT("null"), "terminal read", false, {0}, {0}},
        {TEXT("{\"type\":7,\"type\":\"later\"}"), NULL, false, {0}, {0}},
        {TEXT("{\"name\":true,\"name\":\"later\",\"type\":\"ignored\"}"), NULL, false, {0}, {0}},
        {TEXT("{\"workplace\":false,\"workplace\":{\"name\":\"later\"}}"), NULL, false, {0}, {0}},
        {TEXT("{\"workplace\":{\"name\":4,\"name\":\"later\"}}"), NULL, false, {0}, {0}},
        {TEXT("[]"), NULL, false, {0}, {0}}, {TEXT("123 "), NULL, false, {0}, {0}},
        {TEXT("\"string\" "), NULL, false, {0}, {0}}, {TEXT("{\"type\": "), NULL, false, {0}, {0}},
        {TEXT(""), NULL, false, {0}, {0}}, {TEXT("{\"type\":"), "read before completion", false, {0}, {0}},
        {TEXT(""), "", false, {0}, {0}}, {TEXT("{\"type\":@}"), "later read", false, {0}, {0}},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_results out = one(d, 200, cases[i].body, cases[i].read);
        CHECK(out.len == (cases[i].keep ? 1u : 0u));
        if (cases[i].keep) finding(&out.items[0], token, true, cases[i].type, cases[i].workplace);
        br_results_clear(&out);
    }
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0); return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0], 17, "caller-owned", "key");
    free(error); br_results_clear(out);
}

static void resources_before_drop(const br_detector *d)
{
    br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
    fail_size = strlen(token); fail_after = 1;
    int rc = d->scan(d, NULL, true, text(token), &out, &error); /* Finding MUST precede nil-ctx skip. */
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    out = caller_owned(); error = NULL; fail_add_after = 1;
    rc = d->scan(d, NULL, false, text(token), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);

    char cause[200]; snprintf(cause, sizeof(cause), "reader saw %s and %s", token, token);
    /* Decoder cause-copy then the REQUIRED setter copy: failure of either must
     * abort, not be mistaken for the source's ordinary continue/drop. */
    for (size_t allocation = 1; allocation <= 2; ++allocation) {
        script steps = {.count = 1, .arm_call = 1, .arm_size = strlen(cause) + 1, .arm_after = allocation};
        steps.rows[0] = (row){.key = token, .status = 200, .read_error = cause};
        out = caller_owned(); error = NULL; before = allocation_failures;
        rc = invoke(d, text(token), true, &steps, &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    script steps = {.count = 1, .arm_call = 1, .arm_size = sizeof("reader saw [REDACTED] and [REDACTED]"), .arm_after = 1};
    steps.rows[0] = (row){.key = token, .status = 200, .read_error = cause};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(token), true, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error); /* Redaction resource before DROP. */

    const char *type_cause = "json: cannot unmarshal bool into Go struct field response.name of type string";
    steps = (script){.count = 1, .arm_call = 1, .arm_size = strlen(type_cause) + 1, .arm_after = 1};
    steps.rows[0] = (row){.key = token, .status = 200, .body = TEXT("{\"name\":true}")};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(token), true, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);

    steps = (script){.count = 1, .arm_call = 1, .arm_add = 1}; steps.rows[0] = (row){.key = token, .status = 200, .body = TEXT("{\"type\":\"service\"}")};
    out = caller_owned(); error = NULL; rc = invoke(d, text(token), true, &steps, &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 8 * sizeof(br_result)}; steps.rows[0] = (row){.key = token, .status = 200, .body = TEXT("null")};
    out = (br_results){0}; error = NULL; before = allocation_failures; rc = invoke(d, text(token), true, &steps, &out, &error);
    CHECK(rc == -1 && error && out.len == 0 && !fail_push_size && allocation_failures == before + 1); free(error); br_results_clear(&out);

    char input[180]; snprintf(input, sizeof(input), "%s\n%s", token, other);
    steps = (script){.count = 2, .arm_call = 2, .arm_size = strlen(cause) + 1, .arm_after = 2};
    steps.rows[0] = (row){.key = token, .status = 200, .body = TEXT("{}")}; steps.rows[1] = (row){.key = other, .status = 201, .read_error = cause};
    out = caller_owned(); error = NULL; before = allocation_failures; rc = invoke(d, text(input), true, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error); /* Also removes the prior append from this invocation. */
}

static void consumed_utf8_boundary(const br_detector *d)
{
    script steps = {.count = 1}; steps.rows[0] = (row){.key = token, .status = 200, .body = TEXT("{\"type\":\"\xff\"}")};
    br_results out = caller_owned(); char *error = NULL;
    int rc = invoke(d, text(token), true, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported: Doppler invalid UTF-8 in consumed JSON")); rolled_back(&out, rc, error);
    out = one(d, 401, TEXT("{\"type\":\"\xff\"}"), NULL); CHECK(out.len == 1);
    finding(&out.items[0], token, false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor(); char maximum[87];
    extraction(d, maximum);
    statuses_suppression_and_occurrences(d, maximum);
    first_document_typed_json(d);
    resources_before_drop(d);
    consumed_utf8_boundary(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size);
    return test_finish("Doppler");
}
