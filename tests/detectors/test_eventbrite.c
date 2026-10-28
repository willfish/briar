/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static const char key[] = "ABCD0123EFGH4567IJKL", other[] = "ZYXW9876VUTS5432RQPO";
static size_t fail_size, fail_after, allocation_failures, fail_push_size;
static bool fail_user_add;

/* Native ownership failures only; the bounded URL has no heap/format seam. */
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
    if (fail_user_add && !strcmp(name, "user name")) { fail_user_add = false; return 1; }
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 20 && strlen(other) == 20);
    CHECK(br_eventbrite_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_eventbrite_init(&d, &error) == 0 && d && !error);
    CHECK(br_eventbrite_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 962 && d->version == 0 && !strcmp(d->name, "Eventbrite") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Eventbrite is an event management and ticketing website. Eventbrite API keys can be used to access and manage event data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "eventbrite"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
/* extra=-1 nil after ordinary verification failure, 0 initial empty NoV,
 * +1 independently prepared username map after successful 200 decoding. */
static void finding(const br_result *r, const char *expected, bool verified, const char *cause, int extra, br_slice name)
{
    CHECK(r->detector_type == 962 && !r->detector_name && r->raw.len == 20 && !memcmp(r->raw.data, expected, 20));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->verification_from_cache && !r->chunk_offset && !r->chunk_offset_set && r->verified == verified);
    CHECK((r->verification_error != NULL) == (cause != NULL)); if (cause) CHECK(!strcmp(r->verification_error, cause));
    br_json *part = NULL; CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 20 && !memcmp(json_object_get_string(part), expected, 20));
    if (extra < 0) CHECK(!r->extra_data);
    else {
        CHECK(r->extra_data && json_object_is_type(r->extra_data, json_type_object) && json_object_object_length(r->extra_data) == extra);
        if (extra) {
            CHECK(json_object_object_get_ex(r->extra_data, "user name", &part) && json_object_is_type(part, json_type_string));
            CHECK((size_t)json_object_get_string_len(part) == name.len && (!name.len || !memcmp(json_object_get_string(part), name.data, name.len)));
        }
    }
}
static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == (expected ? 1u : 0u));
    if (expected) finding(&out.items[0], expected, false, NULL, 0, (br_slice){0});
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[240], changed[22]; extraction_case(d, key, NULL);
    const char *good[] = {"eventbrite %s", "EVENTBRITE='%s'", "EvEnTbRiTe\n%s", "xeventbrite:%s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, key); }
    const char *bad[] = {"eventbrit %s", "eventbrite _%s", "eventbrite %s_", "eventbrite %s0", "eventbrite %.19s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, input, NULL); }
    memcpy(changed, key, sizeof(key)); changed[10] = 'g'; snprintf(input, sizeof(input), "eventbrite %s", changed); extraction_case(d, input, NULL);
    memset(changed, '0', 20); changed[20] = '\0'; snprintf(input, sizeof(input), "eventbrite %s", changed); extraction_case(d, input, changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "eventbrite", 10); memset(input + 10, ' ', gap); memcpy(input + 10 + gap, key, sizeof(key));
        extraction_case(d, input, gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "eventbrite %s\nEVENTBRITE %s\neventbrite %s", key, other, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 2);
    finding(&out.items[0], key, false, NULL, 0, (br_slice){0}); finding(&out.items[1], other, false, NULL, 0, (br_slice){0});
    CHECK(out.items[0].extra_data != out.items[1].extra_data && out.items[0].raw.data != out.items[1].raw.data); br_results_clear(&out);
    extraction_case(d, "", NULL);
}

typedef struct { const char *key, *read_error, *send_error; int status, rc; br_slice body; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_url; char *read_storage, *transport_storage; unsigned char *body_storage;
    size_t arm_call, arm_size, arm_after, arm_push; bool arm_user_add;
} script;
static void url_value(const char *url, const char *expected_key)
{
    char expected[70]; CHECK(snprintf(expected, sizeof(expected), "https://www.eventbriteapi.com/v3/users/me/?token=%s", expected_key) == 69);
    CHECK(url && strlen(url) == 69 && !memcmp(url, expected, sizeof(expected)));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    CHECK(request->detector_type == 962 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, steps->suffix ? "TruffleHog eventbrite-offline" : "TruffleHog"));
    url_value(request->url, steps->rows[at].key); steps->borrowed_url = request->url;
    row *reply = &steps->rows[at];
    if (reply->read_error) { steps->read_storage = strdup(reply->read_error); CHECK(steps->read_storage); }
    if (reply->body.len) { steps->body_storage = malloc(reply->body.len); CHECK(steps->body_storage); memcpy(steps->body_storage, reply->body.data, reply->body.len); }
    http->response = (br_http_response){.status = reply->status, .body = {steps->body_storage, reply->body.len}, .body_error = steps->read_storage};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    steps->transport_storage = *error; /* Owned output: verifier may MOVE, rather than clone it. */
    if (steps->arm_call == http->calls) {
        fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; fail_user_add = steps->arm_user_add;
    }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    url_value(steps->borrowed_url, steps->rows[http->calls - 1].key); steps->borrowed_url = NULL;
    /* Pending decoded values/Reader causes MUST be independently owned before
     * release. Do not invalidate the transport's ALREADY-owned error output. */
    if (steps->transport_storage) CHECK(!strcmp(steps->transport_storage, steps->rows[http->calls - 1].send_error));
    if (steps->read_storage) memset(steps->read_storage, '!', strlen(steps->read_storage));
    if (steps->body_storage) memset(steps->body_storage, '!', response->body.len);
    free(steps->read_storage); free(steps->body_storage);
    steps->read_storage = steps->transport_storage = NULL; steps->body_storage = NULL;
    test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "eventbrite-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_url && !steps->read_storage && !steps->body_storage); return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}
static br_results one(const br_detector *d, int status, br_slice body, const char *read_error, const char *send_error, int send_rc)
{
    char input[48]; snprintf(input, sizeof(input), "eventbrite %s", key);
    script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = status, .body = body, .read_error = read_error, .send_error = send_error, .rc = send_rc};
    br_results out = run(d, input, &steps); CHECK(out.len == 1); return out;
}

static void exact_generic_map_success(const br_detector *d)
{
    const struct { br_slice body; const char *read; br_slice name; } cases[] = {
        {TEXT("{\"name\":\"offline\"}"), NULL, TEXT("offline")},
        {TEXT("{\"name\":\"\"}"), NULL, TEXT("")},
        {TEXT("{\"name\":\"λ\\u0000🌲\"}"), NULL, TEXT("λ\0🌲")},
        {TEXT("{\"name\":1,\"name\":\"ok\"}"), NULL, TEXT("ok")},
        {TEXT("{\"name\":null,\"name\":\"ok\"}"), NULL, TEXT("ok")},
        {TEXT("{\"name\":\"first\",\"name\":false,\"name\":\"last\"}"), NULL, TEXT("last")},
        {TEXT("{\"name\":[\"finite\"],\"name\":\"\"}"), NULL, TEXT("")},
        {TEXT("{\"name\":\"first\",\"Name\":null,\"name\\u0000x\":\"unrelated\"}"), NULL, TEXT("first")},
        {TEXT("{\"name\\u0000x\":\"wrong\",\"name\":\"right\",\"NAME\":false}"), NULL, TEXT("right")},
        {TEXT("{\"other\":1e-10000,\"name\":\"ok\"}"), NULL, TEXT("ok")},
        {TEXT("{\"name\":\"first\"}{\"other\":1e10000}\xff"), "ignored tail read", TEXT("first")},
        {TEXT("{\"name\":\"complete\"}"), "terminal read", TEXT("complete")},
        {TEXT("{\"name\":\"first\"}\0\xff"), NULL, TEXT("first")},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_results out = one(d, 200, cases[i].body, cases[i].read, NULL, 0);
        finding(&out.items[0], key, true, NULL, 1, cases[i].name); br_results_clear(&out);
    }
}

static void ordinary_decode_precedence(const br_detector *d)
{
    const struct { br_slice body; const char *read, *cause; } cases[] = {
        {TEXT(""), NULL, "EOF"}, {TEXT("{"), NULL, "unexpected EOF"},
        {TEXT("{\"other\":1e10000,\"name\":\"ok\"}"), NULL, "json: cannot unmarshal number 1e10000 into Go value of type float64"},
        {TEXT("{\"name\":1e10000,\"name\":\"ok\"}"), NULL, "json: cannot unmarshal number 1e10000 into Go value of type float64"},
        {TEXT("{\"other\":{\"n\":1e10000,\"n\":0},\"name\":\"ok\"}"), NULL, "json: cannot unmarshal number 1e10000 into Go value of type float64"},
        {TEXT("{\"other\":1e10000,\"other\":0,\"name\":\"ok\"}"), NULL, "json: cannot unmarshal number 1e10000 into Go value of type float64"},
        {TEXT("[1e10000]"), NULL, "json: cannot unmarshal array into Go value of type map[string]interface {}"},
        {TEXT("1e10000 "), NULL, "json: cannot unmarshal number into Go value of type map[string]interface {}"},
        {TEXT("{\"other\":1e10000,\"name\":@}"), NULL, "invalid character '@' looking for beginning of value"},
        {TEXT("{\"name\":\"ok\",\"other\":1e10000"), NULL, "unexpected EOF"},
        {TEXT("null"), "terminal scalar read", "terminal scalar read"},
        {TEXT("\"text\""), "terminal string read", "terminal string read"},
        {TEXT("{"), "", ""},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_results out = one(d, 200, cases[i].body, cases[i].read, NULL, 0);
        finding(&out.items[0], key, false, cases[i].cause, -1, (br_slice){0}); br_results_clear(&out);
    }
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
static void explicit_assertion_boundary(const br_detector *d)
{
    const br_slice cases[] = {TEXT("null"), TEXT("{}"), TEXT("{\"Name\":\"wrong-case\"}"),
        TEXT("{\"name\\u0000x\":\"not-name\"}"), TEXT("{\"name\":null}"), TEXT("{\"name\":true}"),
        TEXT("{\"name\":1}"), TEXT("{\"name\":[]}"), TEXT("{\"name\":{\"inside\":\"ok\"}}"),
        TEXT("{\"name\":\"good\",\"name\":null}"), TEXT("{\"name\":\"good\",\"name\":false}")};
    char input[48]; snprintf(input, sizeof(input), "eventbrite %s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .body = cases[i]};
        br_results out = caller_owned(); char *error = NULL; int rc = invoke(d, input, &steps, &out, &error);
        CHECK(error && strstr(error, "unsupported upstream panic: Eventbrite name string assertion")); rolled_back(&out, rc, error);
    }
}

static void statuses_zero_redaction_and_lifetimes(const br_detector *d)
{
    const int statuses[] = {0, 199, 201, 204, 299, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char cause[64]; snprintf(cause, sizeof(cause), "unexpected status code: %d", statuses[i]);
        br_results out = one(d, statuses[i], TEXT("\xff"), "ignored body read", NULL, 0);
        finding(&out.items[0], key, false, statuses[i] == 401 || statuses[i] == 403 ? NULL : cause, -1, (br_slice){0}); br_results_clear(&out);
    }
    char echo[220]; snprintf(echo, sizeof(echo), "reader at https://www.eventbriteapi.com/v3/users/me/?token=%s echoed %s", key, key);
    br_results out = one(d, 200, TEXT("{"), echo, NULL, 0);
    finding(&out.items[0], key, false, echo, -1, (br_slice){0}); br_results_clear(&out); /* ZERO redaction arguments. */
    const char *errors[] = {echo, "do not strip failed to make request: opaque cause", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        out = one(d, 200, TEXT("{\"name\":\"ignored\"}"), NULL, errors[i], i % 2 ? -1 : 1);
        finding(&out.items[0], key, false, errors[i] ? errors[i] : "HTTP transport failed", -1, (br_slice){0}); br_results_clear(&out);
    }
    char input[48]; snprintf(input, sizeof(input), "eventbrite %s", key);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, "net/http: nil Context", -1, (br_slice){0}); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, "HTTP transport not installed", -1, (br_slice){0}); br_results_clear(&out);
    script steps = {.count = 1, .suffix = true}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"name\":\"\"}")};
    out = run(d, input, &steps); finding(&out.items[0], key, true, NULL, 1, TEXT("")); br_results_clear(&out);
}

static void owned_resources_before_ordinary_replacement(const br_detector *d)
{
    char input[48]; snprintf(input, sizeof(input), "eventbrite %s", key);
    const size_t sizes[] = {21, 20};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures; fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    script steps = {.count = 1, .arm_call = 1, .arm_user_add = true}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"name\":\"\"}")};
    br_results out = caller_owned(); char *error = NULL; int rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_user_add); rolled_back(&out, rc, error); /* Pending metadata must be complete BEFORE caller state changes. */
    const char *leaf = "unredacted synthetic cause";
    for (size_t mode = 0; mode < 2; ++mode) {
        steps = (script){.count = 1, .arm_call = 1, .arm_after = 1}; steps.rows[0] = (row){.key = key, .status = mode ? 200 : 500};
        if (mode) { steps.rows[0].send_error = leaf; steps.rows[0].rc = 1; }
        steps.arm_size = strlen(mode ? leaf : "unexpected status code: 500") + 1;
        out = caller_owned(); error = NULL; size_t before = allocation_failures;
        rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error); /* Cause ownership, then caller setter +1 failure BEFORE replacement. */
    }
    /* Original integer-number token allocation is owned, not an ordinary
     * decode error or a reason to reach the later string assertion. */
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 2, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"name\":1,\"name\":\"ok\"}")};
    out = caller_owned(); error = NULL; size_t before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"name\":\"\"}")};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"name\":\"\xff\"}")};
    out = caller_owned(); error = NULL; rc = invoke(d, input, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported: Eventbrite invalid UTF-8 in consumed")); rolled_back(&out, rc, error);
}

static void late_invocation_rollback(const br_detector *d)
{
    char input[96]; snprintf(input, sizeof(input), "eventbrite %s\neventbrite %s", key, other);
    script steps = {.count = 2}; steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"name\":\"first\"}")};
    steps.rows[1] = (row){.key = other, .status = 200, .body = TEXT("{\"name\":null}")};
    br_results out = caller_owned(); char *error = NULL; int rc = invoke(d, input, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported upstream panic")); rolled_back(&out, rc, error);
    const char *leaf = "late ordinary transport error";
    steps = (script){.count = 2, .arm_call = 2, .arm_size = strlen(leaf) + 1, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"name\":\"first\"}")};
    steps.rows[1] = (row){.key = other, .status = 200, .rc = 1, .send_error = leaf};
    out = caller_owned(); error = NULL; size_t before = allocation_failures; rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    exact_generic_map_success(d);
    ordinary_decode_precedence(d);
    explicit_assertion_boundary(d);
    statuses_zero_redaction_and_lifetimes(d);
    owned_resources_before_ordinary_replacement(d);
    late_invocation_rollback(d);
    CHECK(!fail_after && !fail_user_add && !fail_push_size);
    return test_finish("Eventbrite");
}
