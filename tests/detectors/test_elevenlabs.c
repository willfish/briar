/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

#define HEX16 "0123456789abcdef"
static const char lower[] = HEX16 HEX16;
static const char upper[] = "0123456789ABCDEF0123456789ABCDEF";
static const char other[] = "fedcba9876543210fedcba9876543210";
static const char v2_key[] = "sk_" HEX16 HEX16 HEX16;
static const char rotation[] = "https://howtorotate.com/docs/tutorials/elevenlabs/";
static size_t fail_size, fail_after, allocation_failures, fail_push_size, fail_field_after;
static const char *fail_field;

/* Real native resource boundaries, not new provider/API failure seams. */
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
    return json_object_object_add_ex(object, name, value, 0);
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static const char *key_for(const br_detector *d) { return d->version == 1 ? lower : v2_key; }

static const br_detector *descriptor(int version)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    int (*init)(const br_detector **, char **) = version == 1 ? br_elevenlabs_v1_init : br_elevenlabs_v2_init;
    CHECK(BR_ABI_REVISION == 1 && strlen(lower) == 32 && strlen(upper) == 32 && strlen(v2_key) == 51);
    CHECK(init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(init(&d, &error) == 0 && d && !error);
    CHECK(init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 994 && d->version == version && !strcmp(d->name, "ElevenLabs") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, version == 1 ?
        "Elevenlabs is an AI-driven voice synthesis platform. Elevenlabs API keys can be used to access and manipulate voice synthesis features and services." :
        "ElevenLabs is a service that provides API keys for accessing their voice synthesis and other AI-powered tools. These keys can be used to interact with ElevenLabs' services programmatically."));
    CHECK(d->nkeywords == 3 && !strcmp(d->keywords[0], "elevenlabs") && !strcmp(d->keywords[1], "xi-api-key") && !strcmp(d->keywords[2], "xi_api_key"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void string_field(br_json *object, const char *name, br_slice expected)
{
    br_json *value = NULL; CHECK(object && json_object_object_get_ex(object, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == expected.len && (!expected.len || !memcmp(json_object_get_string(value), expected.data, expected.len)));
}
static void finding(const br_detector *d, const br_result *r, const char *key, bool verified,
                      const char *cause, bool user, br_slice name, br_slice tier)
{
    CHECK(r->detector_type == 994 && !r->detector_name && r->raw.len == strlen(key) && !memcmp(r->raw.data, key, r->raw.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->verification_from_cache && !r->chunk_offset && !r->chunk_offset_set && r->verified == verified);
    CHECK((r->verification_error != NULL) == (cause != NULL)); if (cause) CHECK(!strcmp(r->verification_error, cause));
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1); string_field(r->secret_parts, "key", text(key));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == (d->version == 1 ? 2 : 1) + (user ? 2 : 0));
    string_field(r->extra_data, "version", d->version == 1 ? TEXT("1") : TEXT("2"));
    if (d->version == 1) string_field(r->extra_data, "rotation_guide", text(rotation));
    else { br_json *unused = NULL; CHECK(!json_object_object_get_ex(r->extra_data, "rotation_guide", &unused)); }
    if (user) { string_field(r->extra_data, "Name", name); string_field(r->extra_data, "Tier", tier); }
    else { br_json *unused = NULL; CHECK(!json_object_object_get_ex(r->extra_data, "Name", &unused) && !json_object_object_get_ex(r->extra_data, "Tier", &unused)); }
}
static char *input_for(const br_detector *d, const char *key)
{
    size_t size = strlen(key) + 16; char *out = malloc(size); CHECK(out);
    snprintf(out, size, d->version == 1 ? "tokenx: %s" : "%s", key); return out;
}
static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == (expected ? 1u : 0u));
    if (expected) finding(d, &out.items[0], expected, false, NULL, false, (br_slice){0}, (br_slice){0});
    br_results_clear(&out);
}
static void extraction(const br_detector *v1, const br_detector *v2)
{
    char input[300], changed[60];
    extraction_case(v1, lower, NULL);
    const char *good[] = {"TOKENx:%s", "KEY::%s", "key\n %s", "monkeyx:%s", "ELEVENLABS : %s", "xi-api-key = %s"};
    for (size_t i = 0; i < sizeof(good) / sizeof(*good); ++i) { snprintf(input, sizeof(input), good[i], upper); extraction_case(v1, input, upper); }
    const char *bad[] = {"token %s", "token:%s", "token. :%s", "tokenx\n %s", "tokenx\t%s", "tokenx:%s_", "tokenx:%s0"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i) { snprintf(input, sizeof(input), bad[i], lower); extraction_case(v1, input, NULL); }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "tokenx", 6); memset(input + 6, 'Z', gap); input[6 + gap] = ':'; memcpy(input + 7 + gap, lower, sizeof(lower));
        extraction_case(v1, input, gap == 40 ? lower : NULL);
    }
    snprintf(input, sizeof(input), "tokenx %s %s", lower, other); extraction_case(v1, input, other); /* Source GREEDY gap selects last eligible capture. */
    snprintf(input, sizeof(input), "tokenx:%s\ntokenx:%s\ntokenx:%s", lower, upper, lower);
    br_results out = test_scan(v1, NULL, false, input, strlen(input)); CHECK(out.len == 2);
    finding(v1, &out.items[0], lower, false, NULL, false, (br_slice){0}, (br_slice){0});
    finding(v1, &out.items[1], upper, false, NULL, false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    extraction_case(v2, v2_key, v2_key); /* DIRECT, independent of dispatch keywords. */
    snprintf(input, sizeof(input), "(%s)", v2_key); extraction_case(v2, input, v2_key);
    memcpy(changed, v2_key, sizeof(v2_key)); changed[0] = 'S'; extraction_case(v2, changed, NULL);
    memcpy(changed, v2_key, sizeof(v2_key)); changed[15] = 'A'; extraction_case(v2, changed, NULL);
    memcpy(changed, v2_key, sizeof(v2_key)); changed[15] = 'g'; extraction_case(v2, changed, NULL);
    snprintf(input, sizeof(input), "_%s", v2_key); extraction_case(v2, input, NULL);
    snprintf(input, sizeof(input), "%s_", v2_key); extraction_case(v2, input, NULL);
    snprintf(input, sizeof(input), "%s\n%s", v2_key, v2_key); extraction_case(v2, input, v2_key);
    extraction_case(v1, "", NULL); extraction_case(v2, "", NULL);
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
    CHECK(request->detector_type == 994 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.elevenlabs.io/v1/user"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "xi-api-key"));
    CHECK(!strcmp(request->headers[0].value, steps->rows[at].key)); steps->borrowed_key = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog elevenlabs-offline" : "TruffleHog"));
    row *reply = &steps->rows[at];
    if (reply->read_error) { steps->read_storage = strdup(reply->read_error); CHECK(steps->read_storage); }
    if (reply->body.len) { steps->body_storage = malloc(reply->body.len); CHECK(steps->body_storage); memcpy(steps->body_storage, reply->body.data, reply->body.len); }
    http->response = (br_http_response){.status = reply->status, .body = {steps->body_storage, reply->body.len}, .body_error = steps->read_storage};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    steps->transport_storage = *error;
    if (steps->arm_call == http->calls) {
        fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push;
        if (steps->arm_field) { fail_field = steps->arm_field; fail_field_after = 1; }
    }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    CHECK(steps->borrowed_key && !strcmp(steps->borrowed_key, steps->rows[http->calls - 1].key)); steps->borrowed_key = NULL;
    /* Causes are sanitized/copied, decoded strings retained, BEFORE release. */
    if (steps->read_storage) memset(steps->read_storage, '!', strlen(steps->read_storage));
    if (steps->transport_storage) memset(steps->transport_storage, '!', strlen(steps->transport_storage));
    if (steps->body_storage) memset(steps->body_storage, '!', response->body.len);
    free(steps->read_storage); free(steps->body_storage);
    steps->read_storage = steps->transport_storage = NULL; steps->body_storage = NULL;
    test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "elevenlabs-offline" : NULL}; steps->ctx = &ctx;
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
    const char *key = key_for(d); char *input = input_for(d, key); script steps = {.count = 1};
    steps.rows[0] = (row){.key = key, .status = status, .body = body, .read_error = read_error, .send_error = send_error, .rc = send_rc};
    br_results out = run(d, input, &steps); CHECK(out.len == 1); free(input); return out;
}

static void typed_first_document(const br_detector *d)
{
    const struct { br_slice body; const char *read, *cause; br_slice name, tier; } cases[] = {
        {TEXT("null"), NULL, NULL, TEXT(""), TEXT("")}, {TEXT("{}"), NULL, NULL, TEXT(""), TEXT("")},
        {TEXT("{\"first_name\":\"offline\",\"subscription\":{\"tier\":\"synthetic\"}}"), NULL, NULL, TEXT("offline"), TEXT("synthetic")},
        {TEXT("{\"FIRST_NAME\":\"first\",\"first_name\":null,\"subscription\":{\"tier\":\"first\"},\"SUBSCRIPTION\":{},\"subscription\":null}"), NULL, NULL, TEXT("first"), TEXT("first")},
        {TEXT("{\"first_name\":\"old\",\"first_name\":\"\",\"subscription\":{\"tier\":\"old\",\"TIER\":null},\"subscription\":{\"tier\":\"new\"}}"), NULL, NULL, TEXT(""), TEXT("new")},
        {TEXT("{\"fir\\u017ft_name\":\"λ\\u0000🌲\",\"\\u017fubscription\":{\"tier\":\"\\u0000\"}}"), NULL, NULL, TEXT("λ\0🌲"), TEXT("\0")},
        {TEXT("{\"first_name\\u0000x\":false,\"subscription\\u0000x\":false,\"subscription\":{\"tier\\u0000x\":false}}"), NULL, NULL, TEXT(""), TEXT("")},
        {TEXT("{\"unknown\":1e10000,\"subscription\":{\"unused\":1e10000}}{}\xff"), "ignored tail read", NULL, TEXT(""), TEXT("")},
        {TEXT("{\"first_name\":\"complete\"}"), "terminal read", NULL, TEXT("complete"), TEXT("")},
        {TEXT("{}\0\xff"), NULL, NULL, TEXT(""), TEXT("")},
        {TEXT("null "), "after separator", NULL, TEXT(""), TEXT("")},
        {TEXT("null"), "terminal scalar read", "terminal scalar read", {0}, {0}},
        {TEXT("[]"), NULL, "json: cannot unmarshal array into Go value of type elevenlabs.UserRes", {0}, {0}},
        {TEXT("\"text\" "), NULL, "json: cannot unmarshal string into Go value of type elevenlabs.UserRes", {0}, {0}},
        {TEXT("\"text\""), "terminal string read", "terminal string read", {0}, {0}},
        {TEXT("{\"first_name\":true,\"first_name\":\"later\",\"subscription\":{\"tier\":7}}"), NULL,
            "json: cannot unmarshal bool into Go struct field UserRes.first_name of type string", {0}, {0}},
        {TEXT("{\"first_name\":\"discarded\",\"subscription\":false,\"subscription\":{\"tier\":\"later\"}}"), NULL,
            "json: cannot unmarshal bool into Go struct field UserRes.subscription of type struct { Tier string \"json:\\\"tier\\\"\" }", {0}, {0}},
        {TEXT("{\"first_name\":\"discarded\",\"subscription\":{\"tier\":7,\"tier\":\"later\"}}"), NULL,
            "json: cannot unmarshal number into Go struct field .subscription.tier of type string", {0}, {0}},
        {TEXT(""), NULL, "EOF", {0}, {0}}, {TEXT("{"), NULL, "unexpected EOF", {0}, {0}},
        {TEXT("{"), "incomplete read", "incomplete read", {0}, {0}},
        {TEXT(""), "", "", {0}, {0}},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        br_results out = one(d, 200, cases[i].body, cases[i].read, NULL, 0);
        finding(d, &out.items[0], key_for(d), cases[i].cause == NULL, cases[i].cause, cases[i].cause == NULL, cases[i].name, cases[i].tier);
        br_results_clear(&out);
    }
}

static void statuses_and_error_lifetimes(const br_detector *d)
{
    const int statuses[] = {0, 199, 201, 204, 299, 300, 400, 401, 403, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        br_results out = one(d, statuses[i], TEXT("\xff"), "ignored read", NULL, 0);
        finding(d, &out.items[0], key_for(d), false, statuses[i] == 400 || statuses[i] == 401 ? NULL : cause, false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    }
    char echoed[256]; snprintf(echoed, sizeof(echoed), "read %s and %s", key_for(d), key_for(d));
    br_results out = one(d, 200, TEXT("{"), echoed, NULL, 0);
    finding(d, &out.items[0], key_for(d), false, "read [REDACTED] and [REDACTED]", false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    snprintf(echoed, sizeof(echoed), "do not strip failed to make request: %s", key_for(d));
    out = one(d, 200, TEXT("{}"), NULL, echoed, 1);
    finding(d, &out.items[0], key_for(d), false, "do not strip failed to make request: [REDACTED]", false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    out = one(d, 200, TEXT("{}"), NULL, "", -1); finding(d, &out.items[0], key_for(d), false, "", false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    char *input = input_for(d, key_for(d)); out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 1);
    finding(d, &out.items[0], key_for(d), false, "net/http: nil Context", false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    finding(d, &out.items[0], key_for(d), false, "HTTP transport not installed", false, (br_slice){0}, (br_slice){0}); br_results_clear(&out);
    script steps = {.count = 1, .suffix = true}; steps.rows[0] = (row){.key = key_for(d), .status = 200, .body = TEXT("{}")};
    out = run(d, input, &steps); finding(d, &out.items[0], key_for(d), true, NULL, true, TEXT(""), TEXT("")); br_results_clear(&out); free(input);
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
    char *input = input_for(d, key_for(d));
    const char *base_fields[] = {"version", "rotation_guide"};
    for (size_t i = 0; i < (d->version == 1 ? 2u : 1u); ++i) {
        br_results out = caller_owned(); char *error = NULL; fail_field = base_fields[i]; fail_field_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_field_after); rolled_back(&out, rc, error); /* Always-owned metadata BEFORE constructor. */
    }
    const size_t lengths[] = {strlen(key_for(d)) + 1, strlen(key_for(d))};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures; fail_size = lengths[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    const char *leaf = "distinct incomplete reader failure";
    for (size_t allocation = 1; allocation <= 2; ++allocation) {
        script steps = {.count = 1, .arm_call = 1, .arm_size = strlen(leaf) + 1, .arm_after = allocation};
        steps.rows[0] = (row){.key = key_for(d), .status = 200, .body = TEXT("{"), .read_error = leaf};
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        int rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error); /* Decoder cause copy, then +1 setter resource failure. */
    }
    const char *type_cause = "json: cannot unmarshal bool into Go struct field UserRes.first_name of type string";
    script steps = {.count = 1, .arm_call = 1, .arm_size = strlen(type_cause) + 1, .arm_after = 1};
    steps.rows[0] = (row){.key = key_for(d), .status = 200, .body = TEXT("{\"first_name\":true}")};
    br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
    int rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    const char *user_fields[] = {"Name", "Tier"};
    for (size_t i = 0; i < 2; ++i) {
        steps = (script){.count = 1, .arm_call = 1, .arm_field = user_fields[i]};
        steps.rows[0] = (row){.key = key_for(d), .status = 200, .body = TEXT("null")};
        out = caller_owned(); error = NULL; rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_field_after); rolled_back(&out, rc, error);
    }
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key_for(d), .status = 200, .body = TEXT("{}")};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1}; steps.rows[0] = (row){.key = key_for(d), .status = 200, .body = TEXT("{\"first_name\":\"\xff\"}")};
    out = caller_owned(); error = NULL; rc = invoke(d, input, &steps, &out, &error);
    CHECK(error && strstr(error, "unsupported: ElevenLabs invalid UTF-8 in consumed")); rolled_back(&out, rc, error);
    free(input);
}

static void invocation_rollback_after_prior_append(const br_detector *v1)
{
    char input[160]; snprintf(input, sizeof(input), "tokenx:%s\ntokenx:%s", lower, upper);
    const char *leaf = "second candidate reader error";
    script steps = {.count = 2, .arm_call = 2, .arm_size = strlen(leaf) + 1, .arm_after = 2};
    steps.rows[0] = (row){.key = lower, .status = 200, .body = TEXT("{}")};
    steps.rows[1] = (row){.key = upper, .status = 200, .body = TEXT("{"), .read_error = leaf};
    br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
    int rc = invoke(v1, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
}

int main(void)
{
    const br_detector *v1 = descriptor(1), *v2 = descriptor(2);
    extraction(v1, v2);
    typed_first_document(v1); typed_first_document(v2);
    statuses_and_error_lifetimes(v1); statuses_and_error_lifetimes(v2);
    owned_resources_and_consumed_boundary(v1); owned_resources_and_consumed_boundary(v2);
    invocation_rollback_after_prior_append(v1);
    CHECK(!fail_after && !fail_field_after && !fail_push_size);
    return test_finish("ElevenLabs v1/v2");
}
