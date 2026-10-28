/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static const char key[] = "AaBbCcDdEeFfGgHh0011";
static const char lower[] = "aabbccddeeffgghh0011";
static const char other[] = "0123456789aBcDeFgHjK";
static const char guide[] = "https://howtorotate.com/docs/tutorials/eraser/";
static const char payload[] = "{\"elements\":[{\"type\":\"diagram\"}]}";
static size_t fail_size, fail_after, allocation_failures, fail_guide_after, fail_push_size, guides_added;
static bool arm_shared_headers, arm_nil_setter;

/* Actual native resource boundaries. Static body/stack Bearer need no heap
 * copy or artificial formatting-failure seam. */
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
    bool rotation = !strcmp(name, "rotation_guide");
    if (rotation && fail_guide_after && --fail_guide_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && rotation) {
        ++guides_added;
        if (arm_shared_headers) { arm_shared_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1; }
        if (arm_nil_setter) { arm_nil_setter = false; fail_size = sizeof("net/http: nil Context"); fail_after = 1; }
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 20 && strlen(lower) == 20 && strlen(other) == 20 && strlen(payload) == 33);
    CHECK(br_eraser_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_eraser_init(&d, &error) == 0 && d && !error);
    CHECK(br_eraser_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 990 && d->version == 0 && !strcmp(d->name, "Eraser") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Eraser is a tool used for generating diagrams from DSL. Eraser API tokens can be used to authenticate and interact with the Eraser API."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "eraser"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void finding(const br_result *r, const char *expected, bool verified, bool verification_ran, const char *cause)
{
    CHECK(r->detector_type == 990 && !r->detector_name && r->raw.len == 20 && !memcmp(r->raw.data, expected, 20));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->redacted && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->verification_from_cache && !r->chunk_offset && !r->chunk_offset_set && r->verified == verified);
    CHECK((r->verification_error != NULL) == (cause != NULL)); if (cause) CHECK(!strcmp(r->verification_error, cause));
    br_json *part = NULL; CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && json_object_is_type(part, json_type_string));
    CHECK(json_object_get_string_len(part) == 20 && !memcmp(json_object_get_string(part), expected, 20));
    if (verification_ran) CHECK(!r->extra_data); /* ALL verification outcomes replace the guide with nil. */
    else {
        CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
        CHECK(json_object_object_get_ex(r->extra_data, "rotation_guide", &part) && json_object_is_type(part, json_type_string));
        CHECK(!strcmp(json_object_get_string(part), guide));
    }
}
static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    size_t before = guides_added; br_results out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && guides_added == before + out.len);
    if (expected) finding(&out.items[0], expected, false, false, NULL);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    char input[240], changed[22]; extraction_case(d, key, NULL);
    const char *good[] = {"eraser %s", "ERASER='%s'", "ErAsEr\r\n%s", "otheraseraser:%s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, input, key); }
    const char *bad[] = {"erase %s", "eraser _%s", "eraser %s_", "eraser %s0", "eraser %.19s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, input, NULL); }
    memcpy(changed, key, sizeof(key)); changed[10] = '_'; snprintf(input, sizeof(input), "eraser %s", changed); extraction_case(d, input, NULL);
    memset(changed, 'A', 20); changed[20] = '\0'; snprintf(input, sizeof(input), "eraser %s", changed); extraction_case(d, input, changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "eraser", 6); memset(input + 6, ' ', gap); memcpy(input + 6 + gap, key, sizeof(key)); extraction_case(d, input, gap == 40 ? key : NULL);
    }
    snprintf(input, sizeof(input), "eraser %s\neraser %s\nERASER %s\neraser %s", key, lower, key, other);
    size_t before = guides_added; br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3 && guides_added == before + 3);
    finding(&out.items[0], key, false, false, NULL); finding(&out.items[1], lower, false, false, NULL); finding(&out.items[2], other, false, false, NULL);
    CHECK(out.items[0].extra_data != out.items[1].extra_data && out.items[0].raw.data != out.items[1].raw.data); br_results_clear(&out);
    extraction_case(d, "", NULL);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; } row;
typedef struct {
    row rows[3]; size_t count, guide_start; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; br_slice borrowed_body; char *transport_storage;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;
static void request_values(const script *steps, const row *reply)
{
    CHECK(steps->borrowed_auth && strlen(steps->borrowed_auth) == 27 && !memcmp(steps->borrowed_auth, "Bearer ", 7));
    CHECK(!memcmp(steps->borrowed_auth + 7, reply->key, 21));
    CHECK(steps->borrowed_body.data && steps->borrowed_body.len == 33 && !memcmp(steps->borrowed_body.data, payload, sizeof(payload)));
}
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    CHECK(guides_added == steps->guide_start + http->calls); /* Even though every guide will be discarded. */
    CHECK(request->detector_type == 990 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://app.eraser.io/api/render/elements"));
    CHECK(request->nheaders == 3 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[1].name, "Content-Type") && !strcmp(request->headers[1].value, "application/json"));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog eraser-offline" : "TruffleHog"));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    steps->borrowed_auth = request->headers[0].value; steps->borrowed_body = request->body; request_values(steps, &steps->rows[at]);
    row *reply = &steps->rows[at]; http->response = (br_http_response){.status = reply->status, .body = TEXT("not JSON\0\xff"), .body_error = reply->read_error};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}
static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    steps->transport_storage = *error;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    return rc;
}
static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user; request_values(steps, &steps->rows[http->calls - 1]);
    steps->borrowed_auth = NULL; steps->borrowed_body = (br_slice){0};
    if (steps->transport_storage) memset(steps->transport_storage, '!', strlen(steps->transport_storage));
    steps->transport_storage = NULL; test_http_release(user, response);
}
static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "eraser-offline" : NULL}; steps->ctx = &ctx; steps->guide_start = guides_added;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_auth && !steps->borrowed_body.data); return rc;
}
static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void verification_replaces_extra_and_retains_causes(const br_detector *d)
{
    char input[220]; snprintf(input, sizeof(input), "eraser %s", key);
    const int statuses[] = {0, 199, 200, 201, 204, 299, 300, 400, 401, 403, 500, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = statuses[i], .read_error = i % 2 ? "ignored body read/drain error" : ""};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        char cause[80]; snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        finding(&out.items[0], key, statuses[i] == 200, true, statuses[i] == 200 || statuses[i] == 401 ? NULL : cause); br_results_clear(&out);
    }
    char echoed[180]; snprintf(echoed, sizeof(echoed), "do not strip failed to make request: %s / %s", key, key);
    const char *errors[] = {echoed, "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < 4; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false, true, i == 0 ? "do not strip failed to make request: [REDACTED] / [REDACTED]" : errors[i] ? errors[i] : "HTTP transport failed"); br_results_clear(&out);
    }
    size_t before = guides_added; br_results out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 1 && guides_added == before + 1);
    finding(&out.items[0], key, false, true, "net/http: nil Context"); br_results_clear(&out);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    before = allocation_failures; arm_shared_headers = true;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(!arm_shared_headers && !fail_after && allocation_failures == before + 1 && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, true, "out of memory constructing HTTP headers"); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, true, "HTTP transport not installed"); br_results_clear(&out);
    snprintf(input, sizeof(input), "eraser %s\nERASER %s\neraser %s", key, other, key);
    script steps = {.count = 2, .suffix = true}; steps.rows[0] = (row){.key = key, .status = 200}; steps.rows[1] = (row){.key = other, .status = 401};
    out = run(d, input, &steps); CHECK(out.len == 2); finding(&out.items[0], key, true, true, NULL); finding(&out.items[1], other, false, true, NULL); br_results_clear(&out);
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
static void owned_resources_before_metadata_replacement(const br_detector *d)
{
    char input[180]; snprintf(input, sizeof(input), "eraser %s", key);
    /* A doomed-to-disappear guide MUST still be allocated and checked. */
    for (size_t verify = 0; verify < 2; ++verify) {
        br_results out = caller_owned(); char *error = NULL; fail_guide_after = 1;
        int rc = d->scan(d, NULL, verify != 0, text(input), &out, &error); CHECK(!fail_guide_after); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures; arm_nil_setter = true;
    int rc = d->scan(d, NULL, true, text(input), &out, &error);
    CHECK(!arm_nil_setter && !fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    const size_t sizes[] = {21, 20};
    for (size_t i = 0; i < 2; ++i) {
        out = caller_owned(); error = NULL; before = allocation_failures; fail_size = sizes[i]; fail_after = 1;
        rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    const char *leaf = "distinct synthetic send cause";
    script steps = {.count = 1, .arm_call = 1, .arm_size = strlen(leaf) + 1, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200, .rc = 1, .send_error = leaf};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error); /* Setter +1 must be fatal. */
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)}; steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    /* Earlier candidate has already lost its guide and been appended. A later
     * failure still rolls back the WHOLE invocation, not caller-owned results. */
    snprintf(input, sizeof(input), "eraser %s\neraser %s", key, other);
    steps = (script){.count = 2, .arm_call = 2, .arm_size = strlen(leaf) + 1, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200}; steps.rows[1] = (row){.key = other, .status = 200, .rc = 1, .send_error = leaf};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error); CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification_replaces_extra_and_retains_causes(d);
    owned_resources_before_metadata_replacement(d);
    CHECK(!fail_after && !fail_guide_after && !fail_push_size && !arm_shared_headers && !arm_nil_setter);
    return test_finish("Eraser");
}
