/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

static const char key[] = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp";
static const char other[] = "0123456789abcdefFEDCBA9876543210";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers;

/* Exercise actual native capture/finding/shared-HTTP/append resources. There
 * is intentionally no artificial allocation seam for the bounded stack auth. */
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
    size_t before = old ? malloc_usable_size(old) : 0;
    void *copy = malloc(size);
    if (copy) { if (old) memcpy(copy, old, before < size ? before : size); free(old); }
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_add_after && --fail_add_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && arm_http_headers && !strcmp(name, "key")) {
        /* Finish all real finding allocations before targeting shared setup. */
        arm_http_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1;
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32);
    CHECK(br_droneci_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_droneci_init(&d, &error) == 0 && d && !error);
    CHECK(br_droneci_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 135 && d->version == 0 && !strcmp(d->name, "DroneCI"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "DroneCI is a continuous integration service that automates the testing and deployment of applications. DroneCI tokens can be used to access and control CI/CD pipelines."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "droneci"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 135, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *d, br_slice input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input.data, input.len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[256], changed[34];
    extraction_case(d, text(key), NULL);
    const char *good[] = {"droneci %s", "DRONECI='%s'", "DrOnEcI\n%s", "xdroneci: (%s)", "droneci\r\n\t%s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, text(input), key); }
    snprintf(input, sizeof(input), "droneci %s", other); extraction_case(d, text(input), other);
    const char *bad[] = {"drone %s", "droneci _%s", "droneci x%s", "droneci %s_", "droneci %s9", "droneci %.31s"};
    for (size_t i = 0; i < 6; ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, text(input), NULL); }
    const char invalid[] = "_-./+";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, sizeof(key)); changed[16] = invalid[i];
        snprintf(input, sizeof(input), "droneci %s", changed); extraction_case(d, text(input), NULL);
    }
    memset(changed, 'A', 32); changed[32] = '\0'; snprintf(input, sizeof(input), "droneci %s", changed);
    extraction_case(d, text(input), changed); /* No entropy or additional token validation. */
    memset(input, ' ', sizeof(input)); memcpy(input, "droneci", 7); memcpy(input + 47, key, sizeof(key));
    extraction_case(d, text(input), key); /* Exactly 40 intervening characters. */
    memcpy(input + 48, key, sizeof(key)); input[47] = ' '; extraction_case(d, text(input), NULL);
    memset(input, ' ', sizeof(input)); memcpy(input, "droneci", 7); input[25] = '\n'; input[35] = '\r'; memcpy(input + 47, key, sizeof(key));
    extraction_case(d, text(input), key);
    /* Only matches of the complete prefixed regexp are occurrences: it does
     * not reuse an already-consumed keyword for a second bare token. */
    snprintf(input, sizeof(input), "droneci %s %s", key, other); extraction_case(d, text(input), key);
    input[0] = '\0'; memcpy(input + 1, "droneci ", 8); memcpy(input + 9, key, 32); input[41] = (char)0xff;
    extraction_case(d, (br_slice){(unsigned char *)input, 42}, key);
    extraction_case(d, (br_slice){0}, NULL);
    snprintf(input, sizeof(input), "droneci %s\nDRONECI %s\ndroneci %s", key, other, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, false); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; br_slice body; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth;
    size_t arm_call, arm_size, arm_after, arm_push;
} script;

static void authorization(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 39 && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, expected, 33)); /* Includes the complete final NUL. */
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == at);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 135 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://cloud.drone.io/api/user"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, reply->key); steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog droneci-offline" : "TruffleHog"));
    http->response = (br_http_response){.status = reply->status, .body = reply->body, .body_error = reply->read_error};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    authorization(steps->borrowed_auth, steps->rows[http->calls - 1].key); steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "droneci-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases && !steps->borrowed_auth); return rc;
}

static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_read_and_send_policy(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "droneci %s", key);
    /* Every 2xx, regardless of invalid/binary body and empty/nonempty read error. */
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = status, .body = TEXT("not-json\0\xff"), .read_error = status % 2 ? "ignored read" : ""};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1); finding(&out.items[0], key, true); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = statuses[i], .body = TEXT("\xff"), .read_error = "ignored"};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    char occurrences[192]; snprintf(occurrences, sizeof(occurrences), "droneci %s\nDRONECI %s\ndroneci %s", key, other, key);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = key, .status = 401}; steps.rows[1] = (row){.key = other, .status = 299}; steps.rows[2] = (row){.key = key, .status = 200};
    br_results out = run(d, text(occurrences), &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, true); finding(&out.items[2], key, true); br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[64]; snprintf(input, sizeof(input), "droneci %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures;
    /* A finding also makes 32-byte allocations. Arm only AFTER its final part
     * insertion so the real shared header-array failure cannot hit ownership
     * resources instead. This is not a heap allocation for the stack Bearer. */
    arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
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

static void own_failure_rollback(const br_detector *d)
{
    char input[160]; snprintf(input, sizeof(input), "droneci %s", key);
    /* Capture/finding errors must not become nil-context skips. */
    const size_t sizes[] = {33, 32};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    /* Force append growth while retaining an existing caller-owned finding. */
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; size_t before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    /* The second finding fails after the first has been sent AND appended. */
    snprintf(input, sizeof(input), "droneci %s\ndroneci %s", key, other);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 32, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    status_read_and_send_policy(d);
    shared_setup_suppressed(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !arm_http_headers);
    return test_finish("DroneCI");
}
