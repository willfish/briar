/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_lemonsqueezy_init(const br_detector **out, char **error);

static char key[865], other[865];
static const char url[] = "https://api.lemonsqueezy.com/v1/products/";
static const char header[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_auth, arm_setter, fail_next_malloc;
static size_t setter_fail_size;

static void fill_key(char *out, char marker)
{
    static const char payload[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static const char signature[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";
    memcpy(out, header, 36);
    out[36] = '.';
    for (int i = 0; i < 314; ++i) out[37 + i] = payload[(i + (unsigned char)marker) % 62];
    out[351] = '.';
    for (int i = 0; i < 512; ++i) out[352 + i] = signature[(i + (unsigned char)marker) % 64];
    out[360] = '-';
    out[361] = '_';
    out[863] = 'Z';
    out[864] = '\0';
}

void *malloc(size_t size)
{
    if (fail_next_malloc) { fail_next_malloc = false; ++allocation_failures; return NULL; }
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
    if (!rc && !strcmp(name, "key")) {
        if (arm_http_headers) { arm_http_headers = false; fail_size = 2 * sizeof(br_header); fail_after = 1; }
        if (arm_auth) { arm_auth = false; fail_size = 7 + 864 + 1; fail_after = 1; }
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(key, 1); fill_key(other, 9);
    CHECK(BR_ABI_REVISION == 1 && strlen(header) == 36 && strlen(key) == 864 && strlen(other) == 864);
    CHECK(strcmp(key, other) && key[360] == '-' && key[361] == '_' && key[863] == 'Z');
    CHECK(!strcmp(url, "https://api.lemonsqueezy.com/v1/products/") && url[strlen(url) - 1] == '/');
    CHECK(br_lemonsqueezy_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_lemonsqueezy_init(&d, &error) == 0 && d && !error);
    CHECK(br_lemonsqueezy_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 952 && d->version == 0 && !strcmp(d->name, "LemonSqueezy"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "LemonSqueezy is a platform for selling digital products. Its API tokens can be used to manage products, orders, and other resources."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "lemonsqueezy"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 952, expected, "key");
    CHECK(result->verified == verified);
}

static void extraction_case(const br_detector *d, br_slice input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input.data, input.len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) { finding(&out.items[0], expected, false); CHECK(!out.items[0].verification_error); }
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[4096], broken[865];
    extraction_case(d, text(key), NULL);
    const char *good[] = {"lemonsqueezy %s", "LEMONSQUEEZY='%s'", "LemonSqueezy\n%s", "xlemonsqueezy: (%s)"};
    for (size_t i = 0; i < 4; ++i) {
        snprintf(input, sizeof(input), good[i], key); extraction_case(d, text(input), key);
        snprintf(input, sizeof(input), good[i], other); extraction_case(d, text(input), other);
    }
    const char *bad[] = {"squeezy %s", "lemon %s", "lemonsqueezy%s"};
    for (size_t i = 0; i < 3; ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, text(input), NULL); }
    memcpy(broken, key, 865); broken[37] = '-';
    snprintf(input, sizeof(input), "lemonsqueezy %s", broken); extraction_case(d, text(input), NULL);
    memcpy(broken, key, 865); broken[400] = '+';
    snprintf(input, sizeof(input), "lemonsqueezy %s", broken); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "lemonsqueezy %.*s", 863, key); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "lemonsqueezy %sA", key); extraction_case(d, text(input), NULL);
    char gap[1024];
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "lemonsqueezy", 12); memcpy(gap + 52, key, 864);
    extraction_case(d, (br_slice){(unsigned char *)gap, 916}, key);
    memcpy(gap + 53, key, 864); gap[52] = ' ';
    extraction_case(d, (br_slice){(unsigned char *)gap, 917}, NULL);
    snprintf(input, sizeof(input), "lemonsqueezy %s %s", key, other); extraction_case(d, text(input), key);
    snprintf(input, sizeof(input), "lemonsqueezy %s\nLEMONSQUEEZY %s\nlemonsqueezy %s", key, other, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, false); finding(&out.items[2], key, false);
    CHECK(!out.items[0].verification_error && !out.items[1].verification_error && !out.items[2].verification_error);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; br_slice body; } row;
typedef struct {
    const char *auth, *key;
    bool prove_setter;
} held;
typedef struct {
    row rows[4]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth;
    size_t arm_call, arm_size, arm_after, arm_push;
    /* Successful Do stays here until scan return. Failed sends do not. */
    held deferred[4]; size_t deferred_len; size_t failed_sends;
    bool immediate, immediate_setter, retain_fails, released_before_setter, saw_setter_before_release;
    const char *immediate_auth, *immediate_key;
    const char *released_keys[4]; size_t release_n;
    size_t setter_baseline;
} script;

static void authorization(const char *value, const char *expected)
{
    CHECK(expected && strlen(expected) == 864 && value && strlen(value) == 7 + 864);
    CHECK(!memcmp(value, "Bearer ", 7) && !memcmp(value + 7, expected, 865));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    /* Only earlier failed sends have released. A successful response stays open. */
    CHECK(at < steps->count && at < 4 && ctx == steps->ctx && http->releases == steps->failed_sends);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 952 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, reply->key); steps->borrowed_auth = request->headers[0].value;
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog lemonsqueezy-offline" : "TruffleHog"));
    http->response = (br_http_response){.status = reply->status, .body = reply->body, .body_error = reply->read_error};
    http->send_rc = reply->rc; http->send_error = reply->send_error;
}

static int send_reply(void *user, const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    int rc = test_http_send(user, ctx, request, response, error); test_http *http = user; script *steps = http->user;
    if (steps->arm_call == http->calls) { fail_size = steps->arm_size; fail_after = steps->arm_after; fail_push_size = steps->arm_push; }
    row *reply = &steps->rows[http->calls - 1];
    bool failed = reply->rc != 0;
    bool retain_this = steps->retain_fails && !failed && http->calls == steps->count;
    if (failed || retain_this) {
        steps->immediate = true; steps->immediate_auth = steps->borrowed_auth; steps->immediate_key = reply->key;
        if (failed) ++steps->failed_sends;
        if (retain_this) fail_next_malloc = true;
    } else {
        CHECK(steps->deferred_len < 4);
        steps->deferred[steps->deferred_len++] = (held){.auth = steps->borrowed_auth, .key = reply->key};
    }
    /* Arm the setter from send return, never from the release hook. */
    if (arm_setter) {
        arm_setter = false; fail_size = setter_fail_size; fail_after = 1; steps->setter_baseline = allocation_failures;
        if (failed) steps->immediate_setter = true;
        else if (!retain_this && steps->deferred_len) steps->deferred[steps->deferred_len - 1].prove_setter = true;
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    const char *auth = NULL, *expected = NULL; bool prove = false;
    if (steps->immediate) {
        auth = steps->immediate_auth; expected = steps->immediate_key; steps->immediate = false;
        if (steps->immediate_setter) {
            CHECK(fail_after == 1); steps->released_before_setter = true; steps->immediate_setter = false;
        }
        for (size_t i = 0; i < steps->deferred_len; ++i) {
            CHECK(steps->deferred[i].auth != auth);
            authorization(steps->deferred[i].auth, steps->deferred[i].key);
        }
    } else {
        CHECK(steps->deferred_len);
        held item = steps->deferred[--steps->deferred_len];
        auth = item.auth; expected = item.key; prove = item.prove_setter;
    }
    /* This is the Bearer of the response being released, still complete. */
    authorization(auth, expected);
    if (prove) {
        CHECK(!fail_after && allocation_failures > steps->setter_baseline);
        steps->saw_setter_before_release = true;
    }
    if (steps->release_n < 4) steps->released_keys[steps->release_n++] = expected;
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "lemonsqueezy-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_auth && !steps->deferred_len && !steps->immediate);
    return rc;
}

static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void expect_status_cause(const br_result *result, int status)
{
    char cause[64];
    int n = snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", status);
    CHECK(n > 0 && result->verification_error && !strcmp(result->verification_error, cause));
    CHECK(!strstr(result->verification_error, key) && !strstr(result->verification_error, "read failed"));
}

static void status_read_and_send_policy(const br_detector *d)
{
    char input[1024]; snprintf(input, sizeof(input), "lemonsqueezy %s", key);
    for (int status = 200; status < 300; ++status) {
        const char *read_error = status % 2 ? "read failed" : NULL;
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = status, .body = TEXT("not-json\0\xff"), .read_error = read_error};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, true); CHECK(!out.items[0].verification_error); br_results_clear(&out);
    }
    script empty = {.count = 1}; empty.rows[0] = (row){.key = key, .status = 200, .read_error = ""};
    br_results out = run(d, text(input), &empty); CHECK(out.len == 1);
    finding(&out.items[0], key, true); CHECK(!out.items[0].verification_error); br_results_clear(&out);
    const char *reads[] = {NULL, "read failed", ""};
    for (size_t i = 0; i < 3; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 401, .body = TEXT("\xff"), .read_error = reads[i]};
        out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); CHECK(!out.items[0].verification_error); br_results_clear(&out);
    }
    const int statuses[] = {0, 199, 300, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = statuses[i], .body = TEXT("\xff"), .read_error = "read failed"};
        out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); expect_status_cause(&out.items[0], statuses[i]); br_results_clear(&out);
    }
    script other_ok = {.count = 1}; other_ok.rows[0] = (row){.key = other, .status = 204};
    snprintf(input, sizeof(input), "lemonsqueezy %s", other);
    out = run(d, text(input), &other_ok); CHECK(out.len == 1);
    finding(&out.items[0], other, true); CHECK(!out.items[0].verification_error); br_results_clear(&out);
    snprintf(input, sizeof(input), "lemonsqueezy %s", key);
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", ""};
    for (size_t i = 0; i < 4; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false);
        CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, errors[i]));
        br_results_clear(&out);
    }
    char wrapped[900]; snprintf(wrapped, sizeof(wrapped), "wrapped %s tail", key);
    script redacted = {.count = 1}; redacted.rows[0] = (row){.key = key, .status = 200, .rc = 1, .send_error = wrapped};
    out = run(d, text(input), &redacted); CHECK(out.len == 1);
    finding(&out.items[0], key, false);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "wrapped [REDACTED] tail"));
    CHECK(!strstr(out.items[0].verification_error, key)); br_results_clear(&out);
    script absent = {.count = 1}; absent.rows[0] = (row){.key = key, .status = 200, .rc = 1};
    size_t before = allocation_failures; fail_size = strlen("HTTP transport failed") + 1; fail_after = 1;
    out = run(d, text(input), &absent);
    CHECK(allocation_failures == before + 1 && !fail_after && out.len == 1);
    finding(&out.items[0], key, false); CHECK(!out.items[0].verification_error); br_results_clear(&out);
    char occurrences[4096];
    snprintf(occurrences, sizeof(occurrences), "lemonsqueezy %s\nLEMONSQUEEZY %s\nlemonsqueezy %s", key, other, key);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = key, .status = 401, .read_error = "ignored"};
    steps.rows[1] = (row){.key = other, .status = 204, .read_error = "ignored"};
    steps.rows[2] = (row){.key = key, .status = 500, .rc = 1, .send_error = "later Do"};
    out = run(d, text(occurrences), &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, false); CHECK(!out.items[0].verification_error);
    finding(&out.items[1], other, true); CHECK(!out.items[1].verification_error);
    finding(&out.items[2], key, false);
    CHECK(out.items[2].verification_error && !strcmp(out.items[2].verification_error, "later Do"));
    /* Failed send released immediately, then successful responses last-success-first. */
    CHECK(steps.failed_sends == 1 && steps.release_n == 3);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[1024]; snprintf(input, sizeof(input), "lemonsqueezy %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "out of memory constructing HTTP headers"));
    br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "out of memory constructing HTTP user agent"));
    br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "invalid HTTP user agent"));
    br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "HTTP transport not installed"));
    br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    prior = caller.items[0]; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    caller.items[0].verification_error = prior.verification_error;
    CHECK(d->scan(d, NULL, true, text(input), &caller, &error) == 0 && !error && caller.len == 1);
    test_key_result(&caller.items[0], 17, "caller-owned", "key");
    CHECK(caller.items[0].verification_error == prior.verification_error); br_results_clear(&caller);
}

static br_results caller_owned(void)
{
    br_results out = {0}; br_result caller = {0};
    CHECK(br_finding_key(&caller, 17, "caller-owned", "key") == 0 && br_results_push(&out, &caller) == 0);
    out.items[0].verification_error = strdup("caller-owned"); CHECK(out.items[0].verification_error);
    return out;
}
static void rolled_back(br_results *out, int rc, char *error)
{
    CHECK(rc == -1 && error && out->len == 1);
    test_key_result(&out->items[0], 17, "caller-owned", "key");
    CHECK(out->items[0].verification_error && !strcmp(out->items[0].verification_error, "caller-owned"));
    free(error); br_results_clear(out);
}

static void own_failure_rollback(const br_detector *d)
{
    char input[4096]; snprintf(input, sizeof(input), "lemonsqueezy %s", key);
    const size_t sizes[] = {865, 864};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(input), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(input), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = caller_owned(); error = NULL; size_t before = allocation_failures; arm_auth = true;
    rc = d->scan(d, &ctx, true, text(input), &out, &error);
    CHECK(!arm_auth && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    CHECK(error && strstr(error, "authorization")); rolled_back(&out, rc, error);
    char sample[64]; int n = snprintf(sample, sizeof(sample), "unexpected HTTP response status %d", 500);
    CHECK(n > 0); setter_fail_size = (size_t)n + 1; arm_setter = true;
    script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 500, .read_error = "ignored"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(steps.saw_setter_before_release && !steps.released_before_setter);
    CHECK(!arm_setter && !fail_after && allocation_failures == before + 1);
    CHECK(error && strstr(error, "sanitize")); rolled_back(&out, rc, error);
    setter_fail_size = strlen("setter-fail") + 1; arm_setter = true;
    steps = (script){.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .rc = 1, .send_error = "setter-fail"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(steps.released_before_setter && !steps.saw_setter_before_release);
    CHECK(!arm_setter && !fail_after && allocation_failures == before + 1);
    CHECK(error && strstr(error, "sanitize")); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "lemonsqueezy %s\nlemonsqueezy %s", key, other);
    steps = (script){.count = 2, .retain_fails = true};
    steps.rows[0] = (row){.key = key, .status = 200};
    steps.rows[1] = (row){.key = other, .status = 401};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1);
    CHECK(steps.release_n == 2 && steps.released_keys[0] == other && steps.released_keys[1] == key);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "lemonsqueezy %s", key);
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "lemonsqueezy %s\nlemonsqueezy %s", key, key);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 864, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    CHECK(d->scan(NULL, NULL, false, text(input), &out, NULL) == -1);
    error = NULL; CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    status_read_and_send_policy(d);
    shared_setup_suppressed(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !fail_next_malloc);
    CHECK(!arm_http_headers && !arm_auth && !arm_setter);
    return test_finish("LemonSqueezy");
}
