/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_linemessaging_init(const br_detector **out, char **error);

static char key171[172], key172[173];
static const char url[] = "https://api.line.me/v2/bot/info";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_auth, fail_next_malloc;

static void fill_key(char *out, size_t len, unsigned salt)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < len; ++i) out[i] = alphabet[(i + salt) % 64];
    out[10] = '+';
    out[len - 2] = '/';
    out[len] = '\0';
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
        if (arm_auth) { arm_auth = false; fail_size = 7 + 171 + 1; fail_after = 1; }
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(key171, 171, 1); fill_key(key172, 172, 3);
    CHECK(BR_ABI_REVISION == 1 && strlen(key171) == 171 && strlen(key172) == 172);
    CHECK(strcmp(key171, key172) && strchr(key171, '+') && strchr(key171, '/'));
    CHECK(!strcmp(url, "https://api.line.me/v2/bot/info") && !strchr(url, ' '));
    CHECK(br_linemessaging_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_linemessaging_init(&d, &error) == 0 && d && !error);
    CHECK(br_linemessaging_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 168 && d->version == 0 && !strcmp(d->name, "LineMessaging"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Line Messaging is a communication app that allows users to send messages, photos, videos, and audio. Line Messaging API keys can be used to access and modify this data and communication."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "line") && strcmp(d->keywords[0], "linemessaging"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 168, expected, "key");
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
    char input[768], short_key[171], long_key[174];
    extraction_case(d, text(key171), NULL);
    extraction_case(d, text(key172), NULL);
    const char *good[] = {"line %s", "LINE='%s'", "Line\n%s", "pipeline %s", "linemessaging %s", "xline: (%s)"};
    for (size_t i = 0; i < 6; ++i) {
        snprintf(input, sizeof(input), good[i], key171); extraction_case(d, text(input), key171);
        snprintf(input, sizeof(input), good[i], key172); extraction_case(d, text(input), key172);
    }
    const char *bad[] = {"notify %s", "message %s", "line%s", "line %.170s"};
    for (size_t i = 0; i < 4; ++i) { snprintf(input, sizeof(input), bad[i], key172); extraction_case(d, text(input), NULL); }
    memset(short_key, 'A', 170); short_key[170] = '\0';
    snprintf(input, sizeof(input), "line %s", short_key); extraction_case(d, text(input), NULL);
    memset(long_key, 'A', 173); long_key[173] = '\0';
    snprintf(input, sizeof(input), "line %s", long_key); extraction_case(d, text(input), NULL);
    memcpy(long_key, key171, 171); long_key[80] = '='; long_key[171] = '\0';
    snprintf(input, sizeof(input), "line %s", long_key); extraction_case(d, text(input), NULL);
    memset(input, ' ', sizeof(input)); memcpy(input, "line", 4); memcpy(input + 44, key171, 171);
    extraction_case(d, (br_slice){(unsigned char *)input, 215}, key171);
    memcpy(input + 45, key171, 171); input[44] = ' ';
    extraction_case(d, (br_slice){(unsigned char *)input, 216}, NULL);
    snprintf(input, sizeof(input), "line %s %s", key171, key172); extraction_case(d, text(input), key171);
    snprintf(input, sizeof(input), "line %s\nLINE %s\nline %s", key171, key172, key171);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key171, false); finding(&out.items[1], key172, false); finding(&out.items[2], key171, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; br_slice body; } row;
typedef struct { const char *auth, *key; } held;
typedef struct {
    row rows[5]; size_t count; const br_scan_ctx *ctx; bool suffix, expect_published, retain_fails;
    const char *borrowed_auth; br_results *results;
    size_t arm_call, arm_size, arm_after, arm_push;
    /* Successful Do stays here until scan return. */
    held deferred[5]; size_t deferred_len; size_t failed_sends;
    bool immediate; const char *immediate_auth, *immediate_key;
    const char *released_keys[5]; size_t release_n;
} script;

static void authorization(const char *value, const char *expected)
{
    size_t n = strlen(expected);
    CHECK((n == 171 || n == 172) && value && strlen(value) == 7 + n);
    CHECK(!memcmp(value, "Bearer ", 7) && !memcmp(value + 7, expected, n + 1));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    /* Only earlier failed sends have released. Successful responses stay open. */
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == steps->failed_sends);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 168 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    authorization(request->headers[0].value, reply->key); steps->borrowed_auth = request->headers[0].value;
    for (size_t i = 0; i < steps->deferred_len; ++i) {
        CHECK(steps->deferred[i].auth && steps->deferred[i].auth != request->headers[0].value);
        authorization(steps->deferred[i].auth, steps->deferred[i].key);
        for (size_t j = 0; j < i; ++j) CHECK(steps->deferred[i].auth != steps->deferred[j].auth);
    }
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog linemessaging-offline" : "TruffleHog"));
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
        steps->immediate = true;
        steps->immediate_auth = steps->borrowed_auth; steps->immediate_key = reply->key;
        if (failed) ++steps->failed_sends;
        if (retain_this) fail_next_malloc = true;
    } else {
        CHECK(steps->deferred_len < 5);
        steps->deferred[steps->deferred_len++] = (held){.auth = steps->borrowed_auth, .key = reply->key};
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    const char *auth = NULL, *expected = NULL; bool deferred = false;
    if (steps->immediate) {
        auth = steps->immediate_auth; expected = steps->immediate_key; steps->immediate = false;
        for (size_t i = 0; i < steps->deferred_len; ++i) {
            CHECK(steps->deferred[i].auth != auth);
            authorization(steps->deferred[i].auth, steps->deferred[i].key);
        }
    } else {
        CHECK(steps->deferred_len);
        held item = steps->deferred[--steps->deferred_len];
        auth = item.auth; expected = item.key; deferred = true;
    }
    authorization(auth, expected);
    if (deferred && steps->expect_published) {
        bool found = false; size_t n = strlen(expected);
        CHECK(steps->results);
        for (size_t i = 0; steps->results && i < steps->results->len; ++i) {
            const br_result *item = &steps->results->items[i];
            if (item->raw.len == n && item->raw.data && !memcmp(item->raw.data, expected, n)) found = true;
        }
        CHECK(found);
    }
    if (steps->release_n < 5) steps->released_keys[steps->release_n++] = expected;
    steps->borrowed_auth = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "linemessaging-offline" : NULL}; steps->ctx = &ctx;
    steps->results = out;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_auth && !steps->deferred_len && !steps->immediate); return rc;
}

static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_read_and_send_policy(const br_detector *d)
{
    char input[256];
    const char *keys[] = {key171, key172};
    for (size_t k = 0; k < 2; ++k) {
        snprintf(input, sizeof(input), "line %s", keys[k]);
        for (int status = 200; status < 300; ++status) {
            const char *read_error = status % 2 ? "read failed" : NULL;
            script steps = {.count = 1};
            steps.rows[0] = (row){.key = keys[k], .status = status, .body = TEXT("not-json\0\xff"), .read_error = read_error};
            br_results out = run(d, text(input), &steps); CHECK(out.len == 1);
            finding(&out.items[0], keys[k], true); br_results_clear(&out);
        }
        script empty = {.count = 1}; empty.rows[0] = (row){.key = keys[k], .status = 200, .read_error = ""};
        br_results out = run(d, text(input), &empty); CHECK(out.len == 1); finding(&out.items[0], keys[k], true); br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "line %s", key171);
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key171, .status = statuses[i], .body = TEXT("\xff"), .read_error = "ignored"};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1); finding(&out.items[0], key171, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key171, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1); finding(&out.items[0], key171, false); br_results_clear(&out);
    }
    char occurrences[768];
    snprintf(occurrences, sizeof(occurrences), "line %s\nLINE %s\nline %s", key171, key172, key171);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = key171, .status = 401, .read_error = "ignored"};
    steps.rows[1] = (row){.key = key172, .status = 204};
    steps.rows[2] = (row){.key = key171, .status = 200, .rc = 1, .send_error = "later Do"};
    steps.expect_published = true;
    br_results out = run(d, text(occurrences), &steps); CHECK(out.len == 3);
    finding(&out.items[0], key171, false); finding(&out.items[1], key172, true); finding(&out.items[2], key171, false);
    /* Failure released immediately; successes released after publication, last first. */
    CHECK(steps.failed_sends == 1 && steps.release_n == 3);
    CHECK(steps.released_keys[0] == key171 && steps.released_keys[1] == key172 && steps.released_keys[2] == key171);
    br_results_clear(&out);
    snprintf(occurrences, sizeof(occurrences), "line %s\nLINE %s", key171, key172);
    script early = {.count = 2, .expect_published = true};
    early.rows[0] = (row){.key = key171, .status = 200, .rc = 1, .send_error = "early Do",
                          .read_error = "must not be read", .body = TEXT("ignored")};
    early.rows[1] = (row){.key = key172, .status = 204, .read_error = ""};
    out = run(d, text(occurrences), &early); CHECK(out.len == 2);
    finding(&out.items[0], key171, false); finding(&out.items[1], key172, true);
    CHECK(early.failed_sends == 1 && early.release_n == 2);
    CHECK(early.released_keys[0] == key171 && early.released_keys[1] == key172);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[256]; snprintf(input, sizeof(input), "line %s", key171);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures;
    arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key171, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, input, strlen(input));
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key171, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key171, false); br_results_clear(&out);
    ctx = (br_scan_ctx){0}; out = test_scan(d, &ctx, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key171, false); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    CHECK(d->scan(d, NULL, true, text(input), &caller, &error) == 0 && !error && caller.len == 1);
    test_key_result(&caller.items[0], 17, "caller-owned", "key"); br_results_clear(&caller);
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
    char input[512]; snprintf(input, sizeof(input), "line %s", key171);
    const size_t sizes[] = {172, 171};
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
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key171, .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "line %s\nline %s", key171, key171);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 171, .arm_after = 1};
    steps.rows[0] = (row){.key = key171, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .retain_fails = true};
    steps.rows[0] = (row){.key = key171, .status = 200, .read_error = "kept"};
    snprintf(input, sizeof(input), "line %s", key171);
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1);
    CHECK(steps.release_n == 1 && steps.released_keys[0] == key171 && !steps.failed_sends);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    char many[1200]; size_t used = 0;
    const char *cycle[] = {key171, key172, key171, key172, key171};
    steps = (script){.count = 5, .retain_fails = true, .expect_published = true};
    for (size_t i = 0; i < 5; ++i) {
        int wrote = snprintf(many + used, sizeof(many) - used, "%sline %s", i ? "\n" : "", cycle[i]);
        CHECK(wrote > 0 && (size_t)wrote < sizeof(many) - used); used += (size_t)wrote;
        steps.rows[i] = (row){.key = cycle[i], .status = 200 + (int)i};
    }
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(many), &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1 && steps.release_n == 5);
    CHECK(steps.released_keys[0] == key171 && steps.released_keys[1] == key172 && steps.released_keys[2] == key171);
    CHECK(steps.released_keys[3] == key172 && steps.released_keys[4] == key171);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
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
    CHECK(!arm_http_headers && !arm_auth);
    return test_finish("LineMessaging");
}
