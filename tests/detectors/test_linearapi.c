/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_linearapi_init(const br_detector **out, char **error);

static char key[49], other[49];
static const char url[] = "https://api.linear.app/graphql";
static const char query[] = "{ \"query\": \"{ viewer { id name } }\" }";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_auth, fail_next_malloc;

static void fill_key(char *out, unsigned salt)
{
    static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    memcpy(out, "lin_api_", 8);
    for (int i = 0; i < 40; ++i) out[8 + i] = alphabet[(i + salt) % 62];
    out[48] = '\0';
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
        if (arm_http_headers) { arm_http_headers = false; fail_size = 3 * sizeof(br_header); fail_after = 1; }
        if (arm_auth) { arm_auth = false; fail_size = 49; fail_after = 1; }
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(key, 1); fill_key(other, 9);
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 48 && strlen(other) == 48 && strcmp(key, other));
    CHECK(!memcmp(key, "lin_api_", 8) && sizeof(query) - 1 == 37);
    CHECK(!strcmp(url, "https://api.linear.app/graphql"));
    CHECK(br_linearapi_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_linearapi_init(&d, &error) == 0 && d && !error);
    CHECK(br_linearapi_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 177 && d->version == 0 && !strcmp(d->name, "LinearAPI"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "LinearAPI is a project management software. LinearAPI keys can be used to access and modify project data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "lin_api_") && strcmp(d->keywords[0], "linearapi"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 177, expected, "key");
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
    char input[256], changed[50];
    extraction_case(d, text(key), key); /* The keyword is inside the token. */
    snprintf(input, sizeof(input), "token=%s", key); extraction_case(d, text(input), key);
    snprintf(input, sizeof(input), "LIN_API_%s", key + 8); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "x%s", key); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "%s!", key); extraction_case(d, text(input), key);
    snprintf(input, sizeof(input), "%s_", key); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "%.47s", key); extraction_case(d, text(input), NULL);
    snprintf(input, sizeof(input), "%sA", key); extraction_case(d, text(input), NULL);
    memcpy(changed, key, 49); changed[20] = '-'; extraction_case(d, text(changed), NULL);
    snprintf(input, sizeof(input), "%s\n%s\n%s", key, other, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, false); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; br_slice body; } row;
typedef struct {
    const char *auth; const char *key;
    const unsigned char *body; size_t body_len;
} held;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix;
    const char *borrowed_auth; const unsigned char *borrowed_body; size_t borrowed_len;
    size_t arm_call, arm_size, arm_after, arm_push; bool poison_body, retain_fails;
    /* Successful Do stays here until scan return, including a ReadAll drop. */
    held deferred[3]; size_t deferred_len; size_t failed_sends;
    bool immediate;
    const char *immediate_auth; const char *immediate_key;
    const unsigned char *immediate_body; size_t immediate_len;
    const char *released_keys[3]; size_t release_n;
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    /* Only earlier failed sends have released. Successful responses stay open. */
    CHECK(at < steps->count && at < 3 && ctx == steps->ctx && http->releases == steps->failed_sends);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 177 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    CHECK(request->body.len == 37 && request->body.data && !memcmp(request->body.data, query, 37));
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(request->headers[1].value && strlen(request->headers[1].value) == 48);
    CHECK(!memcmp(request->headers[1].value, reply->key, 49) && strncmp(request->headers[1].value, "Bearer ", 7));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog linearapi-offline" : "TruffleHog"));
    for (size_t i = 0; i < request->nheaders; ++i) CHECK(strcmp(request->headers[i].name, "Content-Length"));
    for (size_t i = 0; i < steps->deferred_len; ++i) {
        CHECK(steps->deferred[i].auth && steps->deferred[i].auth != request->headers[1].value);
        CHECK(!memcmp(steps->deferred[i].auth, steps->deferred[i].key, 49));
        for (size_t j = 0; j < i; ++j) CHECK(steps->deferred[i].auth != steps->deferred[j].auth);
    }
    steps->borrowed_auth = request->headers[1].value;
    steps->borrowed_body = request->body.data;
    steps->borrowed_len = request->body.len;
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
        steps->immediate_body = steps->borrowed_body; steps->immediate_len = steps->borrowed_len;
        if (failed) ++steps->failed_sends;
        if (retain_this) fail_next_malloc = true;
    } else {
        CHECK(steps->deferred_len < 3);
        steps->deferred[steps->deferred_len++] = (held){
            .auth = steps->borrowed_auth, .key = reply->key,
            .body = steps->borrowed_body, .body_len = steps->borrowed_len,
        };
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    const char *auth = NULL, *expected = NULL;
    const unsigned char *body = NULL; size_t body_len = 0;
    if (steps->immediate) {
        auth = steps->immediate_auth; expected = steps->immediate_key;
        body = steps->immediate_body; body_len = steps->immediate_len;
        steps->immediate = false;
        for (size_t i = 0; i < steps->deferred_len; ++i) {
            CHECK(steps->deferred[i].auth != auth);
            CHECK(!memcmp(steps->deferred[i].auth, steps->deferred[i].key, 49));
        }
    } else {
        CHECK(steps->deferred_len);
        held item = steps->deferred[--steps->deferred_len];
        auth = item.auth; expected = item.key; body = item.body; body_len = item.body_len;
    }
    /* Authorization of the response being released, still the raw key. */
    CHECK(auth && expected && !memcmp(auth, expected, 49) && strncmp(auth, "Bearer ", 7));
    CHECK(body && body_len == 37 && !memcmp(body, query, 37));
    if (steps->release_n < 3) steps->released_keys[steps->release_n++] = expected;
    steps->borrowed_auth = NULL; steps->borrowed_body = NULL;
    /* Native release frees the response body. A late needle search must fail. */
    if (steps->poison_body && response && response->body.data && response->body.len)
        memset((void *)response->body.data, 'X', response->body.len);
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "linearapi-offline" : NULL}; steps->ctx = &ctx;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_auth && !steps->borrowed_body && !steps->deferred_len && !steps->immediate);
    return rc;
}

static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_body_and_send_policy(const br_detector *d)
{
    static const unsigned char nulled[] = {'x', '\0', '"', 'd', 'a', 't', 'a', '"', ':'};
    static const unsigned char needle[] = {'n', 'o', 't', '-', 'j', 's', 'o', 'n', ' ', '"', 'd', 'a', 't', 'a', '"', ':', ' ', '{'};
    char input[160]; snprintf(input, sizeof(input), "%s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = status, .body = {(const unsigned char *)needle, sizeof(needle)}};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, true); br_results_clear(&out);
    }
    const char *misses[] = {"", "data", "\"data\"", "\"Data\":", "{\"viewer\":1}", "prefix \"data\" :"};
    for (size_t i = 0; i < 6; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = 200, .body = text(misses[i])};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); br_results_clear(&out);
    }
    script hidden = {.count = 1};
    hidden.rows[0] = (row){.key = key, .status = 200, .body = {nulled, sizeof(nulled)}};
    br_results out = run(d, text(input), &hidden); CHECK(out.len == 1);
    finding(&out.items[0], key, true); br_results_clear(&out);
    unsigned char mutable[] = {'"', 'd', 'a', 't', 'a', '"', ':'};
    script poisoned = {.count = 1, .poison_body = true};
    poisoned.rows[0] = (row){.key = key, .status = 200, .body = {mutable, sizeof(mutable)}};
    out = run(d, text(input), &poisoned); CHECK(out.len == 1 && mutable[0] == 'X');
    finding(&out.items[0], key, true); br_results_clear(&out);
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = statuses[i], .body = TEXT("\"data\":")};
        out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *reads[] = {"read failed", ""};
    for (size_t i = 0; i < 2; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("\"data\":"), .read_error = reads[i]};
        out = run(d, text(input), &steps); CHECK(out.len == 0); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i], .read_error = "ignored", .body = TEXT("\"data\":")};
        out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); br_results_clear(&out);
    }
    char occurrences[160]; snprintf(occurrences, sizeof(occurrences), "%s\n%s\n%s", key, other, key);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("{\"data\":{}}")};
    steps.rows[1] = (row){.key = other, .status = 200, .read_error = "read failed", .body = TEXT("\"data\":")};
    steps.rows[2] = (row){.key = key, .status = 500, .body = TEXT("\"data\":")};
    out = run(d, text(occurrences), &steps); CHECK(out.len == 2);
    finding(&out.items[0], key, true); finding(&out.items[1], key, false);
    /* ReadAll drop stayed deferred; successes released last-success-first. */
    CHECK(steps.failed_sends == 0 && steps.release_n == 3);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    br_results_clear(&out);
    snprintf(occurrences, sizeof(occurrences), "%s\n%s", key, other);
    script early = {.count = 2};
    early.rows[0] = (row){.key = key, .status = 200, .rc = 1, .send_error = "early Do",
                          .read_error = "must not be read", .body = TEXT("\"data\":")};
    early.rows[1] = (row){.key = other, .status = 200, .body = TEXT("\"data\":")};
    out = run(d, text(occurrences), &early); CHECK(out.len == 2);
    finding(&out.items[0], key, false); finding(&out.items[1], other, true);
    CHECK(early.failed_sends == 1 && early.release_n == 2);
    CHECK(early.released_keys[0] == key && early.released_keys[1] == other);
    br_results_clear(&out);
    script unread = {.count = 1};
    unread.rows[0] = (row){.key = key, .status = 200, .read_error = "", .body = {NULL, 8}};
    out = run(d, text(key), &unread); CHECK(out.len == 0 && unread.failed_sends == 0 && unread.release_n == 1);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, key, 48);
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, key, 48);
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, key, 48); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, key, 48); CHECK(out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    CHECK(d->scan(d, NULL, true, text(key), &caller, &error) == 0 && !error && caller.len == 1);
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
    size_t before = 0;
    const size_t sizes[] = {49, 48};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(key), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(key), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    out = caller_owned(); error = NULL; before = allocation_failures; arm_auth = true;
    rc = d->scan(d, &ctx, true, text(key), &out, &error);
    CHECK(!arm_auth && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    CHECK(error && strstr(error, "authorization")); rolled_back(&out, rc, error);
    script steps = {.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("\"data\":")};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, text(key), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char input[120]; snprintf(input, sizeof(input), "%s\n%s", key, other);
    steps = (script){.count = 2};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("\"data\":")};
    steps.rows[1] = (row){.key = other, .status = 500, .body = {NULL, 4}};
    out = caller_owned(); error = NULL;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(steps.release_n == 2 && steps.released_keys[0] == other && steps.released_keys[1] == key);
    CHECK(error && strstr(error, "body")); rolled_back(&out, rc, error);
    steps = (script){.count = 2, .retain_fails = true};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("\"data\":")};
    steps.rows[1] = (row){.key = other, .status = 204, .body = TEXT("\"data\":")};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1);
    CHECK(steps.release_n == 2 && steps.released_keys[0] == other && steps.released_keys[1] == key);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "%s\n%s", key, key);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 48, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200, .body = TEXT("\"data\":")};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    CHECK(d->scan(NULL, NULL, false, text(key), &out, NULL) == -1);
    error = NULL; CHECK(d->scan(d, NULL, false, (br_slice){NULL, 1}, &out, &error) == -1 && error); free(error);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    status_body_and_send_policy(d);
    shared_setup_suppressed(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !fail_next_malloc);
    CHECK(!arm_http_headers && !arm_auth);
    return test_finish("LinearAPI");
}
