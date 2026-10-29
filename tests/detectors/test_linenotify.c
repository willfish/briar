/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_linenotify_init(const br_detector **out, char **error);

static const char key[] = "xddIUmDwi9BoOOlSVgXSzwABg5R1icstGke6gp9P85B";
static const char other[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
static const char url[] =
    "https://notify-api.line.me/api/notify?message=Notification Successful";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_auth, fail_next_malloc;

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
        if (arm_auth) { arm_auth = false; fail_size = 51; fail_after = 1; }
    }
    return rc;
}

#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 43 && strlen(other) == 43);
    CHECK(strchr(url, ' ') && !strstr(url, "%20") && strlen(url) == 69);
    CHECK(br_linenotify_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_linenotify_init(&d, &error) == 0 && d && !error);
    CHECK(br_linenotify_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 176 && d->version == 0 && !strcmp(d->name, "LineNotify"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Line Notify is a service provided by LINE Corporation that allows you to send notifications to your LINE app. The API keys can be used to send messages to users or groups."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "linenotify"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 176, expected, "key");
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
    char input[192], changed[44];
    extraction_case(d, text(key), NULL);
    const char *good[] = {"linenotify %s", "LINENOTIFY='%s'", "LineNotify\n%s", "xlinenotify: (%s)", "linenotify\r\n\t%s"};
    for (size_t i = 0; i < 5; ++i) { snprintf(input, sizeof(input), good[i], key); extraction_case(d, text(input), key); }
    snprintf(input, sizeof(input), "linenotify token = '%s'", key); extraction_case(d, text(input), key);
    snprintf(input, sizeof(input), "linenotify -%s", key); extraction_case(d, text(input), key);
    snprintf(input, sizeof(input), "linenotify %s", other); extraction_case(d, text(input), other);
    const char *bad[] = {"linenotif %s", "notify %s", "linenotify _%s", "linenotify x%s", "linenotify %s_", "linenotify %s9", "linenotify %.42s"};
    for (size_t i = 0; i < 7; ++i) { snprintf(input, sizeof(input), bad[i], key); extraction_case(d, text(input), NULL); }
    snprintf(input, sizeof(input), "linenotify = '%s'", "xddIUmDwi9BoOOlSVgXSzwABg5R1icstGke6gp9P85");
    extraction_case(d, text(input), NULL);
    const char invalid[] = "_-+./";
    for (size_t i = 0; i < sizeof(invalid) - 1; ++i) {
        memcpy(changed, key, 43); changed[16] = invalid[i]; changed[43] = '\0';
        snprintf(input, sizeof(input), "linenotify %s", changed); extraction_case(d, text(input), NULL);
    }
    memset(changed, 'A', 43); changed[43] = '\0'; snprintf(input, sizeof(input), "linenotify %s", changed);
    extraction_case(d, text(input), changed);
    memset(input, ' ', sizeof(input)); memcpy(input, "linenotify", 10); memcpy(input + 50, key, 43);
    extraction_case(d, (br_slice){(unsigned char *)input, 93}, key); /* Exactly 40 intervening bytes. */
    memcpy(input + 51, key, 43); input[50] = ' ';
    extraction_case(d, (br_slice){(unsigned char *)input, 94}, NULL);
    memset(input, ' ', sizeof(input)); memcpy(input, "linenotify", 10); input[20] = '\n'; input[30] = '\r';
    memcpy(input + 50, key, 43); extraction_case(d, (br_slice){(unsigned char *)input, 93}, key);
    snprintf(input, sizeof(input), "linenotify %s %s", key, other); extraction_case(d, text(input), key);
    input[0] = '\0'; memcpy(input + 1, "linenotify ", 11); memcpy(input + 12, key, 43); input[55] = (char)0xff;
    extraction_case(d, (br_slice){(unsigned char *)input, 56}, key);
    extraction_case(d, (br_slice){0}, NULL);
    snprintf(input, sizeof(input), "linenotify %s\nLINENOTIFY %s\nlinenotify %s", key, other, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, false); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; br_slice body; } row;
typedef struct { const char *auth, *key, *url; } held;
typedef struct {
    row rows[5]; size_t count; const br_scan_ctx *ctx; bool suffix, expect_published, retain_fails;
    const char *borrowed_auth, *borrowed_url; br_results *results;
    size_t arm_call, arm_size, arm_after, arm_push;
    /* Successful Do stays here until scan return. */
    held deferred[5]; size_t deferred_len; size_t failed_sends;
    bool immediate; const char *immediate_auth, *immediate_key, *immediate_url;
    const char *released_keys[5]; size_t release_n;
} script;

static void literal_query(const char *value)
{
    CHECK(value && !strcmp(value, url) && strchr(value, ' ') && !strstr(value, "%20"));
    CHECK(!strstr(value, "Content-Type") && strlen(value) == 69);
}

static void authorization(const char *value, const char *expected)
{
    CHECK(value && strlen(value) == 50 && !memcmp(value, "Bearer ", 7));
    CHECK(!memcmp(value + 7, expected, 44)); /* Includes the complete final NUL. */
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    /* Only earlier failed sends have released. Successful responses stay open. */
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == steps->failed_sends);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 176 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST"));
    literal_query(request->url);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strcmp(request->headers[0].name, "Content-Type") && strcmp(request->headers[0].name, "Accept"));
    CHECK(strcmp(request->headers[1].name, "Content-Type") && strcmp(request->headers[1].name, "Accept"));
    authorization(request->headers[0].value, reply->key);
    steps->borrowed_auth = request->headers[0].value; steps->borrowed_url = request->url;
    for (size_t i = 0; i < steps->deferred_len; ++i) {
        CHECK(steps->deferred[i].auth && steps->deferred[i].auth != request->headers[0].value);
        authorization(steps->deferred[i].auth, steps->deferred[i].key);
        literal_query(steps->deferred[i].url);
        for (size_t j = 0; j < i; ++j) CHECK(steps->deferred[i].auth != steps->deferred[j].auth);
    }
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog linenotify-offline" : "TruffleHog"));
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
        steps->immediate_url = steps->borrowed_url;
        if (failed) ++steps->failed_sends;
        if (retain_this) fail_next_malloc = true;
    } else {
        CHECK(steps->deferred_len < 5);
        steps->deferred[steps->deferred_len++] = (held){
            .auth = steps->borrowed_auth, .key = reply->key, .url = steps->borrowed_url,
        };
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    const char *auth = NULL, *expected = NULL, *query = NULL; bool deferred = false;
    if (steps->immediate) {
        auth = steps->immediate_auth; expected = steps->immediate_key; query = steps->immediate_url;
        steps->immediate = false;
        for (size_t i = 0; i < steps->deferred_len; ++i) {
            CHECK(steps->deferred[i].auth != auth);
            authorization(steps->deferred[i].auth, steps->deferred[i].key);
            literal_query(steps->deferred[i].url);
        }
    } else {
        CHECK(steps->deferred_len);
        held item = steps->deferred[--steps->deferred_len];
        auth = item.auth; expected = item.key; query = item.url; deferred = true;
    }
    authorization(auth, expected); literal_query(query);
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
    steps->borrowed_auth = NULL; steps->borrowed_url = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, br_slice input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "linenotify-offline" : NULL}; steps->ctx = &ctx;
    steps->results = out;
    int rc = d->scan(d, &ctx, true, input, out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_auth && !steps->borrowed_url && !steps->deferred_len && !steps->immediate); return rc;
}

static br_results run(const br_detector *d, br_slice input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_read_and_send_policy(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "linenotify %s", key);
    for (int status = 200; status < 300; ++status) {
        const char *read_error = status % 2 ? "read failed" : NULL;
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = status, .body = TEXT("not-json\0\xff"), .read_error = read_error};
        br_results out = run(d, text(input), &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, true); br_results_clear(&out);
    }
    script empty = {.count = 1}; empty.rows[0] = (row){.key = key, .status = 200, .read_error = ""};
    br_results out = run(d, text(input), &empty); CHECK(out.len == 1); finding(&out.items[0], key, true); br_results_clear(&out);
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = statuses[i], .body = TEXT("\xff")};
        out = run(d, text(input), &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1}; steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i]};
        out = run(d, text(input), &steps); CHECK(out.len == 1); finding(&out.items[0], key, false); br_results_clear(&out);
    }
    char occurrences[192]; snprintf(occurrences, sizeof(occurrences), "linenotify %s\nLINENOTIFY %s\nlinenotify %s", key, other, key);
    script steps = {.count = 3, .suffix = true};
    steps.rows[0] = (row){.key = key, .status = 401, .read_error = "ignored"};
    steps.rows[1] = (row){.key = other, .status = 204};
    steps.rows[2] = (row){.key = key, .status = 200, .rc = 1, .send_error = "later Do"};
    steps.expect_published = true;
    out = run(d, text(occurrences), &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, true); finding(&out.items[2], key, false);
    /* Failure released immediately; successes released after publication, last first. */
    CHECK(steps.failed_sends == 1 && steps.release_n == 3);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    br_results_clear(&out);
    snprintf(occurrences, sizeof(occurrences), "linenotify %s\nLINENOTIFY %s", key, other);
    script early = {.count = 2, .expect_published = true};
    early.rows[0] = (row){.key = key, .status = 200, .rc = 1, .send_error = "early Do",
                          .read_error = "must not be read", .body = TEXT("ignored")};
    early.rows[1] = (row){.key = other, .status = 204, .read_error = ""};
    out = run(d, text(occurrences), &early); CHECK(out.len == 2);
    finding(&out.items[0], key, false); finding(&out.items[1], other, true);
    CHECK(early.failed_sends == 1 && early.release_n == 2);
    CHECK(early.released_keys[0] == key && early.released_keys[1] == other);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "linenotify %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures;
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
    char input[192]; snprintf(input, sizeof(input), "linenotify %s", key);
    const size_t sizes[] = {44, 43};
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
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    snprintf(input, sizeof(input), "linenotify %s\nlinenotify %s", key, other);
    /* Captures are already owned. Fail the second finding's raw copy before its send. */
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 43, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .retain_fails = true};
    steps.rows[0] = (row){.key = key, .status = 200, .read_error = "kept"};
    snprintf(input, sizeof(input), "linenotify %s", key);
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(input), &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1);
    CHECK(steps.release_n == 1 && steps.released_keys[0] == key && !steps.failed_sends);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    char many[400]; size_t used = 0;
    const char *cycle[] = {key, other, key, other, key};
    steps = (script){.count = 5, .retain_fails = true, .expect_published = true};
    for (size_t i = 0; i < 5; ++i) {
        int wrote = snprintf(many + used, sizeof(many) - used, "%slinenotify %s", i ? "\n" : "", cycle[i]);
        CHECK(wrote > 0 && (size_t)wrote < sizeof(many) - used); used += (size_t)wrote;
        steps.rows[i] = (row){.key = cycle[i], .status = 200 + (int)i};
    }
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, text(many), &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1 && steps.release_n == 5);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    CHECK(steps.released_keys[3] == other && steps.released_keys[4] == key);
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
    return test_finish("LineNotify");
}
