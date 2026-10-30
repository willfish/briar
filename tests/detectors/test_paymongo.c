/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_paymongo_init(const br_detector **out, char **error);

static char key[33], other[33], underscored[33];
static char key_auth[64], other_auth[64], underscored_auth[64];
static const char url[] = "https://api.paymongo.com/v1/payment_methods";
static const char payload[] = "{\"data\":{\"attributes\":{\"type\":\"paymaya\"}}}";
static const char known_key[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char known_auth[] = "Basic YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE6";
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_auth, fail_next_malloc;

static void fill_key(char *out, unsigned salt)
{
    static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    for (int i = 0; i < 32; ++i) out[i] = alphabet[(i + salt) % 63];
    out[8] = '_';
    out[32] = '\0';
}

static void expect_auth(const char *token, char *out, size_t cap)
{
    char *value = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)token, 32}, (br_slice){0}, &value, &error) == 0);
    CHECK(value && !error && strlen(value) == 50 && !strncmp(value, "Basic ", 6) && strncmp(value, "Basic Basic ", 12));
    CHECK(strlen(value) < cap);
    memcpy(out, value, strlen(value) + 1);
    free(value);
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
        if (arm_auth) { arm_auth = false; fail_size = 51; fail_after = 1; }
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(key, 1); fill_key(other, 9);
    memset(underscored, '_', 32); underscored[32] = '\0';
    expect_auth(key, key_auth, sizeof(key_auth));
    expect_auth(other, other_auth, sizeof(other_auth));
    expect_auth(underscored, underscored_auth, sizeof(underscored_auth));
    expect_auth(known_key, key_auth, sizeof(key_auth)); /* overwrite after the known check */
    CHECK(!strcmp(key_auth, known_auth) && strlen(known_auth) == 50);
    expect_auth(key, key_auth, sizeof(key_auth));
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 32 && strlen(other) == 32 && strcmp(key, other));
    CHECK(strchr(key, '_') && strchr(underscored, '_') == underscored);
    CHECK(strlen(url) == 43 && !strcmp(url, "https://api.paymongo.com/v1/payment_methods"));
    CHECK(strlen(payload) == 42 && !strcmp(payload, "{\"data\":{\"attributes\":{\"type\":\"paymaya\"}}}"));
    CHECK(br_paymongo_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_paymongo_init(&d, &error) == 0 && d && !error);
    CHECK(br_paymongo_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 534 && d->version == 0 && !strcmp(d->name, "Paymongo"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "PayMongo is a payment processing platform in the Philippines. PayMongo API keys can be used to access and manage payment methods, transactions, and other related data."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "paymongo"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 534, expected, "key");
    CHECK(result->raw.len == 32 && result->verified == verified);
    CHECK(!result->verification_error && !result->extra_data && !result->raw_v2.data);
}

static void extraction_case(const br_detector *d, const char *input, size_t len, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[160], changed[33];
    extraction_case(d, key, 32, NULL);
    snprintf(input, sizeof(input), "paymongo %s", key); extraction_case(d, input, strlen(input), key);
    snprintf(input, sizeof(input), "PAYMONGO:%s", underscored); extraction_case(d, input, strlen(input), underscored);
    snprintf(input, sizeof(input), "paymongo%s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "paymongo %.31s", key); extraction_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "paymongo %sa", key); extraction_case(d, input, strlen(input), NULL);
    memcpy(changed, key, 33); changed[4] = '-';
    snprintf(input, sizeof(input), "paymongo %s", changed); extraction_case(d, input, strlen(input), NULL);
    char gap[140];
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "paymongo", 8); memcpy(gap + 48, key, 32);
    extraction_case(d, gap, 80, key);
    memset(gap, ' ', sizeof(gap)); memcpy(gap, "paymongo", 8); memcpy(gap + 49, key, 32);
    extraction_case(d, gap, 81, NULL);
    snprintf(input, sizeof(input), "paymongo %s\nPaymongo %s\npaymongo %s", key, other, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 3);
    finding(&out.items[0], key, false); finding(&out.items[1], other, false); finding(&out.items[2], key, false);
    CHECK(out.items[0].raw.data != out.items[2].raw.data && memchr(out.items[0].raw.data, '_', 32));
    br_results_clear(&out);
    out = test_scan(d, NULL, true, input, strlen(input)); CHECK(out.len == 0); br_results_clear(&out);
}

typedef struct { const char *key, *auth, *send_error, *read_error; int status, rc; } row;
typedef struct { const char *auth, *key; const unsigned char *body; } held;
typedef struct {
    row rows[5]; size_t count; const br_scan_ctx *ctx; bool suffix, expect_published, retain_fails;
    const char *borrowed_auth; const unsigned char *borrowed_body; br_results *results;
    size_t arm_call, arm_size, arm_after, arm_push;
    held deferred[5]; size_t deferred_len; size_t failed_sends;
    bool immediate; const char *immediate_auth, *immediate_key; const unsigned char *immediate_body;
    const char *released_keys[5]; size_t release_n;
} script;

static void authorization(const char *value, const char *expected)
{
    CHECK(value && expected && !strcmp(value, expected));
    CHECK(!strncmp(value, "Basic ", 6) && strncmp(value, "Basic Basic ", 12) && strlen(value) == 50);
}

static void static_body(const unsigned char *body, size_t len)
{
    CHECK(body && len == 42 && !memcmp(body, payload, 42));
}

static const char *auth_for(const char *token)
{
    if (token == key) return key_auth;
    if (token == other) return other_auth;
    if (token == underscored) return underscored_auth;
    if (token == known_key) return known_auth;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == steps->failed_sends);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 534 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, url));
    static_body(request->body.data, request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    authorization(request->headers[1].value, reply->auth);
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, steps->suffix ? "TruffleHog paymongo-offline" : "TruffleHog"));
    steps->borrowed_auth = request->headers[1].value; steps->borrowed_body = request->body.data;
    for (size_t i = 0; i < steps->deferred_len; ++i) {
        CHECK(steps->deferred[i].auth && steps->deferred[i].auth != request->headers[1].value);
        CHECK(steps->deferred[i].body == request->body.data);
        authorization(steps->deferred[i].auth, steps->deferred[i].key ? auth_for(steps->deferred[i].key) : NULL);
        static_body(steps->deferred[i].body, 42);
    }
    http->response = (br_http_response){.status = reply->status, .body_error = reply->read_error};
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
        steps->immediate_body = steps->borrowed_body;
        if (failed) ++steps->failed_sends;
        if (retain_this) fail_next_malloc = true;
    } else {
        CHECK(steps->deferred_len < 5);
        steps->deferred[steps->deferred_len++] = (held){
            .auth = steps->borrowed_auth, .key = reply->key, .body = steps->borrowed_body,
        };
    }
    return rc;
}

static void release_reply(void *user, br_http_response *response)
{
    test_http *http = user; script *steps = http->user;
    const char *auth = NULL, *expected_key = NULL; const unsigned char *body = NULL; bool deferred = false;
    if (steps->immediate) {
        auth = steps->immediate_auth; expected_key = steps->immediate_key; body = steps->immediate_body;
        steps->immediate = false;
        for (size_t i = 0; i < steps->deferred_len; ++i) {
            CHECK(steps->deferred[i].auth != auth && steps->deferred[i].body == body);
            authorization(steps->deferred[i].auth, auth_for(steps->deferred[i].key));
            static_body(steps->deferred[i].body, 42);
        }
    } else {
        CHECK(steps->deferred_len);
        held item = steps->deferred[--steps->deferred_len];
        auth = item.auth; expected_key = item.key; body = item.body; deferred = true;
    }
    authorization(auth, auth_for(expected_key)); static_body(body, 42);
    if (deferred && steps->expect_published) {
        bool found = false; CHECK(steps->results);
        for (size_t i = 0; steps->results && i < steps->results->len; ++i) {
            const br_result *item = &steps->results->items[i];
            if (item->raw.len == 32 && item->raw.data && !memcmp(item->raw.data, expected_key, 32)) found = true;
        }
        CHECK(found);
    }
    if (steps->release_n < 5) steps->released_keys[steps->release_n++] = expected_key;
    steps->borrowed_auth = NULL; steps->borrowed_body = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "paymongo-offline" : NULL}; steps->ctx = &ctx;
    steps->results = out;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_auth && !steps->borrowed_body && !steps->deferred_len && !steps->immediate);
    return rc;
}

static br_results run(const br_detector *d, const char *input, script *steps)
{
    br_results out = {0}; char *error = NULL; int rc = invoke(d, input, steps, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error); return out;
}

static void status_and_send_policy(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "paymongo %s", key);
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .auth = key_auth, .status = status, .read_error = status % 2 ? "" : "read failed"};
        br_results out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, true); br_results_clear(&out);
    }
    snprintf(input, sizeof(input), "paymongo %s", underscored);
    script under = {.count = 1};
    under.rows[0] = (row){.key = underscored, .auth = underscored_auth, .status = 200, .read_error = "read failed"};
    br_results out = run(d, input, &under); CHECK(out.len == 1);
    finding(&out.items[0], underscored, true); br_results_clear(&out);
    snprintf(input, sizeof(input), "paymongo %s", known_key);
    script known = {.count = 1};
    known.rows[0] = (row){.key = known_key, .auth = known_auth, .status = 204};
    out = run(d, input, &known); CHECK(out.len == 1);
    finding(&out.items[0], known_key, true); br_results_clear(&out);
    snprintf(input, sizeof(input), "paymongo %s", key);
    const int statuses[] = {0, 199, 300, 401, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .auth = key_auth, .status = statuses[i], .read_error = "read failed"};
        out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .auth = key_auth, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i], .read_error = "must not be read"};
        out = run(d, input, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false); br_results_clear(&out);
    }
    char occurrences[200];
    snprintf(occurrences, sizeof(occurrences), "paymongo %s\nPAYMONGO %s\npaymongo %s", key, other, key);
    script steps = {.count = 3, .suffix = true, .expect_published = true};
    steps.rows[0] = (row){.key = key, .auth = key_auth, .status = 200, .read_error = "read failed"};
    steps.rows[1] = (row){.key = other, .auth = other_auth, .status = 401};
    steps.rows[2] = (row){.key = key, .auth = key_auth, .status = 204, .read_error = ""};
    out = run(d, occurrences, &steps); CHECK(out.len == 3);
    finding(&out.items[0], key, true); finding(&out.items[1], other, false); finding(&out.items[2], key, true);
    CHECK(!steps.failed_sends && steps.release_n == 3);
    CHECK(steps.released_keys[0] == key && steps.released_keys[1] == other && steps.released_keys[2] == key);
    br_results_clear(&out);
    snprintf(occurrences, sizeof(occurrences), "paymongo %s\nPaymongo %s", key, other);
    script early = {.count = 2, .expect_published = true};
    early.rows[0] = (row){.key = key, .auth = key_auth, .status = 200, .rc = 1, .send_error = "early Do", .read_error = "must not be read"};
    early.rows[1] = (row){.key = other, .auth = other_auth, .status = 204, .read_error = ""};
    out = run(d, occurrences, &early); CHECK(out.len == 2);
    finding(&out.items[0], key, false); finding(&out.items[1], other, true);
    CHECK(early.failed_sends == 1 && early.release_n == 2);
    CHECK(early.released_keys[0] == key && early.released_keys[1] == other);
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    char input[80]; snprintf(input, sizeof(input), "paymongo %s", key);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
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
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    arm_auth = true;
    CHECK(d->scan(d, NULL, true, text(input), &caller, &error) == 0 && !error && caller.len == 1);
    CHECK(!arm_auth && fail_after == 1);
    test_key_result(&caller.items[0], 17, "caller-owned", "key"); fail_after = 0; br_results_clear(&caller);
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
    char input[80]; snprintf(input, sizeof(input), "paymongo %s", key);
    const size_t sizes[] = {33, 32};
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
    steps.rows[0] = (row){.key = key, .auth = key_auth, .status = 204};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char pair[140]; snprintf(pair, sizeof(pair), "paymongo %s\npaymongo %s", key, other);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 32, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .auth = key_auth, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, pair, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .retain_fails = true};
    steps.rows[0] = (row){.key = key, .auth = key_auth, .status = 200, .read_error = "kept"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, input, &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1);
    CHECK(steps.release_n == 1 && steps.released_keys[0] == key && !steps.failed_sends);
    CHECK(error && strstr(error, "retain")); rolled_back(&out, rc, error);
    char many[400]; size_t used = 0;
    const char *cycle[] = {key, other, key, other, key};
    const char *auths[] = {key_auth, other_auth, key_auth, other_auth, key_auth};
    steps = (script){.count = 5, .retain_fails = true, .expect_published = true};
    for (size_t i = 0; i < 5; ++i) {
        int wrote = snprintf(many + used, sizeof(many) - used, "%spaymongo %s", i ? "\n" : "", cycle[i]);
        CHECK(wrote > 0 && (size_t)wrote < sizeof(many) - used); used += (size_t)wrote;
        steps.rows[i] = (row){.key = cycle[i], .auth = auths[i], .status = 200 + (int)i};
    }
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, many, &steps, &out, &error);
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
    status_and_send_policy(d);
    shared_setup_suppressed(d);
    own_failure_rollback(d);
    CHECK(!fail_after && !fail_add_after && !fail_push_size && !fail_next_malloc);
    CHECK(!arm_http_headers && !arm_auth);
    return test_finish("Paymongo");
}
