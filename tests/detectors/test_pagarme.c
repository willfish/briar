/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <malloc.h>

int br_pagarme_init(const br_detector **out, char **error);

static char key[39], other[39];
static const char url[] = "https://api.pagar.me/1/balance";
static char expected_body[53];
static size_t fail_size, fail_after, allocation_failures, fail_add_after, fail_push_size;
static bool arm_http_headers, arm_body, fail_next_malloc;

static void fill_key(char *out, unsigned salt)
{
    static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    memcpy(out, "ak_live_", 8);
    for (int i = 0; i < 30; ++i) out[8 + i] = alphabet[(i + salt) % 62];
    out[38] = '\0';
}

static void fill_body(char *out, const char *token)
{
    memcpy(out, "{\"api_key\":\"", 12);
    memcpy(out + 12, token, 38);
    memcpy(out + 50, "\"}", 2);
    out[52] = '\0';
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
        if (arm_body) { arm_body = false; fail_size = 53; fail_after = 1; }
    }
    return rc;
}

static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    fill_key(key, 1); fill_key(other, 5); fill_body(expected_body, key);
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 38 && strlen(other) == 38 && strcmp(key, other));
    CHECK(!memcmp(key, "ak_live_", 8) && strlen(url) == 30 && strlen(expected_body) == 52);
    CHECK(!strcmp(url, "https://api.pagar.me/1/balance"));
    CHECK(br_pagarme_init(NULL, &error) == -1 && error); free(error); error = NULL;
    CHECK(br_pagarme_init(&d, &error) == 0 && d && !error);
    CHECK(br_pagarme_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 985 && d->version == 0 && !strcmp(d->name, "Pagarme"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Pagarme is a payment service provider. Pagarme API keys can be used to access and manage payment transactions and other related services."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ak_live_"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void finding(const br_result *result, const char *expected, bool verified, const char *cause)
{
    test_key_result(result, 985, expected, "key");
    CHECK(result->verified == verified && !result->extra_data && !result->raw_v2.data);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
}

static void extraction_case(const br_detector *d, const char *input, const char *expected)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(out.len == (expected ? 1u : 0u) && !http.calls && !http.releases);
    if (expected) finding(&out.items[0], expected, false, NULL);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[160], changed[39];
    extraction_case(d, key, key); /* Direct regex: the keyword is not required twice. */
    snprintf(input, sizeof(input), "pagarme %s", key); extraction_case(d, input, key);
    snprintf(input, sizeof(input), "ak_live_ %s", key); extraction_case(d, input, key);
    snprintf(input, sizeof(input), "x%s", key); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "%.37s", key); extraction_case(d, input, NULL);
    snprintf(input, sizeof(input), "%sa", key); extraction_case(d, input, NULL);
    memcpy(changed, key, 39); changed[10] = '-';
    extraction_case(d, changed, NULL);
    snprintf(input, sizeof(input), "%s %s", key, key);
    br_results out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 1);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    snprintf(input, sizeof(input), "%s %s %s", key, other, key);
    out = test_scan(d, NULL, false, input, strlen(input)); CHECK(out.len == 2);
    finding(&out.items[0], key, false, NULL); finding(&out.items[1], other, false, NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data);
    br_results_clear(&out);
}

typedef struct { const char *key, *send_error, *read_error; int status, rc; } row;
typedef struct {
    row rows[3]; size_t count; const br_scan_ctx *ctx; bool suffix, setter_fails;
    const unsigned char *borrowed_body; br_results *results; size_t published_before_release;
    size_t arm_call, arm_size, arm_after, arm_push;
    const char *released_keys[3]; size_t release_n; bool saw_body;
} script;

static void body_bytes(const unsigned char *body, size_t len, const char *token)
{
    char want[53]; fill_body(want, token);
    CHECK(body && len == 52 && !memcmp(body, want, 52) && body[52] == '\0');
    CHECK(!memchr(body, '%', 52));
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    CHECK(steps->results && steps->results->len == steps->published_before_release + at);
    row *reply = &steps->rows[at];
    CHECK(request->detector_type == 985 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url));
    body_bytes(request->body.data, request->body.len, reply->key);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, steps->suffix ? "TruffleHog pagarme-offline" : "TruffleHog"));
    steps->borrowed_body = request->body.data; steps->saw_body = true;
    http->response = (br_http_response){.status = reply->status, .body_error = reply->read_error};
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
    if (steps->saw_body) {
        row *reply = &steps->rows[http->releases];
        body_bytes(steps->borrowed_body, 52, reply->key);
        steps->saw_body = false;
        if (steps->release_n < 3) steps->released_keys[steps->release_n++] = reply->key;
    }
    if (steps->results)
        CHECK(steps->results->len == steps->published_before_release + http->releases);
    if (steps->setter_fails) fail_next_malloc = true;
    steps->borrowed_body = NULL;
    test_http_release(user, response);
}

static int invoke(const br_detector *d, const char *input, script *steps, br_results *out, char **error)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = {&http, send_reply, release_reply};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = steps->suffix ? "pagarme-offline" : NULL}; steps->ctx = &ctx;
    steps->results = out; steps->published_before_release = out->len;
    int rc = d->scan(d, &ctx, true, text(input), out, error);
    CHECK(http.calls == steps->count && http.calls == http.releases);
    CHECK(!steps->borrowed_body && !steps->saw_body);
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
    for (int status = 200; status < 300; ++status) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = status, .read_error = status % 2 ? "" : "read failed"};
        br_results out = run(d, key, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, true, NULL); br_results_clear(&out);
    }
    script once = {.count = 1}; once.rows[0] = (row){.key = key, .status = 401, .read_error = "read failed"};
    br_results out = run(d, key, &once); CHECK(out.len == 1);
    finding(&out.items[0], key, false, NULL); br_results_clear(&out);
    const int statuses[] = {0, 199, 300, 403, 429, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(*statuses); ++i) {
        char cause[64];
        int n = snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", statuses[i]);
        CHECK(n > 0 && (size_t)n < sizeof(cause));
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = statuses[i], .read_error = ""};
        out = run(d, key, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false, cause); br_results_clear(&out);
    }
    const char *errors[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", NULL};
    const char *reached[] = {"ordinary Do error", "out of memory constructing HTTP headers", "net/http: nil Context", "", "HTTP transport failed"};
    for (size_t i = 0; i < 5; ++i) {
        script steps = {.count = 1};
        steps.rows[0] = (row){.key = key, .status = 200, .rc = i % 2 ? -1 : 1, .send_error = errors[i], .read_error = "must not be read"};
        out = run(d, key, &steps); CHECK(out.len == 1);
        finding(&out.items[0], key, false, reached[i]); br_results_clear(&out);
    }
    char wrapped[96]; snprintf(wrapped, sizeof(wrapped), "wrapped %s tail", key);
    script redacted = {.count = 1};
    redacted.rows[0] = (row){.key = key, .status = 200, .rc = 1, .send_error = wrapped};
    out = run(d, key, &redacted); CHECK(out.len == 1);
    finding(&out.items[0], key, false, "wrapped [REDACTED] tail");
    CHECK(!strstr(out.items[0].verification_error, key)); br_results_clear(&out);
    char pair[160]; snprintf(pair, sizeof(pair), "%s %s", key, other);
    script steps = {.count = 2, .suffix = true};
    steps.rows[0] = (row){.key = key, .status = 204, .read_error = "read failed"};
    steps.rows[1] = (row){.key = other, .status = 401};
    out = run(d, pair, &steps); CHECK(out.len == 2);
    finding(&out.items[0], key, true, NULL); finding(&out.items[1], other, false, NULL);
    CHECK(steps.release_n == 2 && steps.released_keys[0] == key && steps.released_keys[1] == other);
    br_results_clear(&out);
    snprintf(pair, sizeof(pair), "%s %s %s", key, other, key);
    script dup = {.count = 2};
    dup.rows[0] = (row){.key = key, .status = 200};
    dup.rows[1] = (row){.key = other, .status = 500};
    out = run(d, pair, &dup); CHECK(out.len == 2 && dup.release_n == 2);
    finding(&out.items[0], key, true, NULL);
    finding(&out.items[1], other, false, "unexpected HTTP response status 500");
    br_results_clear(&out);
}

static void shared_setup_suppressed(const br_detector *d)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = allocation_failures; arm_http_headers = true;
    br_results out = test_scan(d, &ctx, true, key, 38);
    CHECK(allocation_failures == before + 1 && !arm_http_headers && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "out of memory constructing HTTP headers"); br_results_clear(&out);
    http = (test_http){0}; before = allocation_failures; fail_size = sizeof("TruffleHog"); fail_after = 1;
    out = test_scan(d, &ctx, true, key, 38);
    CHECK(allocation_failures == before + 1 && !fail_after && !http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "out of memory constructing HTTP user agent"); br_results_clear(&out);
    http = (test_http){0}; ctx.user_agent = "\r";
    out = test_scan(d, &ctx, true, key, 38); CHECK(!http.calls && http.releases == 1 && out.len == 1);
    finding(&out.items[0], key, false, "invalid HTTP user agent"); br_results_clear(&out);
    br_scan_ctx missing = {0}; out = test_scan(d, &missing, true, key, 38); CHECK(out.len == 1);
    finding(&out.items[0], key, false, "HTTP transport not installed"); br_results_clear(&out);
    br_results caller = {0}; br_result prior = {0}; char *error = NULL;
    CHECK(br_finding_key(&prior, 17, "caller-owned", "key") == 0 && br_results_push(&caller, &prior) == 0);
    CHECK(d->scan(d, NULL, true, text(key), &caller, &error) == 0 && !error && caller.len == 2);
    test_key_result(&caller.items[0], 17, "caller-owned", "key");
    finding(&caller.items[1], key, false, "net/http: nil Context"); br_results_clear(&caller);
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
    const size_t sizes[] = {39, 38};
    for (size_t i = 0; i < 2; ++i) {
        br_results out = caller_owned(); char *error = NULL; size_t before = allocation_failures;
        fail_size = sizes[i]; fail_after = 1;
        int rc = d->scan(d, NULL, true, text(key), &out, &error);
        CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    }
    br_results out = caller_owned(); char *error = NULL; fail_add_after = 1;
    int rc = d->scan(d, NULL, true, text(key), &out, &error); CHECK(!fail_add_after); rolled_back(&out, rc, error);
    test_http http = {0};
    out = caller_owned(); error = NULL; size_t before = allocation_failures; arm_body = true;
    rc = d->scan(d, NULL, true, text(key), &out, &error);
    CHECK(!arm_body && !fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    CHECK(error && strstr(error, "body")); rolled_back(&out, rc, error);
    out = caller_owned(); error = NULL; before = allocation_failures; fail_size = 22; fail_after = 1;
    rc = d->scan(d, NULL, true, text(key), &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1 && !http.calls && !http.releases);
    CHECK(error && strstr(error, "sanitize")); rolled_back(&out, rc, error);
    script steps = {.count = 1, .setter_fails = true};
    steps.rows[0] = (row){.key = key, .status = 500, .read_error = "kept"};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, key, &steps, &out, &error);
    CHECK(!fail_next_malloc && allocation_failures == before + 1 && steps.release_n == 1);
    CHECK(error && strstr(error, "sanitize")); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_push = 2 * sizeof(br_result)};
    steps.rows[0] = (row){.key = key, .status = 204};
    out = caller_owned(); out.cap = out.len; error = NULL; before = allocation_failures;
    rc = invoke(d, key, &steps, &out, &error);
    CHECK(!fail_push_size && allocation_failures == before + 1); rolled_back(&out, rc, error);
    char pair[96]; snprintf(pair, sizeof(pair), "%s %s", key, other);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 38, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, pair, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1); rolled_back(&out, rc, error);
    steps = (script){.count = 1, .arm_call = 1, .arm_size = 53, .arm_after = 1};
    steps.rows[0] = (row){.key = key, .status = 200};
    out = caller_owned(); error = NULL; before = allocation_failures;
    rc = invoke(d, pair, &steps, &out, &error);
    CHECK(!fail_after && allocation_failures == before + 1);
    CHECK(error && strstr(error, "body")); rolled_back(&out, rc, error);
    CHECK(d->scan(NULL, NULL, false, text(key), &out, NULL) == -1);
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
    CHECK(!arm_http_headers && !arm_body);
    return test_finish("Pagarme");
}
